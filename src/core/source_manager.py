from __future__ import annotations
import asyncio
import logging
import os
import time
import inspect
from typing import Dict, List, Any, Optional, Callable, Union, Tuple
from dataclasses import dataclass
from enum import Enum
from contextlib import asynccontextmanager
from datetime import datetime
from collections import deque
from threading import Lock

from .metrics import MetricsCollector, MetricStatus, time_source

logger = logging.getLogger(__name__)

class SourceType(Enum):
    CVE_FEED = "cve_feed"
    SOCIAL_MEDIA = "social_media"
    GOVERNMENT = "government"
    COMMERCIAL = "commercial"
    RESEARCH = "research"
    COMMUNITY = "community"

class ExecutionMode(Enum):
    PARALLEL = "parallel"
    SEQUENTIAL = "sequential"
    HYBRID = "hybrid"

@dataclass
class SourceConfig:
    name: str
    fetch_function: Callable
    source_type: SourceType
    enabled: bool = True
    timeout_seconds: int = 30
    max_alerts: int = 15
    retry_count: int = 2
    retry_delay: float = 1.0
    priority: int = 1               # 1=highest, 5=lowest
    rate_limit_per_hour: Optional[int] = None
    dependencies: List[str] = None
    required_env: List[str] = None  # si falta => disabled

    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
        if self.required_env is None:
            self.required_env = []

class RateLimiter:
    """Rate limiter seguro para uso sync/async."""
    def __init__(self, calls_per_hour: int):
        self.calls_per_hour = max(0, int(calls_per_hour))
        self._times = deque()  # timestamps de las llamadas (segundos epoch)
        self._lock = Lock()

    def _prune(self, now: float):
        one_hour_ago = now - 3600.0
        while self._times and self._times[0] <= one_hour_ago:
            self._times.popleft()

    def _calc_wait(self, now: float) -> float:
        if self.calls_per_hour <= 0:
            return 0.0
        self._prune(now)
        if len(self._times) < self.calls_per_hour:
            return 0.0
        oldest = self._times[0]
        return max(oldest + 3600.0 - now, 0.0)

    def _record(self, now: float):
        self._times.append(now)

    def wait_if_needed(self) -> None:
        """Versión síncrona (no usar en camino async)."""
        if self.calls_per_hour <= 0:
            return
        with self._lock:
            now = time.time()
            wait = self._calc_wait(now)
            if wait > 0:
                logger.info(f"⏰ Rate limit reached, sleeping {wait:.1f}s (sync)")
                time.sleep(wait)
                now = time.time()
            self._record(now)

    async def wait_if_needed_async(self) -> None:
        """Versión asíncrona (no bloquea el event loop)."""
        if self.calls_per_hour <= 0:
            return
        # Lock de hilos + asyncio para consistencia
        while True:
            with self._lock:
                now = time.time()
                wait = self._calc_wait(now)
                if wait <= 0:
                    self._record(now)
                    return
            # dormir fuera del lock
            logger.info(f"⏰ Rate limit reached, sleeping {wait:.1f}s (async)")
            await asyncio.sleep(wait)

class SourceExecutor:
    """Ejecución robusta por fuente con reintentos, timeout y rate-limit."""
    def __init__(self, config: SourceConfig, metrics_collector: Optional[MetricsCollector] = None):
        self.config = config
        self.metrics_collector = metrics_collector
        self.rate_limiter = RateLimiter(config.rate_limit_per_hour) if config.rate_limit_per_hour else None
        self.last_execution_time = 0.0
        self.consecutive_failures = 0
        self._sig = inspect.signature(config.fetch_function)

    async def execute_async(self, since_dt: Optional[datetime] = None) -> List[Dict[str, Any]]:
        if not self.config.enabled:
            logger.debug(f"⏭️ Source {self.config.name} is disabled, skipping")
            return []
        if self.rate_limiter:
            await self.rate_limiter.wait_if_needed_async()

        alerts: List[Dict[str, Any]] = []
        if self.metrics_collector:
            with time_source(self.metrics_collector, self.config.name) as record_metrics:
                try:
                    alerts = await self._execute_with_retries_async(since_dt)
                    record_metrics(len(alerts))
                    self.consecutive_failures = 0
                except Exception as e:
                    logger.error(f"❌ Source {self.config.name} failed: {e}")
                    self.consecutive_failures += 1
                    raise
        else:
            try:
                alerts = await self._execute_with_retries_async(since_dt)
                self.consecutive_failures = 0
            except Exception as e:
                logger.error(f"❌ Source {self.config.name} failed: {e}")
                self.consecutive_failures += 1
                raise
        self.last_execution_time = time.time()
        return alerts

    def execute_sync(self, since_dt: Optional[datetime] = None) -> List[Dict[str, Any]]:
        if not self.config.enabled:
            logger.debug(f"⏭️ Source {self.config.name} is disabled, skipping")
            return []
        if self.rate_limiter:
            self.rate_limiter.wait_if_needed()

        start = time.time()
        try:
            if self.metrics_collector:
                self.metrics_collector.start_source(self.config.name)
            alerts = self._execute_with_retries_sync(since_dt)
            if self.metrics_collector:
                self.metrics_collector.complete_source(self.config.name, len(alerts), MetricStatus.SUCCESS)
            self.consecutive_failures = 0
            logger.info(f"✅ {self.config.name}: {len(alerts)} alerts in {time.time()-start:.2f}s")
            self.last_execution_time = time.time()
            return alerts
        except Exception as e:
            if self.metrics_collector:
                self.metrics_collector.complete_source(self.config.name, 0, MetricStatus.ERROR, str(e))
            self.consecutive_failures += 1
            logger.error(f"❌ Source {self.config.name} failed: {e}")
            self.last_execution_time = time.time()
            return []  # en sync devolvemos vacío

    # ----- core retries -----
    async def _execute_with_retries_async(self, since_dt: Optional[datetime]) -> List[Dict[str, Any]]:
        last_exc = None
        for attempt in range(self.config.retry_count + 1):
            try:
                alerts = await asyncio.wait_for(
                    self._call_source_async(since_dt),
                    timeout=self.config.timeout_seconds
                )
                if not isinstance(alerts, list):
                    raise ValueError(f"Source returned {type(alerts)}, expected list")
                return alerts[: self.config.max_alerts]
            except asyncio.TimeoutError:
                last_exc = TimeoutError(f"Source timed out after {self.config.timeout_seconds}s")
                logger.warning(f"⏰ {self.config.name} timeout (attempt {attempt+1})")
            except Exception as e:
                last_exc = e
                logger.warning(f"⚠️ {self.config.name} error (attempt {attempt+1}): {e}")
            if attempt < self.config.retry_count:
                delay = self.config.retry_delay * (2 ** attempt)
                await asyncio.sleep(delay)
        raise last_exc or Exception("Unknown error during source execution")

    def _execute_with_retries_sync(self, since_dt: Optional[datetime]) -> List[Dict[str, Any]]:
        last_exc = None
        for attempt in range(self.config.retry_count + 1):
            try:
                alerts = self._call_source_sync(since_dt)
                if not isinstance(alerts, list):
                    raise ValueError(f"Source returned {type(alerts)}, expected list")
                return alerts[: self.config.max_alerts]
            except Exception as e:
                last_exc = e
                logger.warning(f"⚠️ {self.config.name} error (attempt {attempt+1}): {e}")
            if attempt < self.config.retry_count:
                time.sleep(self.config.retry_delay * (2 ** attempt))
        raise last_exc or Exception("Unknown error during source execution")

    # ----- flexible call helpers -----
    def _build_kwargs(self, since_dt: Optional[datetime]) -> Dict[str, Any]:
        params = self._sig.parameters
        kwargs: Dict[str, Any] = {}
        if "limit" in params:
            kwargs["limit"] = self.config.max_alerts
        if "since_dt" in params and since_dt is not None:
            kwargs["since_dt"] = since_dt
        return kwargs

    async def _call_source_async(self, since_dt: Optional[datetime]) -> List[Dict[str, Any]]:
        fn = self.config.fetch_function
        kwargs = self._build_kwargs(since_dt)
        if inspect.iscoroutinefunction(fn):
            return await fn(**kwargs)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: fn(**kwargs))

    def _call_source_sync(self, since_dt: Optional[datetime]) -> List[Dict[str, Any]]:
        fn = self.config.fetch_function
        kwargs = self._build_kwargs(since_dt)
        return fn(**kwargs)

    @property
    def is_healthy(self) -> bool:
        return self.consecutive_failures < 3

    @property
    def should_execute(self) -> bool:
        return self.config.enabled and self.is_healthy

class SourceManager:
    def __init__(self,
                 execution_mode: ExecutionMode = ExecutionMode.PARALLEL,
                 max_parallel_sources: int = 5,
                 metrics_collector: Optional[MetricsCollector] = None):
        self.execution_mode = execution_mode
        self.max_parallel_sources = max_parallel_sources
        self.metrics_collector = metrics_collector
        self.sources: Dict[str, SourceExecutor] = {}
        self.source_configs: Dict[str, SourceConfig] = {}

    def register_source(self, config: SourceConfig) -> None:
        # auto-disable si faltan envs
        missing = [e for e in (config.required_env or []) if not os.getenv(e)]
        if missing:
            config.enabled = False
            logger.warning(f"⛔ {config.name} disabled (missing env): {', '.join(missing)}")
        executor = SourceExecutor(config, self.metrics_collector)
        self.sources[config.name] = executor
        self.source_configs[config.name] = config
        logger.debug(f"📡 Registered source: {config.name} ({config.source_type.value})")

    def register_sources(self, configs: List[SourceConfig]) -> None:
        for cfg in configs:
            self.register_source(cfg)

    def get_source_status(self) -> Dict[str, Dict[str, Any]]:
        status: Dict[str, Dict[str, Any]] = {}
        for name, executor in self.sources.items():
            cfg = self.source_configs[name]
            status[name] = {
                "enabled": cfg.enabled,
                "healthy": executor.is_healthy,
                "consecutive_failures": executor.consecutive_failures,
                "last_execution": executor.last_execution_time,
                "type": cfg.source_type.value,
                "priority": cfg.priority
            }
        return status

    async def execute_all_async(self, since_dt: Optional[datetime] = None) -> Dict[str, List[Dict[str, Any]]]:
        logger.info(f"🚀 Starting async execution of {len(self.sources)} sources")
        if self.execution_mode == ExecutionMode.SEQUENTIAL:
            return await self._execute_sequential_async(since_dt)
        if self.execution_mode == ExecutionMode.HYBRID:
            return await self._execute_hybrid_async(since_dt)
        return await self._execute_parallel_async(since_dt)

    def execute_all_sync(self, since_dt: Optional[datetime] = None) -> Dict[str, List[Dict[str, Any]]]:
        logger.info(f"🚀 Starting sync execution of {len(self.sources)} sources")
        results: Dict[str, List[Dict[str, Any]]] = {}
        sorted_sources = sorted(self.sources.items(), key=lambda x: self.source_configs[x[0]].priority)
        for name, executor in sorted_sources:
            if executor.should_execute:
                try:
                    alerts = executor.execute_sync(since_dt)
                    results[name] = alerts
                    logger.info(f"✅ {name}: {len(alerts)} alerts collected")
                except Exception as e:
                    logger.error(f"❌ {name} failed: {e}")
                    results[name] = []
            else:
                logger.debug(f"⏭️ Skipping {name} (disabled or unhealthy)")
                results[name] = []
        total_alerts = sum(len(v) for v in results.values())
        logger.info(f"🎯 Sync execution completed: {total_alerts} total alerts from {len(results)} sources")
        return results

    async def _execute_sequential_async(self, since_dt: Optional[datetime]) -> Dict[str, List[Dict[str, Any]]]:
        results: Dict[str, List[Dict[str, Any]]] = {}
        sorted_sources = sorted(self.sources.items(), key=lambda x: self.source_configs[x[0]].priority)
        for name, executor in sorted_sources:
            if executor.should_execute:
                try:
                    alerts = await executor.execute_async(since_dt)
                    results[name] = alerts
                    logger.info(f"✅ {name}: {len(alerts)} alerts collected")
                except Exception as e:
                    logger.error(f"❌ {name} failed: {e}")
                    results[name] = []
            else:
                logger.debug(f"⏭️ Skipping {name} (disabled/unhealthy)")
                results[name] = []
        return results

    async def _execute_parallel_async(self, since_dt: Optional[datetime]) -> Dict[str, List[Dict[str, Any]]]:
        results: Dict[str, List[Dict[str, Any]]] = {}
        active = [(n, ex) for n, ex in self.sources.items() if ex.should_execute]
        sem = asyncio.Semaphore(self.max_parallel_sources)

        async def run_one(name: str, executor: SourceExecutor):
            async with sem:
                try:
                    alerts = await executor.execute_async(since_dt)
                    return name, alerts
                except Exception as e:
                    logger.error(f"❌ {name} failed: {e}")
                    return name, []

        tasks = [run_one(n, ex) for n, ex in active]
        if tasks:
            for coro in asyncio.as_completed(tasks):
                name, alerts = await coro
                results[name] = alerts
                logger.info(f"✅ {name}: {len(alerts)} alerts collected")
        for name in self.sources:
            results.setdefault(name, [])
        total = sum(len(v) for v in results.values())
        logger.info(f"🎯 Parallel execution completed: {total} total alerts from {len(results)} sources")
        return results

    async def _execute_hybrid_async(self, since_dt: Optional[datetime]) -> Dict[str, List[Dict[str, Any]]]:
        results: Dict[str, List[Dict[str, Any]]] = {}
        high, normal = [], []
        for name, ex in self.sources.items():
            if not ex.should_execute:
                results[name] = []; continue
            cfg = self.source_configs[name]
            (high if cfg.priority <= 2 else normal).append((name, ex))

        logger.info(f"🎯 Executing {len(high)} high-priority sequentially")
        for name, ex in sorted(high, key=lambda x: self.source_configs[x[0]].priority):
            try:
                alerts = await ex.execute_async(since_dt)
                results[name] = alerts
                logger.info(f"✅ [HIGH] {name}: {len(alerts)} alerts")
            except Exception as e:
                logger.error(f"❌ [HIGH] {name} failed: {e}")
                results[name] = []

        if normal:
            logger.info(f"⚡ Executing {len(normal)} normal-priority in parallel")
            sem = asyncio.Semaphore(self.max_parallel_sources)
            async def run_norm(n, ex):
                async with sem:
                    try:
                        return n, await ex.execute_async(since_dt)
                    except Exception as e:
                        logger.error(f"❌ [NORMAL] {n} failed: {e}")
                        return n, []
            tasks = [run_norm(n, ex) for n, ex in normal]
            for coro in asyncio.as_completed(tasks):
                n, alerts = await coro
                results[n] = alerts
                logger.info(f"✅ [NORMAL] {n}: {len(alerts)} alerts")
        total = sum(len(v) for v in results.values())
        logger.info(f"🎯 Hybrid execution completed: {total} total alerts from {len(results)} sources")
        return results

    # ---------- helpers / admin ----------
    def enable_source(self, source_name: str) -> bool:
        if source_name in self.source_configs:
            self.source_configs[source_name].enabled = True
            logger.info(f"✅ Enabled source: {source_name}")
            return True
        return False

    def disable_source(self, source_name: str) -> bool:
        if source_name in self.source_configs:
            self.source_configs[source_name].enabled = False
            logger.info(f"⏸️ Disabled source: {source_name}")
            return True
        return False

    def get_healthy_sources(self) -> List[str]:
        return [n for n, ex in self.sources.items() if ex.is_healthy and self.source_configs[n].enabled]

    def get_failed_sources(self) -> List[str]:
        return [n for n, ex in self.sources.items() if not ex.is_healthy]

    def reset_source_failures(self, source_name: str) -> bool:
        ex = self.sources.get(source_name)
        if ex:
            ex.consecutive_failures = 0
            logger.info(f"🔄 Reset failures for source: {source_name}")
            return True
        return False

    def get_execution_summary(self, results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        total_alerts = sum(len(v) for v in results.values())
        successful_sources = sum(1 for v in results.values() if len(v) > 0)
        failed_sources = len(results) - successful_sources
        details = {}
        for name, alerts in results.items():
            ex = self.sources.get(name)
            details[name] = {
                "alerts_count": len(alerts),
                "status": "success" if (alerts or not ex) else "failed",
                "is_healthy": ex.is_healthy if ex else False,
                "consecutive_failures": ex.consecutive_failures if ex else 0
            }
        return {
            "total_alerts": total_alerts,
            "total_sources": len(results),
            "successful_sources": successful_sources,
            "failed_sources": failed_sources,
            "success_rate": (successful_sources / len(results) * 100) if results else 0,
            "execution_mode": self.execution_mode.value,
            "source_details": details
        }

# Factories
def create_source_config(name: str, fetch_function: Callable, source_type: SourceType, **kwargs) -> SourceConfig:
    return SourceConfig(name=name, fetch_function=fetch_function, source_type=source_type, **kwargs)

def create_cve_source_config(name: str, fetch_function: Callable, **kwargs) -> SourceConfig:
    defaults = {"source_type": SourceType.CVE_FEED, "timeout_seconds": 45, "max_alerts": 20, "priority": 1, "rate_limit_per_hour": 100}
    defaults.update(kwargs); return create_source_config(name, fetch_function, **defaults)

def create_social_source_config(name: str, fetch_function: Callable, **kwargs) -> SourceConfig:
    defaults = {"source_type": SourceType.SOCIAL_MEDIA, "timeout_seconds": 30, "max_alerts": 10, "priority": 3, "rate_limit_per_hour": 1000, "retry_count": 1}
    defaults.update(kwargs); return create_source_config(name, fetch_function, **defaults)

def create_government_source_config(name: str, fetch_function: Callable, **kwargs) -> SourceConfig:
    defaults = {"source_type": SourceType.GOVERNMENT, "timeout_seconds": 60, "max_alerts": 25, "priority": 1, "rate_limit_per_hour": 50}
    defaults.update(kwargs); return create_source_config(name, fetch_function, **defaults)

@asynccontextmanager
async def managed_sources(configs: List[SourceConfig],
                         execution_mode: ExecutionMode = ExecutionMode.PARALLEL,
                         metrics_collector: Optional[MetricsCollector] = None):
    manager = SourceManager(execution_mode=execution_mode, metrics_collector=metrics_collector)
    try:
        manager.register_sources(configs)
        yield manager
    finally:
        logger.debug("🧹 Cleaning up source manager")
