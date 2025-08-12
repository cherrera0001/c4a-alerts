"""
Source Management module for C4A Alerts.

Handles parallel execution of multiple threat intelligence sources with
resilience, rate limiting, and comprehensive error handling.
"""

import asyncio
import logging
import time
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import asynccontextmanager

from .metrics import MetricsCollector, MetricStatus, time_source

logger = logging.getLogger(__name__)


class SourceType(Enum):
    """Types of threat intelligence sources."""
    CVE_FEED = "cve_feed"
    SOCIAL_MEDIA = "social_media"
    GOVERNMENT = "government"
    COMMERCIAL = "commercial"
    RESEARCH = "research"
    COMMUNITY = "community"


class ExecutionMode(Enum):
    """Source execution modes."""
    PARALLEL = "parallel"
    SEQUENTIAL = "sequential"
    HYBRID = "hybrid"


@dataclass
class SourceConfig:
    """Configuration for individual threat intelligence sources."""
    name: str
    fetch_function: Callable
    source_type: SourceType
    enabled: bool = True
    timeout_seconds: int = 30
    max_alerts: int = 15
    retry_count: int = 2
    retry_delay: float = 1.0
    priority: int = 1  # 1=highest, 5=lowest
    rate_limit_per_hour: Optional[int] = None
    dependencies: List[str] = None  # Other sources this depends on
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []


class RateLimiter:
    """Simple rate limiter for API calls."""
    
    def __init__(self, calls_per_hour: int):
        self.calls_per_hour = calls_per_hour
        self.calls_per_second = calls_per_hour / 3600
        self.last_call_time = 0.0
        self.call_times = []
    
    def wait_if_needed(self) -> None:
        """Wait if rate limit would be exceeded."""
        if self.calls_per_hour <= 0:
            return
        
        now = time.time()
        
        # Clean old call times (older than 1 hour)
        hour_ago = now - 3600
        self.call_times = [t for t in self.call_times if t > hour_ago]
        
        # Check if we need to wait
        if len(self.call_times) >= self.calls_per_hour:
            oldest_call = min(self.call_times)
            wait_time = oldest_call + 3600 - now
            if wait_time > 0:
                logger.info(f"⏰ Rate limit reached, waiting {wait_time:.1f}s")
                time.sleep(wait_time)
        
        self.call_times.append(now)


class SourceExecutor:
    """Handles execution of individual sources with error handling and retries."""
    
    def __init__(self, config: SourceConfig, metrics_collector: Optional[MetricsCollector] = None):
        self.config = config
        self.metrics_collector = metrics_collector
        self.rate_limiter = RateLimiter(config.rate_limit_per_hour) if config.rate_limit_per_hour else None
        self.last_execution_time = 0.0
        self.consecutive_failures = 0
    
    async def execute_async(self) -> List[Dict[str, Any]]:
        """Execute source asynchronously."""
        if not self.config.enabled:
            logger.debug(f"⏭️ Source {self.config.name} is disabled, skipping")
            return []
        
        # Rate limiting
        if self.rate_limiter:
            self.rate_limiter.wait_if_needed()
        
        alerts = []
        error = None
        
        if self.metrics_collector:
            with time_source(self.metrics_collector, self.config.name) as record_metrics:
                try:
                    alerts = await self._execute_with_retries()
                    record_metrics(len(alerts))
                    self.consecutive_failures = 0
                except Exception as e:
                    error = str(e)
                    logger.error(f"❌ Source {self.config.name} failed: {e}")
                    self.consecutive_failures += 1
                    raise
        else:
            try:
                alerts = await self._execute_with_retries()
                self.consecutive_failures = 0
            except Exception as e:
                error = str(e)
                logger.error(f"❌ Source {self.config.name} failed: {e}")
                self.consecutive_failures += 1
                raise
        
        self.last_execution_time = time.time()
        return alerts
    
    def execute_sync(self) -> List[Dict[str, Any]]:
        """Execute source synchronously."""
        if not self.config.enabled:
            logger.debug(f"⏭️ Source {self.config.name} is disabled, skipping")
            return []
        
        # Rate limiting
        if self.rate_limiter:
            self.rate_limiter.wait_if_needed()
        
        alerts = []
        start_time = time.time()
        
        try:
            if self.metrics_collector:
                self.metrics_collector.start_source(self.config.name)
            
            alerts = self._execute_with_retries_sync()
            
            if self.metrics_collector:
                self.metrics_collector.complete_source(
                    self.config.name, 
                    len(alerts), 
                    MetricStatus.SUCCESS
                )
            
            self.consecutive_failures = 0
            logger.info(f"✅ {self.config.name}: {len(alerts)} alerts in {time.time() - start_time:.2f}s")
            
        except Exception as e:
            if self.metrics_collector:
                self.metrics_collector.complete_source(
                    self.config.name, 
                    0, 
                    MetricStatus.ERROR, 
                    str(e)
                )
            
            self.consecutive_failures += 1
            logger.error(f"❌ Source {self.config.name} failed: {e}")
            # Don't re-raise in sync mode, return empty list instead
            alerts = []
        
        self.last_execution_time = time.time()
        return alerts
    
    async def _execute_with_retries(self) -> List[Dict[str, Any]]:
        """Execute with async retries."""
        last_exception = None
        
        for attempt in range(self.config.retry_count + 1):
            try:
                # Execute with timeout
                alerts = await asyncio.wait_for(
                    self._call_source_function_async(),
                    timeout=self.config.timeout_seconds
                )
                
                if not isinstance(alerts, list):
                    raise ValueError(f"Source returned {type(alerts)}, expected list")
                
                return alerts[:self.config.max_alerts]  # Limit alerts
                
            except asyncio.TimeoutError:
                last_exception = TimeoutError(f"Source timed out after {self.config.timeout_seconds}s")
                logger.warning(f"⏰ {self.config.name} timeout (attempt {attempt + 1})")
            except Exception as e:
                last_exception = e
                logger.warning(f"⚠️ {self.config.name} error (attempt {attempt + 1}): {e}")
            
            # Wait before retry (except on last attempt)
            if attempt < self.config.retry_count:
                delay = self.config.retry_delay * (2 ** attempt)  # Exponential backoff
                await asyncio.sleep(delay)
        
        # All retries failed
        raise last_exception or Exception("Unknown error during source execution")
    
    def _execute_with_retries_sync(self) -> List[Dict[str, Any]]:
        """Execute with synchronous retries."""
        last_exception = None
        
        for attempt in range(self.config.retry_count + 1):
            try:
                alerts = self.config.fetch_function(limit=self.config.max_alerts)
                
                if not isinstance(alerts, list):
                    raise ValueError(f"Source returned {type(alerts)}, expected list")
                
                return alerts
                
            except Exception as e:
                last_exception = e
                logger.warning(f"⚠️ {self.config.name} error (attempt {attempt + 1}): {e}")
            
            # Wait before retry (except on last attempt)
            if attempt < self.config.retry_count:
                delay = self.config.retry_delay * (2 ** attempt)
                time.sleep(delay)
        
        # All retries failed
        raise last_exception or Exception("Unknown error during source execution")
    
    async def _call_source_function_async(self) -> List[Dict[str, Any]]:
        """Call source function, handling both sync and async functions."""
        if asyncio.iscoroutinefunction(self.config.fetch_function):
            return await self.config.fetch_function(limit=self.config.max_alerts)
        else:
            # Run sync function in thread pool
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, 
                lambda: self.config.fetch_function(limit=self.config.max_alerts)
            )
    
    @property
    def is_healthy(self) -> bool:
        """Check if source is considered healthy (not too many failures)."""
        return self.consecutive_failures < 3
    
    @property
    def should_execute(self) -> bool:
        """Check if source should be executed (enabled and healthy)."""
        return self.config.enabled and self.is_healthy


class SourceManager:
    """Manages execution of multiple threat intelligence sources."""
    
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
        """Register a new threat intelligence source."""
        executor = SourceExecutor(config, self.metrics_collector)
        self.sources[config.name] = executor
        self.source_configs[config.name] = config
        logger.debug(f"📡 Registered source: {config.name} ({config.source_type.value})")
    
    def register_sources(self, configs: List[SourceConfig]) -> None:
        """Register multiple sources at once."""
        for config in configs:
            self.register_source(config)
    
    def get_source_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all registered sources."""
        status = {}
        for name, executor in self.sources.items():
            config = self.source_configs[name]
            status[name] = {
                "enabled": config.enabled,
                "healthy": executor.is_healthy,
                "consecutive_failures": executor.consecutive_failures,
                "last_execution": executor.last_execution_time,
                "type": config.source_type.value,
                "priority": config.priority
            }
        return status
    
    async def execute_all_async(self) -> Dict[str, List[Dict[str, Any]]]:
        """Execute all sources asynchronously."""
        logger.info(f"🚀 Starting async execution of {len(self.sources)} sources")
        
        if self.execution_mode == ExecutionMode.SEQUENTIAL:
            return await self._execute_sequential_async()
        elif self.execution_mode == ExecutionMode.PARALLEL:
            return await self._execute_parallel_async()
        else:  # HYBRID
            return await self._execute_hybrid_async()
    
    def execute_all_sync(self) -> Dict[str, List[Dict[str, Any]]]:
        """Execute all sources synchronously."""
        logger.info(f"🚀 Starting sync execution of {len(self.sources)} sources")
        
        results = {}
        
        # Sort sources by priority (1=highest)
        sorted_sources = sorted(
            self.sources.items(),
            key=lambda x: self.source_configs[x[0]].priority
        )
        
        for name, executor in sorted_sources:
            if executor.should_execute:
                try:
                    alerts = executor.execute_sync()
                    results[name] = alerts
                    logger.info(f"✅ {name}: {len(alerts)} alerts collected")
                except Exception as e:
                    logger.error(f"❌ {name} failed: {e}")
                    results[name] = []
            else:
                logger.debug(f"⏭️ Skipping {name} (disabled or unhealthy)")
                results[name] = []
        
        total_alerts = sum(len(alerts) for alerts in results.values())
        logger.info(f"🎯 Sync execution completed: {total_alerts} total alerts from {len(results)} sources")
        
        return results
    
    async def _execute_sequential_async(self) -> Dict[str, List[Dict[str, Any]]]:
        """Execute sources sequentially (one after another)."""
        results = {}
        
        # Sort sources by priority
        sorted_sources = sorted(
            self.sources.items(),
            key=lambda x: self.source_configs[x[0]].priority
        )
        
        for name, executor in sorted_sources:
            if executor.should_execute:
                try:
                    alerts = await executor.execute_async()
                    results[name] = alerts
                    logger.info(f"✅ {name}: {len(alerts)} alerts collected")
                except Exception as e:
                    logger.error(f"❌ {name} failed: {e}")
                    results[name] = []
            else:
                logger.debug(f"⏭️ Skipping {name} (disabled or unhealthy)")
                results[name] = []
        
        return results
    
    async def _execute_parallel_async(self) -> Dict[str, List[Dict[str, Any]]]:
        """Execute sources in parallel with concurrency limit."""
        results = {}
        
        # Filter enabled and healthy sources
        active_sources = [
            (name, executor) for name, executor in self.sources.items()
            if executor.should_execute
        ]
        
        # Create semaphore to limit concurrent executions
        semaphore = asyncio.Semaphore(self.max_parallel_sources)
        
        async def execute_with_semaphore(name: str, executor: SourceExecutor):
            async with semaphore:
                try:
                    alerts = await executor.execute_async()
                    return name, alerts
                except Exception as e:
                    logger.error(f"❌ {name} failed: {e}")
                    return name, []
        
        # Execute all sources concurrently
        tasks = [
            execute_with_semaphore(name, executor)
            for name, executor in active_sources
        ]
        
        if tasks:
            completed_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in completed_results:
                if isinstance(result, Exception):
                    logger.error(f"❌ Task failed with exception: {result}")
                    continue
                
                name, alerts = result
                results[name] = alerts
                logger.info(f"✅ {name}: {len(alerts)} alerts collected")
        
        # Add empty results for skipped sources
        for name in self.sources:
            if name not in results:
                results[name] = []
        
        total_alerts = sum(len(alerts) for alerts in results.values())
        logger.info(f"🎯 Parallel execution completed: {total_alerts} total alerts from {len(results)} sources")
        
        return results
    
    async def _execute_hybrid_async(self) -> Dict[str, List[Dict[str, Any]]]:
        """Execute sources in hybrid mode (high priority sequential, others parallel)."""
        results = {}
        
        # Separate sources by priority
        high_priority = []  # Priority 1-2
        normal_priority = []  # Priority 3+
        
        for name, executor in self.sources.items():
            if not executor.should_execute:
                results[name] = []
                continue
                
            config = self.source_configs[name]
            if config.priority <= 2:
                high_priority.append((name, executor))
            else:
                normal_priority.append((name, executor))
        
        # Execute high priority sources sequentially first
        logger.info(f"🎯 Executing {len(high_priority)} high-priority sources sequentially")
        for name, executor in sorted(high_priority, key=lambda x: self.source_configs[x[0]].priority):
            try:
                alerts = await executor.execute_async()
                results[name] = alerts
                logger.info(f"✅ [HIGH] {name}: {len(alerts)} alerts collected")
            except Exception as e:
                logger.error(f"❌ [HIGH] {name} failed: {e}")
                results[name] = []
        
        # Execute normal priority sources in parallel
        if normal_priority:
            logger.info(f"⚡ Executing {len(normal_priority)} normal-priority sources in parallel")
            
            semaphore = asyncio.Semaphore(self.max_parallel_sources)
            
            async def execute_normal(name: str, executor: SourceExecutor):
                async with semaphore:
                    try:
                        alerts = await executor.execute_async()
                        return name, alerts
                    except Exception as e:
                        logger.error(f"❌ [NORMAL] {name} failed: {e}")
                        return name, []
            
            tasks = [execute_normal(name, executor) for name, executor in normal_priority]
            parallel_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in parallel_results:
                if isinstance(result, Exception):
                    logger.error(f"❌ Parallel task failed: {result}")
                    continue
                
                name, alerts = result
                results[name] = alerts
                logger.info(f"✅ [NORMAL] {name}: {len(alerts)} alerts collected")
        
        total_alerts = sum(len(alerts) for alerts in results.values())
        logger.info(f"🎯 Hybrid execution completed: {total_alerts} total alerts from {len(results)} sources")
        
        return results
    
    def enable_source(self, source_name: str) -> bool:
        """Enable a specific source."""
        if source_name in self.source_configs:
            self.source_configs[source_name].enabled = True
            logger.info(f"✅ Enabled source: {source_name}")
            return True
        return False
    
    def disable_source(self, source_name: str) -> bool:
        """Disable a specific source."""
        if source_name in self.source_configs:
            self.source_configs[source_name].enabled = False
            logger.info(f"⏸️ Disabled source: {source_name}")
            return True
        return False
    
    def get_healthy_sources(self) -> List[str]:
        """Get list of healthy source names."""
        return [
            name for name, executor in self.sources.items()
            if executor.is_healthy and self.source_configs[name].enabled
        ]
    
    def get_failed_sources(self) -> List[str]:
        """Get list of failed source names."""
        return [
            name for name, executor in self.sources.items()
            if not executor.is_healthy
        ]
    
    def reset_source_failures(self, source_name: str) -> bool:
        """Reset failure count for a specific source."""
        if source_name in self.sources:
            self.sources[source_name].consecutive_failures = 0
            logger.info(f"🔄 Reset failures for source: {source_name}")
            return True
        return False
    
    def get_execution_summary(self, results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Get summary of execution results."""
        total_alerts = sum(len(alerts) for alerts in results.values())
        successful_sources = sum(1 for alerts in results.values() if len(alerts) > 0)
        failed_sources = len(results) - successful_sources
        
        source_details = {}
        for name, alerts in results.items():
            executor = self.sources.get(name)
            source_details[name] = {
                "alerts_count": len(alerts),
                "status": "success" if len(alerts) > 0 or not executor else "failed",
                "is_healthy": executor.is_healthy if executor else False,
                "consecutive_failures": executor.consecutive_failures if executor else 0
            }
        
        return {
            "total_alerts": total_alerts,
            "total_sources": len(results),
            "successful_sources": successful_sources,
            "failed_sources": failed_sources,
            "success_rate": (successful_sources / len(results) * 100) if results else 0,
            "execution_mode": self.execution_mode.value,
            "source_details": source_details
        }


# Factory functions for creating common source configurations
def create_source_config(name: str, fetch_function: Callable, source_type: SourceType, **kwargs) -> SourceConfig:
    """Factory function to create source configuration with defaults."""
    return SourceConfig(
        name=name,
        fetch_function=fetch_function,
        source_type=source_type,
        **kwargs
    )


def create_cve_source_config(name: str, fetch_function: Callable, **kwargs) -> SourceConfig:
    """Create configuration for CVE sources."""
    defaults = {
        "source_type": SourceType.CVE_FEED,
        "timeout_seconds": 45,
        "max_alerts": 20,
        "priority": 1,
        "rate_limit_per_hour": 100
    }
    defaults.update(kwargs)
    return create_source_config(name, fetch_function, **defaults)


def create_social_source_config(name: str, fetch_function: Callable, **kwargs) -> SourceConfig:
    """Create configuration for social media sources."""
    defaults = {
        "source_type": SourceType.SOCIAL_MEDIA,
        "timeout_seconds": 30,
        "max_alerts": 10,
        "priority": 3,
        "rate_limit_per_hour": 1000,
        "retry_count": 1
    }
    defaults.update(kwargs)
    return create_source_config(name, fetch_function, **defaults)


def create_government_source_config(name: str, fetch_function: Callable, **kwargs) -> SourceConfig:
    """Create configuration for government sources."""
    defaults = {
        "source_type": SourceType.GOVERNMENT,
        "timeout_seconds": 60,
        "max_alerts": 25,
        "priority": 1,
        "rate_limit_per_hour": 50
    }
    defaults.update(kwargs)
    return create_source_config(name, fetch_function, **defaults)


# Context manager for source management
@asynccontextmanager
async def managed_sources(configs: List[SourceConfig], 
                         execution_mode: ExecutionMode = ExecutionMode.PARALLEL,
                         metrics_collector: Optional[MetricsCollector] = None):
    """Context manager for source execution with automatic cleanup."""
    manager = SourceManager(execution_mode=execution_mode, metrics_collector=metrics_collector)
    
    try:
        # Register all sources
        manager.register_sources(configs)
        yield manager
    finally:
        # Cleanup if needed
        logger.debug("🧹 Cleaning up source manager")


# Example usage and testing
if __name__ == "__main__":
    import asyncio
    
    # Mock source functions for testing
    async def mock_cve_source(limit=10):
        await asyncio.sleep(0.1)  # Simulate API call
        return [{"id": f"cve-{i}", "title": f"CVE Test {i}"} for i in range(min(3, limit))]
    
    def mock_reddit_source(limit=10):
        time.sleep(0.1)  # Simulate API call
        return [{"id": f"reddit-{i}", "title": f"Reddit Test {i}"} for i in range(min(2, limit))]
    
    async def test_source_manager():
        """Test the source manager functionality."""
        from .metrics import MetricsCollector
        
        # Create metrics collector
        metrics = MetricsCollector("test-run")
        
        # Create source configurations
        configs = [
            create_cve_source_config("MockCVE", mock_cve_source, priority=1),
            create_social_source_config("MockReddit", mock_reddit_source, priority=2)
        ]
        
        # Test parallel execution
        async with managed_sources(configs, ExecutionMode.PARALLEL, metrics) as manager:
            logger.info("Testing parallel execution...")
            results = await manager.execute_all_async()
            
            summary = manager.get_execution_summary(results)
            logger.info(f"Results: {summary}")
            
            # Print detailed metrics
            metrics.finalize()
            metrics.log_detailed_metrics()
    
    # Run test
    logging.basicConfig(level=logging.INFO)
    asyncio.run(test_source_manager())