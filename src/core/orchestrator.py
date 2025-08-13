# FILE: src/core/orchestrator.py
from __future__ import annotations

import asyncio
import logging
import os
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum

from .metrics import MetricsCollector, MetricStatus, PipelineMetrics
from .source_manager import (
    SourceManager, SourceConfig, ExecutionMode, SourceType,
    create_cve_source_config, create_social_source_config, create_government_source_config
)
from .alert_processor import AlertProcessor, ProcessedAlert, create_default_processor
from ..secure_storage import load_sent_ids, save_sent_ids

logger = logging.getLogger(__name__)


# -------------------- Modo de pipeline / parse helpers -------------------- #

class PipelineMode(Enum):
    PRODUCTION = "production"
    TESTING = "testing"
    DRY_RUN = "dry_run"


def _parse_execution_mode(val: str) -> ExecutionMode:
    v = (val or "").strip().lower()
    if v in ("parallel", "par"):
        return ExecutionMode.PARALLEL
    if v in ("sequential", "seq"):
        return ExecutionMode.SEQUENTIAL
    if v in ("hybrid", "mix"):
        return ExecutionMode.HYBRID
    return ExecutionMode.PARALLEL


def _parse_pipeline_mode(val: str) -> PipelineMode:
    v = (val or "").strip().lower()
    if v in ("production", "prod"):
        return PipelineMode.PRODUCTION
    if v in ("testing", "test"):
        return PipelineMode.TESTING
    if v in ("dry_run", "dry"):
        return PipelineMode.DRY_RUN
    return PipelineMode.PRODUCTION


# ------------------------------ Config ----------------------------------- #

@dataclass
class OrchestrationConfig:
    # Pipeline
    pipeline_mode: PipelineMode = PipelineMode.PRODUCTION
    max_alerts_per_source: int = 15
    min_critical_score: float = 7.0
    min_fallback_score: float = 3.0

    # Ejecución de fuentes
    source_execution_mode: ExecutionMode = ExecutionMode.PARALLEL
    max_parallel_sources: int = 5
    source_timeout_seconds: int = 30

    # Procesamiento
    enable_external_apis: bool = False
    max_alert_age_days: int = 30
    enable_deduplication: bool = True

    # Notificaciones / Integraciones
    enable_telegram: bool = True
    enable_looker_sync: bool = True
    telegram_rate_limit: int = 20

    # Flags
    enable_ml_classification: bool = False
    enable_advanced_scoring: bool = True
    enable_campaign_detection: bool = False

    # Ventana de interés (por ahora informativa; las fuentes pueden usarla)
    alerts_window_hours: int = 24

    # Palabras clave críticas
    critical_keywords: List[str] = field(default_factory=lambda: [
        "rce", "remote code execution", "bypass", "0day", "zero-day",
        "privesc", "privilege escalation", "exploit", "critical", "crítico",
        "falabella", "sodimac", "tottus", "linio", "banco falabella"
    ])

    @classmethod
    def from_env(cls) -> "OrchestrationConfig":
        return cls(
            pipeline_mode=_parse_pipeline_mode(os.getenv("PIPELINE_MODE", "production")),
            max_alerts_per_source=int(os.getenv("MAX_ALERTS_PER_SOURCE", "15")),
            min_critical_score=float(os.getenv("MIN_CRITICAL_SCORE", "7.0")),
            min_fallback_score=float(os.getenv("MIN_FALLBACK_SCORE", "3.0")),
            source_execution_mode=_parse_execution_mode(os.getenv("SOURCE_EXECUTION_MODE", "parallel")),
            max_parallel_sources=int(os.getenv("MAX_PARALLEL_SOURCES", "5")),
            source_timeout_seconds=int(os.getenv("SOURCE_TIMEOUT", "30")),
            enable_external_apis=os.getenv("ENABLE_EXTERNAL_APIS", "false").lower() == "true",
            enable_telegram=os.getenv("ENABLE_TELEGRAM", "true").lower() == "true",
            enable_looker_sync=os.getenv("ENABLE_LOOKER_SYNC", "true").lower() == "true",
            alerts_window_hours=int(os.getenv("ALERTS_WINDOW_HOURS", "24")),
        )


# ------------------------------ Result ----------------------------------- #

@dataclass
class OrchestrationResult:
    success: bool
    pipeline_metrics: PipelineMetrics
    alerts_collected: int
    alerts_processed: int
    alerts_sent: int
    critical_alerts_count: int
    execution_time_seconds: float
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "alerts_collected": self.alerts_collected,
            "alerts_processed": self.alerts_processed,
            "alerts_sent": self.alerts_sent,
            "critical_alerts_count": self.critical_alerts_count,
            "execution_time_seconds": self.execution_time_seconds,
            "errors": self.errors,
            "pipeline_metrics": self.pipeline_metrics.to_dict() if self.pipeline_metrics else None,
        }


# ---------------------------- Orchestrator -------------------------------- #

class ThreatIntelligenceOrchestrator:
    def __init__(self, config: Optional[OrchestrationConfig] = None):
        self.config = config or OrchestrationConfig.from_env()
        self.metrics_collector = MetricsCollector()

        self.source_manager = SourceManager(
            execution_mode=self.config.source_execution_mode,
            max_parallel_sources=self.config.max_parallel_sources,
            metrics_collector=self.metrics_collector,
        )

        self.alert_processor: Optional[AlertProcessor] = None
        self.notification_manager = None
        self.dashboard_sync = None

        # Estado
        self.sent_ids: Set[str] = set()
        self.current_alerts: List[ProcessedAlert] = []
        self.critical_alerts: List[ProcessedAlert] = []

        # Registrar fuentes
        self._register_threat_sources()

    def _register_threat_sources(self) -> None:
        """Registra todas las fuentes TI. Desactiva algunas si faltan credenciales."""
        try:
            from ..sources.mitre import fetch_mitre_techniques
            from ..sources.cisa import fetch_cisa_alerts
            from ..sources.stepsecurity import fetch_stepsecurity_posts
            from ..sources.cert import fetch_cert_alerts
            from ..sources.threatfeeds import fetch_threat_feeds
            from ..sources.reddit import fetch_reddit_posts
            from ..sources.exploitdb import fetch_exploitdb_alerts
            from ..sources.github_advisories import fetch_github_advisories
            from ..sources.csirtcl import fetch_csirt_cl_alerts
            from ..collector import get_latest_cves, get_latest_pocs

            github_token_present = bool(os.getenv("GHSA_TOKEN") or os.getenv("GITHUB_TOKEN"))

            configs: List[SourceConfig] = [
                # Gobierno (alta prioridad)
                create_government_source_config("CISA", fetch_cisa_alerts, priority=1, max_alerts=20, timeout_seconds=45),
                create_government_source_config("CERT", fetch_cert_alerts, priority=1, max_alerts=25, timeout_seconds=60),
                create_government_source_config("CSIRT Chile", fetch_csirt_cl_alerts, priority=2, max_alerts=15, timeout_seconds=30),

                # CVE / PoC
                create_cve_source_config("CVE", get_latest_cves, priority=1, max_alerts=20, timeout_seconds=45),
                create_cve_source_config("PoC", get_latest_pocs, priority=1, max_alerts=15, timeout_seconds=30),

                # GitHub Advisories (se desactiva si no hay token)
                create_cve_source_config(
                    "GitHub Advisories",
                    fetch_github_advisories,
                    priority=2,
                    max_alerts=15,
                    timeout_seconds=30,
                    enabled=github_token_present,
                ),

                # Investigación / comunidad / comerciales
                SourceConfig(
                    name="MITRE ATT&CK",
                    fetch_function=fetch_mitre_techniques,
                    source_type=SourceType.RESEARCH,
                    priority=2,
                    max_alerts=10,
                    timeout_seconds=30,
                ),
                SourceConfig(
                    name="StepSecurity",
                    fetch_function=fetch_stepsecurity_posts,
                    source_type=SourceType.RESEARCH,
                    priority=3,
                    max_alerts=10,
                    timeout_seconds=25,
                ),
                SourceConfig(
                    name="ThreatFeeds",
                    fetch_function=fetch_threat_feeds,
                    source_type=SourceType.COMMERCIAL,
                    priority=3,
                    max_alerts=15,
                    timeout_seconds=45,
                ),
                SourceConfig(
                    name="ExploitDB",
                    fetch_function=fetch_exploitdb_alerts,
                    source_type=SourceType.COMMUNITY,
                    priority=3,
                    max_alerts=10,
                    timeout_seconds=25,
                ),

                # Social (baja prioridad)
                create_social_source_config(
                    "Reddit",
                    fetch_reddit_posts,
                    priority=4,
                    max_alerts=8,
                    timeout_seconds=20,
                    retry_count=1,
                ),
            ]

            self.source_manager.register_sources(configs)
            logger.info(f"✅ Registered {len(configs)} threat intelligence sources")

        except ImportError as e:
            logger.error(f"❌ Failed to import source functions: {e}")
            raise
        except Exception as e:
            logger.error(f"❌ Failed to register sources: {e}")
            raise

    async def execute_pipeline(self) -> OrchestrationResult:
        start = datetime.now(timezone.utc)

        try:
            logger.info(f"🚀 Starting C4A Threat Intelligence Pipeline ({self.config.pipeline_mode.value} mode)")

            # Fase 1: datos históricos
            await self._load_historical_data()

            # Fase 2: colección de fuentes
            if self.config.source_execution_mode == ExecutionMode.PARALLEL:
                source_results = await self.source_manager.execute_all_async()
            else:
                source_results = self.source_manager.execute_all_sync()

            total_collected = sum(len(v) for v in source_results.values())
            ok_sources = sum(1 for v in source_results.values() if v)
            logger.info(f"📊 Collection completed: {total_collected} alerts from {ok_sources}/{len(source_results)} sources")

            # Fase 3: procesamiento
            processed_alerts = await self._process_alerts(source_results)

            # Fase 4: selección de críticos
            critical_alerts = self._filter_critical_alerts(processed_alerts)

            # Fase 5: notificaciones
            sent_count = await self._send_notifications(critical_alerts)

            # Fase 6: sincronización dashboard
            await self._sync_to_dashboard(processed_alerts)

            # Fase 7: persistencia
            await self._save_state()

            pipeline_metrics = self.metrics_collector.finalize(MetricStatus.SUCCESS)
            elapsed = (datetime.now(timezone.utc) - start).total_seconds()

            result = OrchestrationResult(
                success=True,
                pipeline_metrics=pipeline_metrics,
                alerts_collected=total_collected,
                alerts_processed=len(processed_alerts),
                alerts_sent=sent_count,
                critical_alerts_count=len(critical_alerts),
                execution_time_seconds=elapsed,
            )
            logger.info(f"✅ Pipeline completed successfully: {self.metrics_collector.get_summary()}")
            return result

        except Exception as e:
            pipeline_metrics = self.metrics_collector.finalize(MetricStatus.ERROR)
            elapsed = (datetime.now(timezone.utc) - start).total_seconds()
            msg = str(e)
            logger.error(f"❌ Pipeline failed: {msg}")
            return OrchestrationResult(
                success=False,
                pipeline_metrics=pipeline_metrics,
                alerts_collected=0,
                alerts_processed=0,
                alerts_sent=0,
                critical_alerts_count=0,
                execution_time_seconds=elapsed,
                errors=[msg],
            )

    async def _load_historical_data(self) -> None:
        try:
            self.sent_ids = load_sent_ids()
            logger.info(f"✅ Loaded {len(self.sent_ids)} historical alert IDs")
        except Exception as e:
            logger.warning(f"⚠️ Failed to load historical data: {e}")
            self.sent_ids = set()

    async def _process_alerts(self, source_results: Dict[str, List[Dict[str, Any]]]) -> List[ProcessedAlert]:
        raw_alerts: List[Dict[str, Any]] = []
        for source_name, alerts in source_results.items():
            for alert in alerts:
                if isinstance(alert, dict):
                    alert.setdefault("source", source_name)
                    raw_alerts.append(alert)

        if not raw_alerts:
            logger.warning("⚠️ No alerts to process")
            return []

        logger.info(f"⚙️ Processing {len(raw_alerts)} raw alerts through pipeline...")

        self.alert_processor = create_default_processor(
            existing_hashes=self.sent_ids if self.config.enable_deduplication else None,
            min_score=self.config.min_fallback_score,
        )
        self.alert_processor.config.update({
            "enable_external_apis": self.config.enable_external_apis,
            "max_age_days": self.config.max_alert_age_days,
            "min_score": self.config.min_fallback_score,
            "scoring": {"critical_keywords": self.config.critical_keywords},
        })

        processed = self.alert_processor.process_pipeline(raw_alerts)
        self.current_alerts = processed

        logger.info(f"📊 Processing completed: {len(processed)} alerts ready")
        if hasattr(self.alert_processor, "get_processing_summary"):
            s = self.alert_processor.get_processing_summary()
            eff = s.get("processing_efficiency", 0)
            logger.info(f"📈 Processing efficiency: {eff:.1f}%")

        return processed

    def _filter_critical_alerts(self, processed_alerts: List[ProcessedAlert]) -> List[ProcessedAlert]:
        critical: List[ProcessedAlert] = []
        for alert in processed_alerts:
            if alert.id in self.sent_ids or alert.content_hash in self.sent_ids:
                continue

            if alert.risk_score >= self.config.min_critical_score:
                critical.append(alert)
                continue

            text = f"{alert.title} {alert.description}".lower()
            if any(keyword in text for keyword in self.config.critical_keywords):
                critical.append(alert)

        self.critical_alerts = critical
        logger.info(f"🚨 Identified {len(critical)} critical alerts")
        return critical

    async def _send_notifications(self, critical_alerts: List[ProcessedAlert]) -> int:
        if not self.config.enable_telegram or self.config.pipeline_mode == PipelineMode.DRY_RUN:
            logger.info("📧 Notifications disabled or dry run mode")
            return 0

        from ..telegram_bot import TelegramBot
        bot = TelegramBot()

        to_send: List[ProcessedAlert] = critical_alerts[:]
        if not to_send:
            logger.info("⚠️ No critical alerts found, applying fallback strategy")
            fallback = [
                a for a in self.current_alerts
                if a.risk_score >= self.config.min_fallback_score and a.id not in self.sent_ids
            ][:5]
            to_send = fallback

        sent = 0
        for alert in to_send:
            try:
                message = self._format_telegram_message(alert)
                ok = await asyncio.to_thread(bot.send_message, message)  # no bloquear event loop
                if ok:
                    self.sent_ids.add(alert.id)
                    self.sent_ids.add(alert.content_hash)
                    sent += 1
                    logger.info(f"✅ Sent: {alert.title}")
                else:
                    logger.error(f"❌ Failed to send: {alert.title}")
            except Exception as e:
                logger.error(f"❌ Error sending alert {alert.id}: {e}")

        return sent

    def _format_telegram_message(self, alert: ProcessedAlert) -> str:
        source_emojis = {
            "CISA": "🏛️",
            "CERT": "🛡️",
            "CVE": "📄",
            "PoC": "💣",
            "MITRE ATT&CK": "🎯",
            "GitHub Advisories": "📚",
            "Reddit": "🗣️",
            "ExploitDB": "🧨",
            "CSIRT Chile": "🇨🇱",
        }
        emoji = source_emojis.get(alert.source, "🔔")

        if alert.risk_score >= 8.0:
            risk_indicator = "🚨 CRÍTICO"
        elif alert.risk_score >= 6.0:
            risk_indicator = "⚡ ALTO"
        elif alert.risk_score >= 4.0:
            risk_indicator = "⚠️ MEDIO"
        else:
            risk_indicator = "ℹ️ BAJO"

        msg = f"{emoji} *{alert.title}*\n\n"
        if alert.description:
            desc = alert.description
            if len(desc) > 200:
                desc = desc[:197] + "..."
            msg += f"📝 {desc}\n\n"

        msg += f"📊 *Riesgo:* {risk_indicator} ({alert.risk_score:.1f}/10)\n"

        if alert.attack_types:
            msg += f"🔴 *Tipos de Ataque:* {', '.join(alert.attack_types)}\n"
        if alert.affected_products:
            msg += f"🔧 *Productos:* {', '.join(alert.affected_products[:3])}\n"
        if alert.kev_listed:
            msg += "⚡ *KEV Listed* - Explotación activa\n"
        if alert.poc_available:
            msg += "💥 *PoC Disponible*\n"
        if alert.cvss_score:
            msg += f"📈 *CVSS:* {alert.cvss_score}/10\n"

        msg += f"🔍 *Fuente:* {alert.source}\n"
        if alert.url:
            msg += f"🔗 {alert.url}\n"
        return msg

    async def _sync_to_dashboard(self, processed_alerts: List[ProcessedAlert]) -> None:
        if not self.config.enable_looker_sync or self.config.pipeline_mode == PipelineMode.DRY_RUN:
            logger.info("📊 Dashboard sync disabled or dry run mode")
            return
        try:
            from tools.sync_to_looker import send_to_looker
            send_to_looker([a.to_dict() for a in processed_alerts])
            logger.info(f"📊 Synced {len(processed_alerts)} alerts to dashboard")
        except ImportError:
            logger.warning("⚠️ Dashboard sync not available")
        except Exception as e:
            logger.error(f"❌ Dashboard sync failed: {e}")

    async def _save_state(self) -> None:
        try:
            if self.config.pipeline_mode != PipelineMode.DRY_RUN:
                save_sent_ids(self.sent_ids)
                logger.info(f"💾 Saved {len(self.sent_ids)} sent IDs")
        except Exception as e:
            logger.error(f"❌ Failed to save state: {e}")

    def get_status(self) -> Dict[str, Any]:
        source_status = self.source_manager.get_source_status()
        return {
            "config": {
                "pipeline_mode": self.config.pipeline_mode.value,
                "source_execution_mode": self.config.source_execution_mode.value,
                "max_parallel_sources": self.config.max_parallel_sources,
                "min_critical_score": self.config.min_critical_score,
            },
            "sources": {
                "total": len(source_status),
                "healthy": len([s for s in source_status.values() if s["healthy"]]),
                "enabled": len([s for s in source_status.values() if s["enabled"]]),
                "details": source_status,
            },
            "current_session": {
                "alerts_processed": len(self.current_alerts),
                "critical_alerts": len(self.critical_alerts),
                "sent_ids_count": len(self.sent_ids),
            },
        }


# ------------------------------ Factories -------------------------------- #

def create_orchestrator(mode: PipelineMode = PipelineMode.PRODUCTION) -> ThreatIntelligenceOrchestrator:
    cfg = OrchestrationConfig.from_env()
    cfg.pipeline_mode = mode
    return ThreatIntelligenceOrchestrator(cfg)


def create_test_orchestrator() -> ThreatIntelligenceOrchestrator:
    cfg = OrchestrationConfig(
        pipeline_mode=PipelineMode.TESTING,
        max_alerts_per_source=5,
        min_critical_score=2.0,  # umbral bajo para tests
        enable_external_apis=False,
        enable_telegram=False,
        enable_looker_sync=False,
        alerts_window_hours=int(os.getenv("ALERTS_WINDOW_HOURS_TEST", "24")),
    )
    return ThreatIntelligenceOrchestrator(cfg)
