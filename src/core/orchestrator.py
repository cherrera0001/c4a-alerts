import asyncio
import logging
import sys
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from .metrics import MetricsCollector, MetricStatus, PipelineMetrics

from enum import Enum

class SourceType(Enum):
    """Types of threat intelligence sources."""
    CVE_FEED = "cve_feed"
    SOCIAL_MEDIA = "social_media"
    GOVERNMENT = "government"
    COMMERCIAL = "commercial"
    RESEARCH = "research"
    COMMUNITY = "community"

from .source_manager import (
    SourceManager, SourceConfig, ExecutionMode,
    create_cve_source_config, create_social_source_config, create_government_source_config
)
from .alert_processor import AlertProcessor, ProcessedAlert, create_default_processor
from ..secure_storage import load_sent_ids, save_sent_ids

logger = logging.getLogger(__name__)


class PipelineMode(Enum):
    """Pipeline execution modes."""
    PRODUCTION = "production"
    TESTING = "testing"
    DRY_RUN = "dry_run"


@dataclass
class OrchestrationConfig:
    """Configuration for threat intelligence orchestration."""
    # Pipeline settings
    pipeline_mode: PipelineMode = PipelineMode.PRODUCTION
    max_alerts_per_source: int = 15
    min_critical_score: float = 7.0
    min_fallback_score: float = 3.0
    
    # Source execution settings
    source_execution_mode: ExecutionMode = ExecutionMode.PARALLEL
    max_parallel_sources: int = 5
    source_timeout_seconds: int = 30
    
    # Processing settings
    enable_external_apis: bool = False  # EPSS/KEV APIs
    max_alert_age_days: int = 30
    enable_deduplication: bool = True
    
    # Notification settings
    enable_telegram: bool = True
    enable_looker_sync: bool = True
    telegram_rate_limit: int = 20  # messages per hour
    
    # Feature flags
    enable_ml_classification: bool = False
    enable_advanced_scoring: bool = True
    enable_campaign_detection: bool = False
    
    # Critical keywords for filtering
    critical_keywords: List[str] = field(default_factory=lambda: [
        "rce", "remote code execution", "bypass", "0day", "zero-day",
        "privesc", "privilege escalation", "exploit", "critical", "crítico",
        "falabella", "sodimac", "tottus", "linio", "banco falabella"
    ])
    
    @classmethod
    def from_env(cls) -> 'OrchestrationConfig':
        """Create configuration from environment variables."""
        import os
        
        return cls(
            pipeline_mode=PipelineMode(os.getenv("PIPELINE_MODE", "production")),
            max_alerts_per_source=int(os.getenv("MAX_ALERTS_PER_SOURCE", "15")),
            min_critical_score=float(os.getenv("MIN_CRITICAL_SCORE", "7.0")),
            min_fallback_score=float(os.getenv("MIN_FALLBACK_SCORE", "3.0")),
            source_execution_mode=ExecutionMode(os.getenv("SOURCE_EXECUTION_MODE", "parallel")),
            max_parallel_sources=int(os.getenv("MAX_PARALLEL_SOURCES", "5")),
            source_timeout_seconds=int(os.getenv("SOURCE_TIMEOUT", "30")),
            enable_external_apis=os.getenv("ENABLE_EXTERNAL_APIS", "false").lower() == "true",
            enable_telegram=os.getenv("ENABLE_TELEGRAM", "true").lower() == "true",
            enable_looker_sync=os.getenv("ENABLE_LOOKER_SYNC", "true").lower() == "true",
        )


@dataclass
class OrchestrationResult:
    """Result of orchestration execution."""
    success: bool
    pipeline_metrics: PipelineMetrics
    alerts_collected: int
    alerts_processed: int
    alerts_sent: int
    critical_alerts_count: int
    execution_time_seconds: float
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "success": self.success,
            "alerts_collected": self.alerts_collected,
            "alerts_processed": self.alerts_processed,
            "alerts_sent": self.alerts_sent,
            "critical_alerts_count": self.critical_alerts_count,
            "execution_time_seconds": self.execution_time_seconds,
            "errors": self.errors,
            "pipeline_metrics": self.pipeline_metrics.to_dict() if self.pipeline_metrics else None
        }


class ThreatIntelligenceOrchestrator:
    """Main orchestrator for threat intelligence pipeline."""
    
    def __init__(self, config: Optional[OrchestrationConfig] = None):
        self.config = config or OrchestrationConfig.from_env()
        self.metrics_collector = MetricsCollector()
        
        # Initialize components
        self.source_manager = SourceManager(
            execution_mode=self.config.source_execution_mode,
            max_parallel_sources=self.config.max_parallel_sources,
            metrics_collector=self.metrics_collector
        )
        
        self.alert_processor: Optional[AlertProcessor] = None
        #self.notification_manager: Optional['NotificationManager'] = None
        #self.dashboard_sync: Optional['DashboardSync'] = None
        self.notification_manager = None
        self.dashboard_sync = None
        
        # State
        self.sent_ids: Set[str] = set()
        self.current_alerts: List[ProcessedAlert] = []
        self.critical_alerts: List[ProcessedAlert] = []
        
        # Initialize sources
        self._register_threat_sources()
    
    def _register_threat_sources(self) -> None:
        """Register all threat intelligence sources."""
        try:
            # Import source functions (avoiding circular imports)
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
            
            # Register sources with appropriate configurations
            source_configs = [
                # High priority government sources
                create_government_source_config(
                    "CISA", fetch_cisa_alerts, 
                    priority=1, max_alerts=20, timeout_seconds=45
                ),
                create_government_source_config(
                    "CERT", fetch_cert_alerts,
                    priority=1, max_alerts=25, timeout_seconds=60
                ),
                create_government_source_config(
                    "CSIRT Chile", fetch_csirt_cl_alerts,
                    priority=2, max_alerts=15, timeout_seconds=30
                ),
                
                # High priority CVE sources
                create_cve_source_config(
                    "CVE", get_latest_cves,
                    priority=1, max_alerts=20, timeout_seconds=45
                ),
                create_cve_source_config(
                    "PoC", get_latest_pocs,
                    priority=1, max_alerts=15, timeout_seconds=30
                ),
                create_cve_source_config(
                    "GitHub Advisories", fetch_github_advisories,
                    priority=2, max_alerts=15, timeout_seconds=30
                ),
                
                # Medium priority research sources
                SourceConfig(
                    name="MITRE ATT&CK",
                    fetch_function=fetch_mitre_techniques,
                    source_type=SourceType.RESEARCH,
                    priority=2,
                    max_alerts=10,
                    timeout_seconds=30
                ),
                SourceConfig(
                    name="StepSecurity",
                    fetch_function=fetch_stepsecurity_posts,
                    source_type=SourceType.RESEARCH,
                    priority=3,
                    max_alerts=10,
                    timeout_seconds=25
                ),
                SourceConfig(
                    name="ThreatFeeds",
                    fetch_function=fetch_threat_feeds,
                    source_type=SourceType.COMMERCIAL,
                    priority=3,
                    max_alerts=15,
                    timeout_seconds=45
                ),
                SourceConfig(
                    name="ExploitDB",
                    fetch_function=fetch_exploitdb_alerts,
                    source_type=SourceType.COMMUNITY,
                    priority=3,
                    max_alerts=10,
                    timeout_seconds=25
                ),
                
                # Lower priority social sources
                create_social_source_config(
                    "Reddit", fetch_reddit_posts,
                    priority=4, max_alerts=8, timeout_seconds=20, retry_count=1
                )
            ]
            
            # Register all sources
            self.source_manager.register_sources(source_configs)
            logger.info(f"✅ Registered {len(source_configs)} threat intelligence sources")
            
        except ImportError as e:
            logger.error(f"❌ Failed to import source functions: {e}")
            raise
        except Exception as e:
            logger.error(f"❌ Failed to register sources: {e}")
            raise
    
    async def execute_pipeline(self) -> OrchestrationResult:
        """Execute the complete threat intelligence pipeline."""
        start_time = datetime.now()
        
        try:
            logger.info(f"🚀 Starting C4A Threat Intelligence Pipeline ({self.config.pipeline_mode.value} mode)")
            
            # Phase 1: Load historical data
            await self._load_historical_data()
            
            # Phase 2: Collect from sources
            source_results = await self._collect_from_sources()
            
            # Phase 3: Process alerts
            processed_alerts = await self._process_alerts(source_results)
            
            # Phase 4: Filter critical alerts
            critical_alerts = self._filter_critical_alerts(processed_alerts)
            
            # Phase 5: Send notifications
            sent_count = await self._send_notifications(critical_alerts)
            
            # Phase 6: Sync to dashboard
            await self._sync_to_dashboard(processed_alerts)
            
            # Phase 7: Save state
            await self._save_state()
            
            # Finalize metrics
            pipeline_metrics = self.metrics_collector.finalize(MetricStatus.SUCCESS)
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Create result
            result = OrchestrationResult(
                success=True,
                pipeline_metrics=pipeline_metrics,
                alerts_collected=sum(len(alerts) for alerts in source_results.values()),
                alerts_processed=len(processed_alerts),
                alerts_sent=sent_count,
                critical_alerts_count=len(critical_alerts),
                execution_time_seconds=execution_time
            )
            
            logger.info(f"✅ Pipeline completed successfully: {self.metrics_collector.get_summary()}")
            return result
            
        except Exception as e:
            # Handle pipeline failure
            pipeline_metrics = self.metrics_collector.finalize(MetricStatus.ERROR)
            execution_time = (datetime.now() - start_time).total_seconds()
            
            error_msg = str(e)
            logger.error(f"❌ Pipeline failed: {error_msg}")
            
            result = OrchestrationResult(
                success=False,
                pipeline_metrics=pipeline_metrics,
                alerts_collected=0,
                alerts_processed=0,
                alerts_sent=0,
                critical_alerts_count=0,
                execution_time_seconds=execution_time,
                errors=[error_msg]
            )
            
            return result
    
    async def _load_historical_data(self) -> None:
        """Load historical sent IDs for deduplication."""
        try:
            self.sent_ids = load_sent_ids()
            logger.info(f"✅ Loaded {len(self.sent_ids)} historical alert IDs")
        except Exception as e:
            logger.warning(f"⚠️ Failed to load historical data: {e}")
            self.sent_ids = set()
    
    async def _collect_from_sources(self) -> Dict[str, List[Dict[str, Any]]]:
        """Collect alerts from all configured sources."""
        logger.info("🔎 Collecting alerts from threat intelligence sources...")
        
        if self.config.source_execution_mode == ExecutionMode.PARALLEL:
            source_results = await self.source_manager.execute_all_async()
        else:
            source_results = self.source_manager.execute_all_sync()
        
        # Log collection summary
        total_collected = sum(len(alerts) for alerts in source_results.values())
        successful_sources = sum(1 for alerts in source_results.values() if alerts)
        
        logger.info(f"📊 Collection completed: {total_collected} alerts from {successful_sources}/{len(source_results)} sources")
        
        # Log per-source results
        for source_name, alerts in source_results.items():
            if alerts:
                logger.info(f"  ✅ {source_name}: {len(alerts)} alerts")
            else:
                logger.warning(f"  ⚠️ {source_name}: no alerts")
        
        return source_results
    
    async def _process_alerts(self, source_results: Dict[str, List[Dict[str, Any]]]) -> List[ProcessedAlert]:
        """Process raw alerts through the processing pipeline."""
        # Flatten all source results
        raw_alerts = []
        for source_name, alerts in source_results.items():
            for alert in alerts:
                if isinstance(alert, dict):
                    alert.setdefault('source', source_name)
                    raw_alerts.append(alert)
        
        if not raw_alerts:
            logger.warning("⚠️ No alerts to process")
            return []
        
        logger.info(f"⚙️ Processing {len(raw_alerts)} raw alerts through pipeline...")
        
        # Initialize alert processor
        self.alert_processor = create_default_processor(
            existing_hashes=self.sent_ids if self.config.enable_deduplication else None,
            min_score=self.config.min_fallback_score
        )
        
        # Configure processor
        processor_config = {
            "enable_external_apis": self.config.enable_external_apis,
            "max_age_days": self.config.max_alert_age_days,
            "min_score": self.config.min_fallback_score,
            "scoring": {
                "critical_keywords": self.config.critical_keywords
            }
        }
        self.alert_processor.config.update(processor_config)
        
        # Process alerts
        processed_alerts = self.alert_processor.process_pipeline(raw_alerts)
        self.current_alerts = processed_alerts
        
        logger.info(f"📊 Processing completed: {len(processed_alerts)} alerts ready")
        
        # Log processing summary
        if hasattr(self.alert_processor, 'get_processing_summary'):
            summary = self.alert_processor.get_processing_summary()
            logger.info(f"📈 Processing efficiency: {summary.get('processing_efficiency', 0):.1f}%")
        
        return processed_alerts
    
    def _filter_critical_alerts(self, processed_alerts: List[ProcessedAlert]) -> List[ProcessedAlert]:
        """Filter and identify critical alerts."""
        critical_alerts = []
        
        for alert in processed_alerts:
            # Check if already sent
            if alert.id in self.sent_ids or alert.content_hash in self.sent_ids:
                logger.debug(f"⏭️ Skipping already sent alert: {alert.title}")
                continue
            
            # Check critical score threshold
            if alert.risk_score >= self.config.min_critical_score:
                critical_alerts.append(alert)
                continue
            
            # Check critical keywords
            text = f"{alert.title} {alert.description}".lower()
            if any(keyword in text for keyword in self.config.critical_keywords):
                logger.info(f"🔍 Critical keyword match: {alert.title}")
                critical_alerts.append(alert)
                continue
        
        self.critical_alerts = critical_alerts
        logger.info(f"🚨 Identified {len(critical_alerts)} critical alerts")
        
        return critical_alerts
    
    async def _send_notifications(self, critical_alerts: List[ProcessedAlert]) -> int:
        """Send notifications for critical alerts."""
        if not self.config.enable_telegram or self.config.pipeline_mode == PipelineMode.DRY_RUN:
            logger.info(f"📧 Notifications disabled or dry run mode")
            return 0
        
        sent_count = 0
        
        if critical_alerts:
            logger.info(f"📬 Sending notifications for {len(critical_alerts)} critical alerts")
            sent_count = await self._send_telegram_notifications(critical_alerts)
        else:
            # Fallback: send lower-scored alerts if no critical alerts
            logger.info("⚠️ No critical alerts found, applying fallback strategy")
            fallback_alerts = [
                alert for alert in self.current_alerts 
                if alert.risk_score >= self.config.min_fallback_score and 
                   alert.id not in self.sent_ids
            ][:5]  # Limit fallback alerts
            
            if fallback_alerts:
                logger.info(f"📬 Sending {len(fallback_alerts)} fallback alerts")
                sent_count = await self._send_telegram_notifications(fallback_alerts)
        
        return sent_count
    
    async def _send_telegram_notifications(self, alerts: List[ProcessedAlert]) -> int:
        """Send Telegram notifications for alerts."""
        try:
            from ..telegram_bot import TelegramBot
            
            bot = TelegramBot()
            sent_count = 0
            
            for alert in alerts:
                try:
                    # Format message
                    message = self._format_telegram_message(alert)
                    
                    # Send message
                    if bot.send_message(message):
                        self.sent_ids.add(alert.id)
                        self.sent_ids.add(alert.content_hash)
                        sent_count += 1
                        logger.info(f"✅ Sent: {alert.title}")
                    else:
                        logger.error(f"❌ Failed to send: {alert.title}")
                        
                except Exception as e:
                    logger.error(f"❌ Error sending alert {alert.id}: {e}")
            
            return sent_count
            
        except ImportError:
            logger.error("❌ TelegramBot not available")
            return 0
        except Exception as e:
            logger.error(f"❌ Telegram notification error: {e}")
            return 0
    
    def _format_telegram_message(self, alert: ProcessedAlert) -> str:
        """Format alert for Telegram message."""
        # Source emoji mapping
        source_emojis = {
            "CISA": "🏛️",
            "CERT": "🛡️", 
            "CVE": "📄",
            "PoC": "💣",
            "MITRE ATT&CK": "🎯",
            "GitHub Advisories": "📚",
            "Reddit": "🗣️",
            "ExploitDB": "🧨",
            "CSIRT Chile": "🇨🇱"
        }
        
        emoji = source_emojis.get(alert.source, "🔔")
        
        # Risk level indicators
        if alert.risk_score >= 8.0:
            risk_indicator = "🚨 CRÍTICO"
        elif alert.risk_score >= 6.0:
            risk_indicator = "⚡ ALTO"
        elif alert.risk_score >= 4.0:
            risk_indicator = "⚠️ MEDIO"
        else:
            risk_indicator = "ℹ️ BAJO"
        
        # Build message
        message = f"{emoji} *{alert.title}*\n\n"
        
        if alert.description:
            desc = alert.description
            if len(desc) > 200:
                desc = desc[:197] + "..."
            message += f"📝 {desc}\n\n"
        
        # Risk and classification info
        message += f"📊 *Riesgo:* {risk_indicator} ({alert.risk_score:.1f}/10)\n"
        
        if alert.attack_types:
            message += f"🔴 *Tipos de Ataque:* {', '.join(alert.attack_types)}\n"
        
        if alert.affected_products:
            message += f"🔧 *Productos:* {', '.join(alert.affected_products[:3])}\n"
        
        if alert.kev_listed:
            message += f"⚡ *KEV Listed* - Explotación activa\n"
        
        if alert.poc_available:
            message += f"💥 *PoC Disponible*\n"
        
        if alert.cvss_score:
            message += f"📈 *CVSS:* {alert.cvss_score}/10\n"
        
        message += f"🔍 *Fuente:* {alert.source}\n"
        
        if alert.url:
            message += f"🔗 {alert.url}\n"
        
        return message
    
    async def _sync_to_dashboard(self, processed_alerts: List[ProcessedAlert]) -> None:
        """Sync processed alerts to dashboard."""
        if not self.config.enable_looker_sync or self.config.pipeline_mode == PipelineMode.DRY_RUN:
            logger.info("📊 Dashboard sync disabled or dry run mode")
            return
        
        try:
            from tools.sync_to_looker import send_to_looker
            
            # Convert ProcessedAlert objects to dict format expected by sync_to_looker
            alert_dicts = [alert.to_dict() for alert in processed_alerts]
            
            send_to_looker(alert_dicts)
            logger.info(f"📊 Synced {len(alert_dicts)} alerts to dashboard")
            
        except ImportError:
            logger.warning("⚠️ Dashboard sync not available")
        except Exception as e:
            logger.error(f"❌ Dashboard sync failed: {e}")
    
    async def _save_state(self) -> None:
        """Save current state (sent IDs, metrics, etc.)."""
        try:
            # Save sent IDs
            if self.config.pipeline_mode != PipelineMode.DRY_RUN:
                save_sent_ids(self.sent_ids)
                logger.info(f"💾 Saved {len(self.sent_ids)} sent IDs")
            
            # Save metrics (if needed)
            # TODO: Implement metrics persistence
            
        except Exception as e:
            logger.error(f"❌ Failed to save state: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current orchestrator status."""
        source_status = self.source_manager.get_source_status()
        
        return {
            "config": {
                "pipeline_mode": self.config.pipeline_mode.value,
                "source_execution_mode": self.config.source_execution_mode.value,
                "max_parallel_sources": self.config.max_parallel_sources,
                "min_critical_score": self.config.min_critical_score
            },
            "sources": {
                "total": len(source_status),
                "healthy": len([s for s in source_status.values() if s['healthy']]),
                "enabled": len([s for s in source_status.values() if s['enabled']]),
                "details": source_status
            },
            "current_session": {
                "alerts_processed": len(self.current_alerts),
                "critical_alerts": len(self.critical_alerts),
                "sent_ids_count": len(self.sent_ids)
            }
        }
    
    def enable_source(self, source_name: str) -> bool:
        """Enable a specific source."""
        return self.source_manager.enable_source(source_name)
    
    def disable_source(self, source_name: str) -> bool:
        """Disable a specific source."""
        return self.source_manager.disable_source(source_name)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary."""
        if hasattr(self.metrics_collector, 'metrics'):
            return {
                "pipeline_metrics": self.metrics_collector.get_summary(),
                "source_metrics": {
                    name: {
                        "duration": metric.duration_seconds,
                        "alerts": metric.alerts_collected,
                        "status": metric.status.value
                    }
                    for name, metric in self.metrics_collector.metrics.source_metrics.items()
                },
                "processing_summary": (
                    self.alert_processor.get_processing_summary() 
                    if self.alert_processor else {}
                )
            }
        return {}


# Factory functions
def create_orchestrator(mode: PipelineMode = PipelineMode.PRODUCTION) -> ThreatIntelligenceOrchestrator:
    """Create orchestrator with specified mode."""
    config = OrchestrationConfig.from_env()
    config.pipeline_mode = mode
    return ThreatIntelligenceOrchestrator(config)


def create_test_orchestrator() -> ThreatIntelligenceOrchestrator:
    """Create orchestrator for testing."""
    config = OrchestrationConfig(
        pipeline_mode=PipelineMode.TESTING,
        max_alerts_per_source=5,
        min_critical_score=2.0,  # Lower threshold for testing
        enable_external_apis=False,
        enable_telegram=False,
        enable_looker_sync=False
    )
    return ThreatIntelligenceOrchestrator(config)


# Context manager for orchestration
async def managed_orchestration(config: Optional[OrchestrationConfig] = None):
    """Context manager for orchestrator with automatic cleanup."""
    orchestrator = ThreatIntelligenceOrchestrator(config)
    try:
        yield orchestrator
    finally:
        # Cleanup if needed
        logger.debug("🧹 Cleaning up orchestrator")


# CLI-compatible function (backward compatibility)
async def run_alerts() -> OrchestrationResult:
    """Main entry point for alert processing (backward compatible)."""
    orchestrator = create_orchestrator()
    return await orchestrator.execute_pipeline()


# Example usage and testing
if __name__ == "__main__":
    import asyncio
    import json
    
    async def test_orchestrator():
        """Test the orchestrator functionality."""
        logging.basicConfig(level=logging.INFO)
        
        # Create test orchestrator
        orchestrator = create_test_orchestrator()
        
        # Run pipeline
        result = await orchestrator.execute_pipeline()
        
        # Display results
        print("="*60)
        print("ORCHESTRATION RESULTS:")
        print(json.dumps(result.to_dict(), indent=2, default=str))
        
        print("\nORCHESTRATOR STATUS:")
        status = orchestrator.get_status()
        print(json.dumps(status, indent=2))
        
        print("\nMETRICS SUMMARY:")
        metrics = orchestrator.get_metrics_summary()
        print(json.dumps(metrics, indent=2, default=str))
    
    # Run test
    asyncio.run(test_orchestrator())