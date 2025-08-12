"""
Core module for C4A Alerts - Threat Intelligence Pipeline

This module provides the core functionality for the C4A Alerts system,
including orchestration, source management, alert processing, and metrics.
"""

from .orchestrator import ThreatIntelligenceOrchestrator
from .source_manager import SourceManager, SourceConfig
from .alert_processor import AlertProcessor, ProcessingStage
from .metrics import PipelineMetrics, MetricsCollector

# Version info
__version__ = "4.0.0"
__author__ = "C4A Team"

# Export main classes
__all__ = [
    "ThreatIntelligenceOrchestrator",
    "SourceManager", 
    "SourceConfig",
    "AlertProcessor",
    "ProcessingStage", 
    "PipelineMetrics",
    "MetricsCollector"
]

# Module-level configuration
DEFAULT_CONFIG = {
    "max_sources_parallel": 5,
    "source_timeout_seconds": 30,
    "max_alerts_per_source": 15,
    "min_critical_score": 7.0,
    "enable_metrics": True,
    "enable_async": True
}

def get_version() -> str:
    """Get the current version of the core module."""
    return __version__

def get_default_config() -> dict:
    """Get the default configuration for the core module."""
    return DEFAULT_CONFIG.copy()