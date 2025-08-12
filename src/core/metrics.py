"""
Metrics and telemetry module for C4A Alerts pipeline.

Provides comprehensive monitoring and observability for the threat intelligence pipeline,
including execution times, success rates, error tracking, and performance metrics.
"""

import time
import json
import logging
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Types of metrics collected."""
    COUNTER = "counter"
    GAUGE = "gauge" 
    HISTOGRAM = "histogram"
    TIMER = "timer"


class MetricStatus(Enum):
    """Status levels for metrics."""
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"
    INFO = "info"


@dataclass
class SourceMetrics:
    """Metrics for individual source execution."""
    name: str
    start_time: float
    end_time: Optional[float] = None
    alerts_collected: int = 0
    status: MetricStatus = MetricStatus.INFO
    error_message: Optional[str] = None
    retry_count: int = 0
    
    @property
    def duration_seconds(self) -> float:
        """Calculate execution duration in seconds."""
        if self.end_time is None:
            return time.time() - self.start_time
        return self.end_time - self.start_time
    
    @property
    def is_success(self) -> bool:
        """Check if source execution was successful."""
        return self.status == MetricStatus.SUCCESS
    
    def mark_completed(self, status: MetricStatus, error: Optional[str] = None) -> None:
        """Mark source execution as completed."""
        self.end_time = time.time()
        self.status = status
        if error:
            self.error_message = error


@dataclass 
class ProcessingStageMetrics:
    """Metrics for processing pipeline stages."""
    stage_name: str
    start_time: float
    end_time: Optional[float] = None
    input_count: int = 0
    output_count: int = 0
    filtered_count: int = 0
    error_count: int = 0
    status: MetricStatus = MetricStatus.INFO
    
    @property
    def duration_seconds(self) -> float:
        """Calculate stage execution duration."""
        if self.end_time is None:
            return time.time() - self.start_time
        return self.end_time - self.start_time
    
    @property
    def processing_rate(self) -> float:
        """Calculate alerts processed per second."""
        duration = self.duration_seconds
        return self.input_count / duration if duration > 0 else 0.0
    
    @property
    def filter_rate(self) -> float:
        """Calculate percentage of alerts filtered out."""
        return (self.filtered_count / self.input_count * 100) if self.input_count > 0 else 0.0


@dataclass
class PipelineMetrics:
    """Comprehensive metrics for entire pipeline execution."""
    run_id: str
    start_time: float
    end_time: Optional[float] = None
    
    # Source metrics
    source_metrics: Dict[str, SourceMetrics] = field(default_factory=dict)
    
    # Processing stage metrics  
    stage_metrics: Dict[str, ProcessingStageMetrics] = field(default_factory=dict)
    
    # Overall counts
    total_alerts_collected: int = 0
    total_alerts_processed: int = 0
    total_alerts_sent: int = 0
    total_errors: int = 0
    
    # Status tracking
    overall_status: MetricStatus = MetricStatus.INFO
    error_messages: List[str] = field(default_factory=list)
    
    @property
    def duration_seconds(self) -> float:
        """Calculate total pipeline execution duration."""
        if self.end_time is None:
            return time.time() - self.start_time
        return self.end_time - self.start_time
    
    @property
    def sources_success_rate(self) -> float:
        """Calculate percentage of sources that executed successfully."""
        if not self.source_metrics:
            return 0.0
        
        successful = sum(1 for m in self.source_metrics.values() if m.is_success)
        return (successful / len(self.source_metrics)) * 100
    
    @property
    def processing_efficiency(self) -> float:
        """Calculate overall processing efficiency (processed/collected)."""
        if self.total_alerts_collected == 0:
            return 0.0
        return (self.total_alerts_processed / self.total_alerts_collected) * 100
    
    @property
    def send_rate(self) -> float:
        """Calculate percentage of processed alerts that were sent."""
        if self.total_alerts_processed == 0:
            return 0.0
        return (self.total_alerts_sent / self.total_alerts_processed) * 100
    
    def add_error(self, error_message: str) -> None:
        """Add an error to the metrics."""
        self.error_messages.append(error_message)
        self.total_errors += 1
        if self.overall_status != MetricStatus.ERROR:
            self.overall_status = MetricStatus.ERROR
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for serialization."""
        data = asdict(self)
        
        # Convert enums to strings
        data['overall_status'] = self.overall_status.value
        
        for source_name, metrics in data['source_metrics'].items():
            metrics['status'] = metrics['status'].value if isinstance(metrics['status'], MetricStatus) else metrics['status']
        
        for stage_name, metrics in data['stage_metrics'].items():
            metrics['status'] = metrics['status'].value if isinstance(metrics['status'], MetricStatus) else metrics['status']
        
        return data
    
    def to_json(self) -> str:
        """Convert metrics to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)


class MetricsCollector:
    """Centralized metrics collection and management."""
    
    def __init__(self, run_id: Optional[str] = None):
        """Initialize metrics collector."""
        self.run_id = run_id or f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.metrics = PipelineMetrics(
            run_id=self.run_id,
            start_time=time.time()
        )
        self._active_timers: Dict[str, float] = {}
    
    def start_source(self, source_name: str) -> None:
        """Start timing a source execution."""
        self.metrics.source_metrics[source_name] = SourceMetrics(
            name=source_name,
            start_time=time.time()
        )
        logger.debug(f"📊 Started metrics for source: {source_name}")
    
    def complete_source(self, source_name: str, alerts_count: int, 
                       status: MetricStatus = MetricStatus.SUCCESS, 
                       error: Optional[str] = None) -> None:
        """Complete timing for a source execution."""
        if source_name in self.metrics.source_metrics:
            source_metric = self.metrics.source_metrics[source_name]
            source_metric.alerts_collected = alerts_count
            source_metric.mark_completed(status, error)
            
            # Update totals
            self.metrics.total_alerts_collected += alerts_count
            
            if status == MetricStatus.ERROR:
                self.metrics.add_error(f"Source {source_name}: {error or 'Unknown error'}")
            
            logger.debug(f"📊 Completed metrics for {source_name}: {alerts_count} alerts in {source_metric.duration_seconds:.2f}s")
    
    def start_stage(self, stage_name: str, input_count: int) -> None:
        """Start timing a processing stage."""
        self.metrics.stage_metrics[stage_name] = ProcessingStageMetrics(
            stage_name=stage_name,
            start_time=time.time(),
            input_count=input_count
        )
        logger.debug(f"📊 Started stage: {stage_name} with {input_count} inputs")
    
    def complete_stage(self, stage_name: str, output_count: int, 
                      filtered_count: int = 0, error_count: int = 0) -> None:
        """Complete timing for a processing stage."""
        if stage_name in self.metrics.stage_metrics:
            stage_metric = self.metrics.stage_metrics[stage_name]
            stage_metric.end_time = time.time()
            stage_metric.output_count = output_count
            stage_metric.filtered_count = filtered_count
            stage_metric.error_count = error_count
            
            # Determine status
            if error_count > 0:
                stage_metric.status = MetricStatus.ERROR
            elif filtered_count > 0:
                stage_metric.status = MetricStatus.WARNING
            else:
                stage_metric.status = MetricStatus.SUCCESS
            
            logger.debug(f"📊 Completed stage {stage_name}: {output_count} outputs, {filtered_count} filtered in {stage_metric.duration_seconds:.2f}s")
    
    def record_sent_alerts(self, count: int) -> None:
        """Record number of alerts sent."""
        self.metrics.total_alerts_sent = count
    
    def finalize(self, status: MetricStatus = MetricStatus.SUCCESS) -> PipelineMetrics:
        """Finalize metrics collection."""
        self.metrics.end_time = time.time()
        self.metrics.overall_status = status
        
        # Calculate final totals
        self.metrics.total_alerts_processed = sum(
            stage.output_count for stage in self.metrics.stage_metrics.values()
        )
        
        logger.info(f"📊 Pipeline metrics finalized: {self.get_summary()}")
        return self.metrics
    
    def get_summary(self) -> str:
        """Get a human-readable summary of metrics."""
        return (
            f"Run {self.run_id}: "
            f"{self.metrics.total_alerts_collected} collected, "
            f"{self.metrics.total_alerts_processed} processed, "
            f"{self.metrics.total_alerts_sent} sent "
            f"in {self.metrics.duration_seconds:.1f}s "
            f"({self.metrics.sources_success_rate:.0f}% sources OK)"
        )
    
    def log_detailed_metrics(self) -> None:
        """Log detailed metrics for analysis."""
        logger.info("📊 === DETAILED PIPELINE METRICS ===")
        logger.info(f"Run ID: {self.run_id}")
        logger.info(f"Duration: {self.metrics.duration_seconds:.2f}s")
        logger.info(f"Overall Status: {self.metrics.overall_status.value}")
        
        # Source metrics
        logger.info("📡 SOURCE METRICS:")
        for name, source_metric in self.metrics.source_metrics.items():
            logger.info(
                f"  {name}: {source_metric.alerts_collected} alerts "
                f"in {source_metric.duration_seconds:.2f}s "
                f"({source_metric.status.value})"
            )
        
        # Stage metrics  
        logger.info("⚙️ PROCESSING METRICS:")
        for name, stage_metric in self.metrics.stage_metrics.items():
            logger.info(
                f"  {name}: {stage_metric.input_count}→{stage_metric.output_count} "
                f"({stage_metric.filter_rate:.1f}% filtered) "
                f"in {stage_metric.duration_seconds:.2f}s"
            )
        
        # Summary
        logger.info("📈 SUMMARY:")
        logger.info(f"  Collection Rate: {self.metrics.total_alerts_collected}/{len(self.metrics.source_metrics)} sources")
        logger.info(f"  Processing Efficiency: {self.metrics.processing_efficiency:.1f}%")
        logger.info(f"  Send Rate: {self.metrics.send_rate:.1f}%")
        logger.info(f"  Error Count: {self.metrics.total_errors}")
        
        if self.metrics.error_messages:
            logger.info("❌ ERRORS:")
            for error in self.metrics.error_messages:
                logger.info(f"  - {error}")


# Context managers for easy timing
@contextmanager
def time_source(collector: MetricsCollector, source_name: str):
    """Context manager for timing source execution."""
    collector.start_source(source_name)
    alerts_count = 0
    error = None
    
    try:
        yield lambda count: setattr(time_source, 'alerts_count', count)
        # Get alerts count from the lambda (if used)
        alerts_count = getattr(time_source, 'alerts_count', 0)
        collector.complete_source(source_name, alerts_count, MetricStatus.SUCCESS)
    except Exception as e:
        error = str(e)
        collector.complete_source(source_name, alerts_count, MetricStatus.ERROR, error)
        raise


@contextmanager  
def time_stage(collector: MetricsCollector, stage_name: str, input_count: int):
    """Context manager for timing processing stages."""
    collector.start_stage(stage_name, input_count)
    output_count = 0
    filtered_count = 0
    error_count = 0
    
    try:
        yield lambda out, filt=0, err=0: (
            setattr(time_stage, 'output_count', out),
            setattr(time_stage, 'filtered_count', filt), 
            setattr(time_stage, 'error_count', err)
        )
        
        # Get counts from the lambda (if used)
        output_count = getattr(time_stage, 'output_count', input_count)
        filtered_count = getattr(time_stage, 'filtered_count', 0)
        error_count = getattr(time_stage, 'error_count', 0)
        
        collector.complete_stage(stage_name, output_count, filtered_count, error_count)
    except Exception as e:
        error_count = 1
        collector.complete_stage(stage_name, output_count, filtered_count, error_count)
        raise


# Utility functions for metrics analysis
def format_duration(seconds: float) -> str:
    """Format duration in human-readable format."""
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    else:
        return f"{seconds/60:.1f}m"


def calculate_percentile(values: List[float], percentile: float) -> float:
    """Calculate percentile of a list of values."""
    if not values:
        return 0.0
    
    sorted_values = sorted(values)
    index = (percentile / 100) * (len(sorted_values) - 1)
    
    if index.is_integer():
        return sorted_values[int(index)]
    else:
        lower_index = int(index)
        upper_index = lower_index + 1
        weight = index - lower_index
        return sorted_values[lower_index] * (1 - weight) + sorted_values[upper_index] * weight


def export_metrics_json(metrics: PipelineMetrics, filepath: str) -> bool:
    """Export metrics to JSON file."""
    try:
        with open(filepath, 'w') as f:
            f.write(metrics.to_json())
        logger.info(f"📊 Metrics exported to {filepath}")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to export metrics: {e}")
        return False


# Example usage and testing
if __name__ == "__main__":
    import time
    
    # Test metrics collection
    collector = MetricsCollector("test-run")
    
    # Simulate source collection
    with time_source(collector, "TestSource") as record:
        time.sleep(0.1)  # Simulate work
        record(5)  # Record 5 alerts collected
    
    # Simulate processing stage
    with time_stage(collector, "Normalization", 5) as record:
        time.sleep(0.05)  # Simulate work  
        record(4, 1, 0)  # 4 output, 1 filtered, 0 errors
    
    # Finalize and display
    final_metrics = collector.finalize(MetricStatus.SUCCESS)
    collector.log_detailed_metrics()
    
    print("\n" + "="*50)
    print("METRICS JSON:")
    print(final_metrics.to_json())