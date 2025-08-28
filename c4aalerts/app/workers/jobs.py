"""
Celery worker jobs for alert processing.
"""

from datetime import datetime
from typing import Any

from celery import current_task

from c4aalerts.app.schemas.alert import IOC, IOCType, NormalizedAlert
from c4aalerts.app.services.dedup import dedup_service
from c4aalerts.app.services.prioritize import prioritization_service
from c4aalerts.app.services.router import routing_service
from c4aalerts.app.workers.queue import celery_app


def _normalize_alert(alert_data: dict[str, Any]) -> NormalizedAlert:
    """Normalize raw alert data into a standardized format."""
    # Extract basic fields
    uid = alert_data.get("uid", f"alert_{datetime.utcnow().timestamp()}")
    source = alert_data.get("source", "unknown")
    title = alert_data.get("title", "Untitled Alert")
    description = alert_data.get("description", "")
    severity = alert_data.get("severity", "medium")

    # Convert string IOCs to IOC objects
    ioc_objects = []
    for ioc_value in alert_data.get("iocs", []):
        if isinstance(ioc_value, str):
            # Simple IOC creation - in PR#4 we'll implement proper IOC parsing
            ioc_type = IOCType.IP_ADDRESS if "." in ioc_value else IOCType.DOMAIN
            ioc_objects.append(IOC(value=ioc_value, type=ioc_type))
        else:
            ioc_objects.append(ioc_value)

    # Ensure content hash is at least 8 characters
    content_hash = alert_data.get("content_hash", "")
    if len(content_hash) < 8:
        content_hash = f"{content_hash}{'0' * (8 - len(content_hash))}"

    # Create normalized alert
    normalized_alert = NormalizedAlert(
        uid=uid,
        source=source,
        title=title,
        description=description,
        severity=severity,
        iocs=ioc_objects,
        cve_id=alert_data.get("cve_id"),
        cvss_score=alert_data.get("cvss_score"),
        epss_score=alert_data.get("epss_score"),
        tags=alert_data.get("tags", []),
        references=alert_data.get("references", []),
        published_at=alert_data.get("published_at"),
        content_hash=content_hash,
        confidence=alert_data.get("confidence", 0.5),
    )

    return normalized_alert

def _collect_from_sources(source: str = None) -> list[dict[str, Any]]:
    """Collect alerts from configured sources."""
    # TODO: Implement actual collection logic in PR#4
    # For now, return empty list
    return []

def _send_notifications(alert: NormalizedAlert, channels: list[str]) -> dict[str, Any]:
    """Send notifications to specified channels."""
    results = {}

    for channel in channels:
        # TODO: Implement actual notification logic in PR#5
        results[channel] = {
            "status": "sent",
            "alert_id": alert.uid,
            "timestamp": datetime.utcnow().isoformat()
        }

    return results

@celery_app.task(bind=True)
def process_alert_pipeline(self, alert_data: dict[str, Any]) -> dict[str, Any]:
    """Process an alert through the complete pipeline."""
    try:
        # Update task state
        self.update_state(state="PROGRESS", meta={"step": "normalizing"})

        # Step 1: Normalize alert
        normalized_alert = _normalize_alert(alert_data)

        # Update task state
        self.update_state(state="PROGRESS", meta={"step": "deduplicating"})

        # Step 2: Check for duplicates
        if dedup_service.is_duplicate(normalized_alert):
            return {
                "status": "duplicate",
                "alert_id": normalized_alert.uid,
                "message": "Alert is a duplicate"
            }

        # Update task state
        self.update_state(state="PROGRESS", meta={"step": "prioritizing"})

        # Step 3: Calculate priority
        priority_score = prioritization_service.calculate_priority(normalized_alert)

        # Update task state
        self.update_state(state="PROGRESS", meta={"step": "routing"})

        # Step 4: Determine notification channels
        target_channels = routing_service.get_target_channels(normalized_alert)

        # Update task state
        self.update_state(state="PROGRESS", meta={"step": "notifying"})

        # Step 5: Send notifications
        notification_results = _send_notifications(normalized_alert, target_channels)

        return {
            "status": "processed",
            "alert_id": normalized_alert.uid,
            "priority_score": priority_score,
            "target_channels": target_channels,
            "notifications": notification_results,
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

@celery_app.task(bind=True)
def collect_alerts_task(self) -> dict[str, Any]:
    """Collect alerts from all sources."""
    try:
        # Update task state
        self.update_state(state="PROGRESS", meta={"step": "collecting"})

        # Collect alerts
        alerts = _collect_from_sources()

        # Process each alert
        results = []
        for alert_data in alerts:
            result = process_alert_pipeline.delay(alert_data)
            results.append(result.id)

        return {
            "status": "completed",
            "alerts_collected": len(alerts),
            "tasks_queued": len(results),
            "task_ids": results,
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

@celery_app.task
def health_check_task() -> dict[str, Any]:
    """Health check task for workers."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "worker_id": current_task.request.id if current_task else "unknown"
    }
