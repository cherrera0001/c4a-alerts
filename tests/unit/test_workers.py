"""
Unit tests for worker functions.
"""

from datetime import datetime

from c4aalerts.app.schemas.alert import IOC, AlertSeverity, IOCType, NormalizedAlert
from c4aalerts.app.workers.jobs import (
    _collect_from_sources,
    _normalize_alert,
    _send_notifications,
)


class TestWorkerJobs:
    """Test worker job functions."""

    def test_normalize_alert(self):
        """Test alert normalization."""
        alert_data = {
            "uid": "test_alert_123",
            "source": "test_source",
            "title": "Test Alert",
            "description": "Test description",
            "severity": "high",
            "iocs": ["192.168.1.1", "malicious.com"],
            "cve_id": "CVE-2024-0001",
            "cvss_score": 8.5,
            "epss_score": 0.75,
            "tags": ["test", "security"],
            "references": ["https://example.com"],
            "published_at": "2024-01-01T00:00:00Z",
            "content_hash": "abc123456",
            "confidence": 0.8,
        }

        normalized = _normalize_alert(alert_data)

        assert isinstance(normalized, NormalizedAlert)
        assert normalized.uid == "test_alert_123"
        assert normalized.source == "test_source"
        assert normalized.title == "Test Alert"
        assert normalized.severity == AlertSeverity.HIGH
        assert len(normalized.iocs) == 2
        assert normalized.iocs[0].value == "192.168.1.1"
        assert normalized.iocs[0].type == IOCType.IP_ADDRESS
        assert normalized.iocs[1].value == "malicious.com"
        assert normalized.iocs[1].type == IOCType.DOMAIN
        assert normalized.cve_id == "CVE-2024-0001"
        assert normalized.cvss_score == 8.5
        assert normalized.epss_score == 0.75
        assert normalized.tags == ["test", "security"]
        assert normalized.confidence == 0.8
        assert normalized.content_hash == "abc123456"

    def test_normalize_alert_with_defaults(self):
        """Test alert normalization with missing fields."""
        # Minimal test data
        alert_data = {
            "title": "Minimal Alert",
        }

        # Normalize alert
        normalized = _normalize_alert(alert_data)

        assert isinstance(normalized, NormalizedAlert)
        assert normalized.title == "Minimal Alert"
        assert normalized.source == "unknown"
        assert normalized.severity == AlertSeverity.MEDIUM
        assert normalized.description == ""
        assert len(normalized.iocs) == 0
        assert normalized.confidence == 0.5

    def test_send_notifications(self):
        """Test notification sending."""
        alert = NormalizedAlert(
            uid="test_alert",
            source="test",
            title="Test Alert",
            description="Test",
            severity=AlertSeverity.HIGH,
            content_hash="test123456",
            iocs=[IOC(value="192.168.1.1", type=IOCType.IP_ADDRESS)],
        )

        channels = ["telegram", "slack", "email"]
        results = _send_notifications(alert, channels)

        assert isinstance(results, dict)
        assert len(results) == 3

        for channel in channels:
            assert channel in results
            assert results[channel]["status"] == "sent"
            assert results[channel]["alert_id"] == "test_alert"

    def test_collect_from_sources(self):
        """Test alert collection from sources."""
        # Currently returns empty list (TODO: implement in PR#4)
        alerts = _collect_from_sources()
        assert isinstance(alerts, list)
        assert len(alerts) == 0

class TestWorkerPipeline:
    """Test the complete worker pipeline."""

    def test_pipeline_integration(self):
        """Test integration of pipeline components."""
        alert_data = {
            "uid": "integration_test_123",
            "source": "integration_test",
            "title": "Integration Test Alert",
            "description": "Testing the complete pipeline",
            "severity": "critical",
            "iocs": ["192.168.1.100", "malware-test.com"],
            "cve_id": "CVE-2024-INTEGRATION-001",
            "cvss_score": 9.5,
            "epss_score": 0.95,
            "tags": ["integration", "test", "critical"],
            "references": ["https://example.com/integration"],
            "published_at": datetime.utcnow().isoformat(),
            "content_hash": "integration123hash456",
            "confidence": 0.95,
        }

        # Test normalization
        normalized = _normalize_alert(alert_data)

        assert normalized.uid == "integration_test_123"
        assert normalized.severity == AlertSeverity.CRITICAL
        assert normalized.cvss_score == 9.5

        # Test notification sending
        channels = ["telegram", "slack", "email", "webhook"]
        notifications = _send_notifications(normalized, channels)

        assert len(notifications) == 4
        for channel in channels:
            assert channel in notifications
            assert notifications[channel]["status"] == "sent"
