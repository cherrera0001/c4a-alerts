"""
Unit tests for Pydantic schemas.
"""


import pytest

from c4aalerts.app.schemas.alert import (
    IOC,
    AlertResponse,
    AlertSeverity,
    IOCType,
    NormalizedAlert,
)


def test_alert_severity_enum():
    """Test AlertSeverity enum values."""
    assert AlertSeverity.LOW == "low"
    assert AlertSeverity.MEDIUM == "medium"
    assert AlertSeverity.HIGH == "high"
    assert AlertSeverity.CRITICAL == "critical"

def test_ioc_type_enum():
    """Test IOCType enum values."""
    assert IOCType.IP_ADDRESS == "ip_address"
    assert IOCType.DOMAIN == "domain"
    assert IOCType.URL == "url"
    assert IOCType.EMAIL == "email"
    assert IOCType.HASH == "hash"
    assert IOCType.CVE == "cve"

def test_ioc_model():
    """Test IOC model creation and validation."""
    ioc = IOC(
        value="192.168.1.1",
        type=IOCType.IP_ADDRESS,
        confidence=0.8,
        tags=["malicious", "botnet"],
        metadata={"source": "threat_intel"}
    )

    assert ioc.value == "192.168.1.1"
    assert ioc.type == IOCType.IP_ADDRESS
    assert ioc.confidence == 0.8
    assert ioc.tags == ["malicious", "botnet"]
    assert ioc.metadata["source"] == "threat_intel"

def test_normalized_alert_model():
    """Test NormalizedAlert model creation and validation."""
    alert = NormalizedAlert(
        uid="test_alert_123",
        source="test_source",
        title="Test Alert",
        description="Test description",
        severity=AlertSeverity.HIGH,
        content_hash="test123456789",
        iocs=[
            IOC(value="192.168.1.1", type=IOCType.IP_ADDRESS),
            IOC(value="malicious.com", type=IOCType.DOMAIN)
        ],
        cve_id="CVE-2024-0001",
        cvss_score=8.5,
        epss_score=0.75,
        tags=["test", "security"],
        references=["https://example.com"],
        confidence=0.8
    )

    assert alert.uid == "test_alert_123"
    assert alert.source == "test_source"
    assert alert.title == "Test Alert"
    assert alert.severity == AlertSeverity.HIGH
    assert len(alert.iocs) == 2
    assert alert.cve_id == "CVE-2024-0001"
    assert alert.cvss_score == 8.5
    assert alert.epss_score == 0.75
    assert alert.confidence == 0.8

def test_normalized_alert_content_hash_validation():
    """Test content hash validation."""
    # Should raise error for short hash
    with pytest.raises(ValueError, match="Content hash must be at least 8 characters long"):
        NormalizedAlert(
            uid="test",
            source="test",
            title="Test",
            content_hash="short"
        )

    # Should work with valid hash
    alert = NormalizedAlert(
        uid="test",
        source="test",
        title="Test",
        content_hash="valid_hash_123"
    )
    assert alert.content_hash == "valid_hash_123"

def test_alert_response_model():
    """Test AlertResponse model."""
    alert = NormalizedAlert(
        uid="test_alert",
        source="test",
        title="Test Alert",
        content_hash="test123456789"
    )

    response = AlertResponse(
        status="success",
        message="Alert processed successfully",
        alert=alert
    )

    assert response.status == "success"
    assert response.message == "Alert processed successfully"
    assert response.alert == alert
    assert "timestamp" in response.dict()
