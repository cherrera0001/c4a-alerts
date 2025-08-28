"""
Unit tests for health endpoints.
"""

from fastapi.testclient import TestClient

from c4aalerts.app.api.main import app

client = TestClient(app)

def test_health_check():
    """Test basic health check endpoint."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "healthy"
    assert "timestamp" in data
    assert data["version"] == "2.0.0"

def test_detailed_health_check():
    """Test detailed health check endpoint."""
    response = client.get("/api/v1/health/detailed")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "healthy"
    assert "timestamp" in data
    assert data["version"] == "2.0.0"
    assert "services" in data

    services = data["services"]
    assert services["api"] == "healthy"
    assert services["database"] == "healthy"
    assert services["redis"] == "healthy"
    assert services["workers"] == "healthy"

def test_root_endpoint():
    """Test root endpoint."""
    response = client.get("/")
    assert response.status_code == 200

    data = response.json()
    assert data["message"] == "C4A Alerts API"
    assert data["version"] == "2.0.0"
    assert data["status"] == "running"
