from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/v1/health")

    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "URL Sentinel API"
    assert data["model_loaded"] is True


def test_scan_github_url():
    response = client.post(
        "/api/v1/scans",
        json={"url": "https://github.com"},
    )

    assert response.status_code == 200

    data = response.json()
    assert data["url"] == "https://github.com"
    assert data["classification"] in ("legitimate", "malicious")
    assert 0 <= data["risk_score"] <= 100
    assert "model_version" in data


def test_reject_unsupported_scheme():
    response = client.post(
        "/api/v1/scans",
        json={"url": "ftp://example.com"},
    )

    assert response.status_code in (400, 422)
