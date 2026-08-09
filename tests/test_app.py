import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-pytest-only")

from app import create_app


@pytest.fixture()
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_index_loads(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"AI CyberShield" in response.data


def test_health_endpoint(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_check_password_requires_field(client):
    response = client.post("/api/check-password", json={})
    assert response.status_code == 400


def test_check_password_success(client):
    response = client.post("/api/check-password", json={"password": "Xk9#mQ2!ExtraLong"})
    assert response.status_code == 200
    data = response.get_json()
    assert "score" in data


def test_check_password_rejects_oversized_input(client):
    response = client.post("/api/check-password", json={"password": "a" * 500})
    assert response.status_code == 400


def test_check_phishing_requires_field(client):
    response = client.post("/api/check-phishing", json={})
    assert response.status_code == 400


def test_check_phishing_success(client):
    response = client.post("/api/check-phishing", json={"url": "https://example.com"})
    assert response.status_code == 200
    assert response.get_json()["risk_level"] == "Low Risk \u2705"


def test_scan_file_json_mode(client):
    response = client.post("/api/scan-file", json={"file": "invoice.pdf.exe"})
    assert response.status_code == 200
    assert response.get_json()["risk_score"] >= 5


def test_scan_file_upload_mode(client):
    data = {"file": (io.BytesIO(b"MZ\x90\x00fakecontent"), "note.txt")}
    response = client.post("/api/scan-file", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    body = response.get_json()
    assert any("mismatch" in i.lower() for i in body["indicators"])


def test_scan_file_requires_input(client):
    response = client.post("/api/scan-file", json={})
    assert response.status_code == 400


def test_security_tips_endpoint(client):
    response = client.get("/api/security-tips")
    assert response.status_code == 200
    assert len(response.get_json()["tips"]) == 15


def test_generate_report_with_no_data(client):
    response = client.post("/api/generate-report", json={})
    assert response.status_code == 200
    assert response.get_json()["overall_security_score"] is None


def test_generate_report_aggregates_real_scores(client):
    pw = client.post("/api/check-password", json={"password": "password"}).get_json()
    response = client.post("/api/generate-report", json={"password_result": pw})
    data = response.get_json()
    assert data["overall_security_score"] is not None
    assert data["components_analyzed"] == 1


def test_404_returns_json(client):
    response = client.get("/api/does-not-exist")
    assert response.status_code == 404
    assert response.get_json()["error"] == "Resource not found"


def test_security_headers_present(client):
    response = client.get("/")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"


def test_rate_limit_engages(client):
    last_status = None
    for _ in range(35):
        last_status = client.post("/api/check-password", json={"password": "Test1234!"}).status_code
    assert last_status == 429
  
