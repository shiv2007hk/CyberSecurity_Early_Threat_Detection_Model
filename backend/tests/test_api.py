"""API contract, provenance, RBAC and workflow tests."""
from app.database import SessionLocal
from app.models import Alert, AssetVulnerability, Vulnerability


def test_health_and_public_overview_are_public(client):
    health = client.get("/api/system/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    overview = client.get("/api/public/overview")
    assert overview.status_code == 200
    payload = overview.json()
    assert payload["platform"] == "CyberGuard AI"
    assert "data_mode" not in payload and "disclaimer" not in payload
    assert payload["metrics"]["threat_records"] > 0


def test_authentication_required_and_invalid_credentials(client):
    assert client.get("/api/dashboard").status_code == 401
    assert client.get("/api/admin/users").status_code == 401
    bad = client.post("/api/auth/login", json={"email": "admin@aegissentinel.ai", "password": "wrong-password"})
    assert bad.status_code == 401
    me = client.get("/api/auth/me", headers={"Authorization": "Bearer not-a-token"})
    assert me.status_code == 401


def test_dashboard_and_intelligence_contract(client, admin_headers):
    dashboard = client.get("/api/dashboard?range=7d", headers=admin_headers)
    assert dashboard.status_code == 200
    data = dashboard.json()
    assert data["kpis"]["total_threats"] > 0
    assert isinstance(data["threat_series"], list)
    assert data["summary"]
    assert "stored records" in data["summary_disclaimer"].lower()

    threats = client.get("/api/threats?range=90d&size=5", headers=admin_headers)
    assert threats.status_code == 200
    body = threats.json()
    assert body["total"] > 0 and len(body["items"]) <= 5
    assert all(item["source"] and item["published_at"] for item in body["items"])

    vulnerabilities = client.get("/api/vulnerabilities?range=90d&size=5", headers=admin_headers)
    assert vulnerabilities.status_code == 200
    assert vulnerabilities.json()["total"] > 0


def test_analytics_reports_and_search(client, admin_headers):
    analytics = client.get("/api/analytics?range=30d", headers=admin_headers)
    assert analytics.status_code == 200
    data = analytics.json()
    assert data["severity_distribution"]
    assert data["heatmap"]["rows"]
    assert "not verified" in data["geo_note"].lower() or "not verified attacker" in data["geo_note"].lower()

    report = client.get("/api/reports/weekly?range=7d", headers=admin_headers)
    assert report.status_code == 200
    report_data = report.json()
    assert report_data["sections"]
    assert "stored" in report_data["classification"].lower()

    search = client.get("/api/search?q=apache", headers=admin_headers)
    assert search.status_code == 200
    assert search.json()["total"] > 0


def test_exports_are_csv(client, admin_headers):
    for url in ["/api/threats/export.csv", "/api/vulnerabilities/export.csv", "/api/alerts/export.csv",
                "/api/reports/critical/export.csv", "/api/admin/audit/export.csv"]:
        response = client.get(url, headers=admin_headers)
        assert response.status_code == 200, url
        assert response.headers["content-type"].startswith("text/csv")
        assert response.content


def test_rbac_blocks_viewers_and_analysts(client, viewer_headers, analyst_headers):
    assert client.post("/api/alerts/scan", headers=viewer_headers).status_code == 403
    assert client.post("/api/exposure/scan", headers=viewer_headers).status_code == 403
    assert client.get("/api/admin/users", headers=analyst_headers).status_code == 403
    assert client.post("/api/admin/classifier-quality/run", headers=viewer_headers).status_code == 403


def test_alert_and_recommendation_workflow(client, analyst_headers, admin_headers):
    alerts = client.get("/api/alerts?size=1", headers=admin_headers).json()["items"]
    assert alerts
    ref = alerts[0]["ref"]
    detail = client.get(f"/api/alerts/{ref}", headers=admin_headers)
    assert detail.status_code == 200
    assert "timeline" in detail.json()
    if alerts[0]["status"] == "new":
        updated = client.patch(f"/api/alerts/{ref}", json={"status": "acknowledged"}, headers=analyst_headers)
        assert updated.status_code == 200
        assert updated.json()["alert"]["acknowledged_at"]
    note = client.post(f"/api/alerts/{ref}/notes", json={"body": "Verified source and asset context."},
                       headers=analyst_headers)
    assert note.status_code == 201

    recs = client.get("/api/recommendations?size=1", headers=admin_headers).json()["items"]
    assert recs
    rec_ref = recs[0]["ref"]
    rec_update = client.patch(f"/api/recommendations/{rec_ref}",
                              json={"status": "in_progress", "due_in_days": 5}, headers=analyst_headers)
    assert rec_update.status_code == 200


def test_sources_never_expose_secrets(client, admin_headers):
    response = client.get("/api/sources", headers=admin_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["secret_policy"]
    text = response.text.lower()
    assert "sk-" not in text
    assert "bearer " not in text
    for source in body["items"]:
        assert "key_configured" in source


def test_scenario_non_affected_does_not_claim_exposure(client, analyst_headers):
    response = client.post("/api/scenarios/non-affected-asset/run", headers=analyst_headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["scenario"] == "non-affected-asset"
    db = SessionLocal()
    try:
        vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == "CVE-2026-50992").first()
        assert vuln is not None
        assert db.query(AssetVulnerability).filter(AssetVulnerability.vulnerability_id == vuln.id).count() == 0
    finally:
        db.close()


def test_offline_live_sync_fails_explicitly(client, analyst_headers):
    response = client.post("/api/sources/nvd/sync", headers=analyst_headers)
    assert response.status_code == 503
    assert "Nothing was written" in response.json()["detail"]


def test_security_headers(client):
    response = client.get("/api/system/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
