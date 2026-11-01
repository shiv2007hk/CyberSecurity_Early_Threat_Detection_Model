"""Unit tests for the deterministic engines."""
from app.database import SessionLocal
from app.models import Asset, Threat, Vulnerability
from app.security import create_access_token, decode_access_token, hash_password, password_problems, verify_password
from app.services import classifier, correlation, early_warning, exposure, risk
from app.utils import severity_from_cvss, version_in_range


def test_classifier_categories_and_entities():
    ransomware = classifier.classify("LockGrid ransomware encrypts files and demands payment via Tor.")
    assert ransomware["category"] == "Ransomware"
    assert 0 <= ransomware["confidence"] <= 1
    phishing = classifier.classify("Credential phishing email impersonates the payroll portal and steals passwords.")
    assert phishing["category"] == "Phishing"
    text = "CVE-2026-48211 affects 10.20.30.40 and evil-cdn-secure.com over https://evil-cdn-secure.com/a"
    entities = classifier.extract_entities(text)
    assert "CVE-2026-48211" in entities["cve"]
    assert "10.20.30.40" in entities["ipv4"]
    assert "evil-cdn-secure.com" in entities["domain"]


def test_classifier_evaluation_is_bounded_and_honest():
    evaluation = classifier.evaluate()
    assert 20 <= evaluation["samples"] <= 60
    assert 0 <= evaluation["macro_f1"] <= 1
    assert "benchmark" in evaluation["dataset_name"].lower()
    assert "not generalise" in evaluation["notes"]


def test_version_and_severity_helpers():
    assert version_in_range("2.4.53", "2.4.49", "2.4.55")
    assert not version_in_range("2.4.58", "2.4.49", "2.4.55")
    assert version_in_range("8.5.2", "8.5.0", "8.5.3")
    assert not version_in_range("8.5.4", "8.5.0", "8.5.3")
    assert severity_from_cvss(9.8) == "critical"
    assert severity_from_cvss(7.1) == "high"
    assert severity_from_cvss(None) == "unknown"


def test_risk_score_math_and_bands():
    components = {
        "severity": {"value": 10.0},
        "exploitability": {"value": 10.0},
        "exposure": {"value": 10.0},
        "asset_criticality": {"value": 10.0},
        "evidence_strength": {"value": 10.0},
    }
    score = risk.compute_score(components, risk.DEFAULT_WEIGHTS)
    assert 99 <= score <= 100
    assert risk.category_for(20) == "Low"
    assert risk.category_for(30) == "Medium"
    assert risk.category_for(60) == "High"
    assert risk.category_for(80) == "Critical"


def test_exposure_requires_validated_product_and_version():
    db = SessionLocal()
    try:
        vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == "CVE-2026-48211").first()
        assert vuln is not None
        matched = db.query(Asset).filter(Asset.software == "Apache HTTP Server").all()
        assert matched
        results = [exposure.match_vulnerability(vuln, asset) for asset in matched]
        assert any(item and item["validated"] for item in results)
        absent = exposure.match_vulnerability(vuln, Asset(
            ref="TEST-1", name="Unrelated", category="Server", software="SAP NetWeaver",
            software_version="7.5", exposure="internal", criticality=3, internet_facing=False,
        ))
        assert absent is None
    finally:
        db.close()


def test_risk_assessment_is_explainable_and_separates_exploitation():
    db = SessionLocal()
    try:
        threat = db.query(Threat).filter(Threat.cve_id == "CVE-2026-48211").first()
        assert threat is not None
        result = risk.assess(threat, None, None, db)
        assert 0 <= result["risk_score"] <= 100
        assert len(result["factors"]) == 5
        assert "exploitation_status" in result
        assert "evidence_confidence" in result
        assert result["explanation"]
        assert abs(sum(risk.get_risk_config(db)["weights"].values()) - 1.0) < 0.01
    finally:
        db.close()


def test_correlation_graph_and_fingerprint():
    db = SessionLocal()
    try:
        graph = correlation.graph(db, days=120)
        assert "nodes" in graph and "edges" in graph
        assert all("id" in node for node in graph["nodes"])
    finally:
        db.close()
    first = early_warning.fingerprint("kev-exposure", "CVE-2026-48211")
    assert first == early_warning.fingerprint("kev-exposure", "CVE-2026-48211")
    assert first != early_warning.fingerprint("multi-source-cve", "CVE-2026-48211")


def test_password_hashing_and_jwt():
    stored = hash_password("Strong#Passw0rd")
    assert stored.startswith("pbkdf2_sha256$")
    assert verify_password("Strong#Passw0rd", stored)
    assert not verify_password("Wrong#Passw0rd", stored)
    assert password_problems("short")
    assert password_problems("alllowercase123") != []
    assert password_problems("Strong#Passw0rd") == []
    token, expires_in = create_access_token(1, "user@example.com", "analyst")
    payload = decode_access_token(token)
    assert payload and payload["role"] == "analyst" and payload["sub"] == "1"
    assert expires_in > 0
