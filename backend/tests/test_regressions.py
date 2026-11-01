"""Regression tests for defects fixed during the model/backend audit.

Each test pins one real failure mode that was reproduced before the fix, so a
reintroduction fails the suite rather than the running app.
"""
import pytest
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import RiskAssessment, Threat
from app.services import analytics, classifier, risk
from app.utils import utcnow


# --- risk engine ------------------------------------------------------------

def test_cvss_zero_is_evidence_not_a_missing_value():
    """A supplied CVSS of 0.0 must score as 0 exploitability, not fall back to severity."""
    threat = Threat(name="x", description="x", category="Software Vulnerability",
                    severity="critical", cvss_score=0.0)
    value, note = risk._exploitability(threat)
    assert value == 0.0
    assert "EPSS" in note


def test_save_risk_config_rejects_unknown_and_non_numeric_weights():
    weights = dict(risk.DEFAULT_WEIGHTS)
    thresholds = dict(risk.DEFAULT_THRESHOLDS)
    with SessionLocal() as db:
        with pytest.raises(ValueError, match="Unknown weight key"):
            risk.save_risk_config(db, {**weights, "bogus": 0.0}, thresholds)
        with pytest.raises(ValueError, match="must be numbers"):
            risk.save_risk_config(db, {**weights, "severity": "high"}, thresholds)
        with pytest.raises(ValueError, match="non-negative"):
            risk.save_risk_config(db, {**weights, "severity": -0.5}, thresholds)


def test_next_ref_advances_past_the_highest_stored_suffix(client):
    """ref is UNIQUE, so a deleted-then-recreated row must not reuse a live ref."""
    with SessionLocal() as db:
        try:
            first = risk.next_ref(db, "RG")
            prefix, suffix = first.rsplit("-", 1)
            db.add(RiskAssessment(ref=first, threat_id=None, risk_score=1.0,
                                  risk_category="Low", created_at=utcnow()))
            db.flush()
            second = risk.next_ref(db, "RG")
            assert second != first
            assert int(second.rsplit("-", 1)[1]) == int(suffix) + 1
        finally:
            db.rollback()


# --- analytics --------------------------------------------------------------

def test_anomaly_baseline_is_withheld_when_history_is_empty(client, analyst_headers):
    """A window with no preceding records must not report a fabricated z-score."""
    response = client.get("/api/analytics?from=2027-01-01&end=2027-01-08",
                          headers=analyst_headers)
    assert response.status_code == 200, response.text
    series = response.json()["anomaly_series"]
    assert series, "expected a series for the requested window"
    for point in series:
        assert point["baseline_ready"] is False
        assert point["z"] is None
        assert point["flagged"] is False
        assert "withheld" in point["baseline_status"].lower()


# --- classifier -------------------------------------------------------------

def test_classifier_reports_an_external_hint_as_such():
    result = classifier.classify("A remote code execution flaw was patched.",
                                 hint="Remote Code Execution")
    assert result["method"] == classifier.METHOD
    assert "external hint: Remote Code Execution" in result["evidence_terms"]["Remote Code Execution"]


def test_evaluate_allocates_a_row_for_out_of_scheme_predictions():
    evaluation = classifier.evaluate()
    assert classifier.OTHER in evaluation["per_category"]
    for row in evaluation["confusion"].values():
        assert classifier.OTHER in row
    assert evaluation["model_name"].startswith("aegis-nlp-lexicon-v1")
    assert "not a trained model" in evaluation["notes"]


def test_seeded_records_label_the_method_as_its_real_technique(client, analyst_headers):
    response = client.get("/api/threats?limit=5", headers=analyst_headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    items = payload["items"] if isinstance(payload, dict) else payload
    assert items, "expected seeded threat records"
    assert all(item["ai_method"] == classifier.METHOD for item in items)
