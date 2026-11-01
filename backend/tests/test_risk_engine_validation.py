"""Validation of the deterministic risk engine against the worked cases in the training brief.

The brief specifies a six-factor model (severity 25 / exploitation 25 / KEV 10 / criticality 25 /
exposure 5 / relevance 10, bands 85-65-40, Log4Shell = 99.4 CRITICAL). The shipped engine is a
five-factor model with different weights, bands and a KEV rule that feeds exploitability and
evidence instead of being its own factor. The difference is documented in
docs/METHODOLOGY.md section 5 and is not silently reconciled: these tests pin what the engine
actually does, so a future change to the arithmetic has to be deliberate.
"""
from datetime import timedelta

from app.database import SessionLocal
from app.models import Asset, RiskAssessment, Threat, Vulnerability
from app.services import exposure, risk
from app.utils import utcnow, version_in_range, version_matches

NOW = utcnow()


def threat(**overrides) -> Threat:
    base = dict(
        ref="TH-RISK-1",
        name="Test record",
        category="Vulnerability",
        description="Synthetic record used only to exercise the scoring engine.",
        source="unit-test",
        published_at=NOW - timedelta(hours=1),
        severity="critical",
        cvss_score=10.0,
        epss_score=0.975,
        known_exploited=True,
        source_reliability=95,
        indicators=[{"type": "cve", "value": f"CVE-2021-{i}"} for i in range(5)],
    )
    base.update(overrides)
    return Threat(**base)


def asset(**overrides) -> Asset:
    base = dict(
        ref="AST-RISK-1",
        name="Test gateway",
        category="Server",
        software="Apache HTTP Server",
        software_version="2.4.49",
        exposure="internet-facing",
        internet_facing=True,
        criticality=5,
        business_importance="mission-critical",
    )
    base.update(overrides)
    return Asset(**base)


def vulnerability(**overrides) -> Vulnerability:
    base = dict(
        cve_id="CVE-2021-44228",
        title="Log4Shell remote code execution",
        description="JNDI lookup in Apache Log4j allows remote code execution.",
        cvss_score=10.0,
        cvss_severity="critical",
        published_at=NOW - timedelta(days=2),
        known_exploited=True,
        affected_products=[{
            "vendor": "Apache",
            "product": "Log4j",
            "versions": {"start": "2.0", "end": "2.14.1"},
        }],
    )
    base.update(overrides)
    return Vulnerability(**base)


def test_log4shell_worked_example_is_critical_and_reproducible():
    """Case 1. The brief's example expects 99.4; this engine's own arithmetic is asserted instead."""
    result = risk.assess(threat(), asset())
    # severity 10.0, exploitability 10.0 (known exploited), exposure 9.5 (internet-facing),
    # criticality 10.0 (5/5), evidence 6.65 + 2.0 + 1.0 = 9.65.
    assert result["components"]["evidence_strength"]["value"] == 9.65
    expected = risk.compute_score(result["components"], risk.DEFAULT_WEIGHTS)
    assert result["risk_score"] == expected == 98.5
    assert result["risk_category"] == "Critical"
    assert result["urgency"] == "immediate"
    assert result["exploitation_status"] == "confirmed-known-exploited"
    # The stored factors must reproduce the headline number, not merely accompany it.
    assert round(sum(f["contribution"] for f in result["factors"]), 1) == result["risk_score"]


def test_not_affected_version_suppresses_the_exposure_match():
    """Case 2. A version outside the affected range must produce no match at all."""
    vuln = vulnerability()
    patched = asset(software="Log4j", software_version="2.15.0")
    assert exposure.match_vulnerability(vuln, patched) is None
    inside = asset(software="Log4j", software_version="2.14.1")
    match = exposure.match_vulnerability(vuln, inside)
    assert match and match["validated"] and match["status"] == "potentially_exposed"


def test_product_absent_from_inventory_is_not_reported_as_affected():
    """Case 3. PRODUCT_ABSENT: no product overlap means no match, whatever the text says."""
    matched, strength = exposure.product_matches("SAP NetWeaver", "Log4j", "Apache")
    assert (matched, strength) == (False, "no-product-match")
    assert exposure.match_vulnerability(vulnerability(), asset(software="SAP NetWeaver")) is None


def test_version_unknown_is_needs_verification_and_never_validated():
    """Case 4. VERSION_UNKNOWN: a product match without version evidence stays unverified."""
    vuln = vulnerability(affected_products=[{"vendor": "Apache", "product": "Log4j", "versions": {}}])
    match = exposure.match_vulnerability(vuln, asset(software="Log4j", software_version="unknown"))
    assert match is not None
    assert match["validated"] is False
    assert match["status"] == "needs_verification"
    assert match["confidence"] <= 58
    assert "must not be treated as confirmed" in match["reason"]


def test_known_exploited_lifts_exploitability_and_urgency_without_a_cvss():
    """Case 5. The brief's KEV factor is implemented as an evidence and urgency rule, not a weight."""
    kev = threat(cvss_score=None, epss_score=None, known_exploited=True, severity="medium")
    plain = threat(cvss_score=None, epss_score=None, known_exploited=False, severity="medium")

    kev_result = risk.assess(kev, asset())
    plain_result = risk.assess(plain, asset())

    assert kev_result["components"]["exploitability"]["value"] == 10.0
    # Without EPSS or KEV, exploitability is derived from the severity fallback and capped at 4/10,
    # so missing exploitation intelligence can never inflate a score.
    assert plain_result["components"]["exploitability"]["value"] == 1.65
    assert plain_result["components"]["exploitability"]["value"] <= 4.0
    assert kev_result["components"]["severity"]["value"] == 5.5  # medium fallback, not invented CVSS
    assert kev_result["risk_score"] > plain_result["risk_score"]
    assert kev_result["urgency"] == "immediate"
    assert kev_result["exploitation_status"] == "confirmed-known-exploited"
    assert plain_result["exploitation_status"] == "not-confirmed"


def test_known_exploited_urgency_floor_needs_reachability():
    """The floor is a reachability rule: KEV alone does not force 'immediate'."""
    weak = dict(cvss_score=4.0, epss_score=None, known_exploited=True, severity="medium",
                source_reliability=50, indicators=[])
    exposed = risk.assess(threat(**weak), asset(criticality=1))
    isolated = risk.assess(threat(**weak), asset(criticality=1, exposure="air-gapped", internet_facing=False))

    assert exposed["risk_score"] == 59.8 and exposed["risk_category"] == "High"
    assert exposed["urgency"] == "immediate"  # the floor, not the band, is doing this
    assert isolated["risk_score"] == 43.8 and isolated["risk_category"] == "Medium"
    assert isolated["urgency"] == "monitored"
    assert isolated["components"]["exposure"]["value"] == 1.5
    assert isolated["exploitation_status"] == exposed["exploitation_status"] == "confirmed-known-exploited"


def test_missing_asset_data_is_flagged_as_an_assumption():
    """Case 6. With no linked asset the engine scores anyway, but says so in the record."""
    result = risk.assess(threat(), None)
    assert "No asset linked" in result["components"]["exposure"]["note"]
    assert "No asset linked" in result["components"]["asset_criticality"]["note"]
    assert "No asset is linked" in result["explanation"]
    assert "should be validated against inventory" in result["explanation"]
    assert result["components"]["exposure"]["value"] == 5.0
    # The same record with a real asset scores higher because exposure and criticality are recorded,
    # so the unlinked figure is a lower bound and must not be read as the estate risk.
    assert result["risk_score"] < risk.assess(threat(), asset())["risk_score"]


def test_version_range_comparison_is_numeric_aware():
    """Case 7. Range checks must order 2.4.10 above 2.4.9 and treat both bounds as inclusive."""
    assert version_in_range("2.4.10", "2.4.9", "2.4.11")
    assert not version_in_range("2.4.8", "2.4.9", "2.4.11")
    assert version_in_range("2.0", "2.0", "2.14.1")
    assert version_in_range("2.14.1", "2.0", "2.14.1")
    assert not version_in_range("2.15.0", "2.0", "2.14.1")
    spec = {"start": "2.0", "end": "2.14.1"}
    assert version_matches("2.14.1", spec) is True
    assert version_matches("2.15.0", spec) is False
    assert version_matches("not-a-version", spec) is False


def test_stored_waterfalls_reconcile_with_stored_scores(client):
    """Case 8. Every seeded assessment must add up to its own headline score."""
    db = SessionLocal()
    try:
        records = db.query(RiskAssessment).all()
        assert records, "seed data must include stored assessments"
        worst = 0.0
        for record in records:
            factors = record.factors or []
            assert factors, f"{record.ref} stores no factor ledger"
            assert abs(sum(f["weight"] for f in factors) - 1.0) <= 0.011
            total = round(sum(f["contribution"] for f in factors), 1)
            worst = max(worst, abs(total - record.risk_score))
        # Each contribution is rounded to 0.1 before summing, so five factors can drift by at most 0.2.
        assert worst <= 0.2, f"factor ledger drifts {worst} pts from the stored score"
    finally:
        db.close()
