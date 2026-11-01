"""Transparent, configurable, multi-factor risk scoring."""
from sqlalchemy.orm import Session

from ..models import Asset, RiskAssessment, Setting, Threat, User, utcnow
from ..utils import clamp, risk_category

MODEL_VERSION = "aegis-risk-v1"
DEFAULT_WEIGHTS = {
    "severity": 0.25,
    "exploitability": 0.20,
    "exposure": 0.20,
    "asset_criticality": 0.20,
    "evidence_strength": 0.15,
}
DEFAULT_THRESHOLDS = {"medium": 25, "high": 50, "critical": 75}
FACTOR_LABELS = {
    "severity": "Vulnerability severity (CVSS-normalised)",
    "exploitability": "Exploitability evidence (EPSS / known-exploited)",
    "exposure": "External exposure of the asset",
    "asset_criticality": "Asset criticality",
    "evidence_strength": "Evidence strength and source reliability",
}
SEVERITY_FALLBACK = {"critical": 9.2, "high": 8.0, "medium": 5.5, "low": 2.5, "informational": 0.8}


def get_risk_config(db: Session) -> dict:
    row = db.get(Setting, "risk_weights")
    stored = row.value if row else {}
    weights = {**DEFAULT_WEIGHTS, **stored.get("weights", {})}
    thresholds = {**DEFAULT_THRESHOLDS, **stored.get("thresholds", {})}
    return {
        "weights": weights,
        "thresholds": thresholds,
        "model_version": MODEL_VERSION,
        "formula": "score = 10 × Σ(weightᵢ × factorᵢ), factors normalised 0–10",
        "notes": (
            "Prioritisation score. It is not a prediction of compromise and no component represents a "
            "probability of real-world attack. Exploitation status and evidence confidence are recorded separately."
        ),
    }


def save_risk_config(db: Session, weights: dict, thresholds: dict) -> dict:
    for key in DEFAULT_WEIGHTS:
        if key not in weights:
            raise ValueError(f"Missing weight: {key}")
    unknown = sorted(set(weights) - set(DEFAULT_WEIGHTS))
    if unknown:
        raise ValueError(f"Unknown weight key(s): {', '.join(unknown)}")
    try:
        weights = {key: float(weights[key]) for key in DEFAULT_WEIGHTS}
        thresholds = {key: float(thresholds[key]) for key in DEFAULT_THRESHOLDS}
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"Weights and thresholds must be numbers: {exc}") from exc
    if any(value < 0 for value in weights.values()):
        raise ValueError("Weights must be non-negative")
    total = sum(weights.values())
    if abs(total - 1.0) > 0.011:
        raise ValueError(f"Weights must sum to 1.0 (currently {total:.3f})")
    if not (0 < thresholds["medium"] < thresholds["high"] < thresholds["critical"] <= 100):
        raise ValueError("Thresholds must satisfy 0 < medium < high < critical ≤ 100")
    row = db.get(Setting, "risk_weights") or Setting(key="risk_weights")
    row.value = {"weights": weights, "thresholds": thresholds}
    row.updated_at = utcnow()
    db.add(row)
    db.commit()
    return get_risk_config(db)


def category_for(score: float, thresholds: dict | None = None) -> str:
    thresholds = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    if score >= thresholds["critical"]:
        return "Critical"
    if score >= thresholds["high"]:
        return "High"
    if score >= thresholds["medium"]:
        return "Medium"
    return "Low"


def _exploitability(threat: Threat) -> tuple[float, str]:
    if threat.known_exploited:
        return 10.0, "Listed as known exploited in the evidence set."
    if threat.epss_score is not None:
        value = clamp(float(threat.epss_score) * 10)
        return round(value, 2), f"EPSS probability {threat.epss_score * 100:.1f}%."
    # A supplied CVSS of 0.0 is real evidence of "not exploitable", not a missing value.
    cvss = threat.cvss_score if threat.cvss_score is not None else SEVERITY_FALLBACK.get(threat.severity, 4)
    value = clamp(cvss * 0.3, 0, 4)
    return round(value, 2), "No EPSS or known-exploited evidence; exploitability capped at 4/10."


def _exploitation_status(threat: Threat) -> str:
    if threat.known_exploited:
        return "confirmed-known-exploited"
    if threat.epss_score is not None and threat.epss_score >= 0.5:
        return "likely"
    if threat.epss_score is not None and threat.epss_score >= 0.1:
        return "possible"
    return "not-confirmed"


def _evidence(threat: Threat) -> tuple[float, list[str]]:
    notes = [f"Source reliability {threat.source_reliability}/100."]
    base = (threat.source_reliability / 100) * 7
    indicator_count = len(threat.indicators or [])
    indicator_bonus = min(2.0, indicator_count * 0.4)
    if indicator_count:
        notes.append(f"{indicator_count} structured indicator(s) supplied.")
    kev_bonus = 1.0 if threat.known_exploited else 0.0
    if kev_bonus:
        notes.append("Known-exploited evidence present.")
    if not threat.indicators:
        notes.append("No structured indicators; evidence limited to source text.")
    return clamp(round(base + indicator_bonus + kev_bonus, 2)), notes


def compute_components(threat: Threat, asset=None, match_confidence: float | None = None) -> dict:
    severity = clamp(threat.cvss_score if threat.cvss_score is not None else SEVERITY_FALLBACK.get(threat.severity, 4.0))
    exploitability, exploit_note = _exploitability(threat)
    if asset is not None:
        if asset.exposure == "internet-facing" or getattr(asset, "internet_facing", False):
            exposure, exposure_note = 9.5, f"Asset {asset.ref} is internet-facing."
        elif asset.exposure == "air-gapped":
            exposure, exposure_note = 1.5, f"Asset {asset.ref} is reported air-gapped."
        else:
            exposure, exposure_note = 5.0, f"Asset {asset.ref} is internal-only."
        criticality = clamp((asset.criticality or 3) * 2)
        criticality_note = f"Asset criticality {asset.criticality}/5 ({asset.business_importance})."
    else:
        exposure, exposure_note = 5.0, "No asset linked; exposure assumed mid-range and unverified."
        criticality, criticality_note = 5.0, "No asset linked; organisation-average criticality assumed."
    evidence, evidence_notes = _evidence(threat)
    if match_confidence is not None:
        evidence = clamp(evidence * 0.8 + (match_confidence / 100) * 2)
        evidence_notes.append(f"Asset match confidence {match_confidence:.0f}%.")
    return {
        "severity": {"value": round(severity, 2), "note": f"CVSS {threat.cvss_score:.1f}" if threat.cvss_score is not None else f"Severity fallback for {threat.severity}."},
        "exploitability": {"value": exploitability, "note": exploit_note},
        "exposure": {"value": exposure, "note": exposure_note},
        "asset_criticality": {"value": criticality, "note": criticality_note},
        "evidence_strength": {"value": evidence, "note": " ".join(evidence_notes)},
    }


def compute_score(components: dict, weights: dict) -> float:
    total = sum(weights[key] * components[key]["value"] for key in DEFAULT_WEIGHTS)
    return round(clamp(10 * total, 0, 100), 1)


def urgency_for(score: float, exploitation_status: str, exposure_value: float) -> str:
    if score >= 75 or (exploitation_status == "confirmed-known-exploited" and exposure_value >= 9):
        return "immediate"
    if score >= 50:
        return "elevated"
    if score >= 25:
        return "monitored"
    return "routine"


def assess(threat: Threat, asset=None, match_confidence: float | None = None, db: Session | None = None) -> dict:
    config = get_risk_config(db) if db else {"weights": DEFAULT_WEIGHTS, "thresholds": DEFAULT_THRESHOLDS}
    components = compute_components(threat, asset, match_confidence)
    score = compute_score(components, config["weights"])
    exploitation_status = _exploitation_status(threat)
    confidence = round(components["evidence_strength"]["value"] * 10)
    if match_confidence is not None:
        confidence = round(confidence * 0.8 + match_confidence * 0.2)
    factors = []
    # Iterate the canonical factor order so a hand-edited Setting row cannot key-error the API.
    for key in DEFAULT_WEIGHTS:
        weight = float(config["weights"].get(key, DEFAULT_WEIGHTS[key]))
        contribution = round(weight * components[key]["value"] * 10, 1)
        factors.append({
            "key": key,
            "label": FACTOR_LABELS[key],
            "normalized": components[key]["value"],
            "weight": weight,
            "contribution": contribution,
            "note": components[key]["note"],
        })
    category = category_for(score, config["thresholds"])
    top = sorted(factors, key=lambda f: f["contribution"], reverse=True)[:2]
    explanation = (
        f"Risk score {score:.1f}/100 ({category}). The largest contributors are "
        + " and ".join(f"{f['label'].lower()} ({f['contribution']:.1f} pts)" for f in top)
        + ". Severity, exploitation evidence, exposure, asset criticality and evidence strength are scored "
        "independently. This is a prioritisation score, not a probability that the asset is compromised. "
        f"Exploitation status: {exploitation_status.replace('-', ' ')}."
    )
    asset_note = (
        f"No asset is linked: exposure and criticality are assumptions, so the score carries lower evidence "
        f"confidence ({confidence}%) and should be validated against inventory."
        if asset is None else f"Scored against asset {asset.ref} ({asset.name})."
    )
    return {
        "risk_score": score,
        "risk_category": category,
        "urgency": urgency_for(score, exploitation_status, components["exposure"]["value"]),
        "exploitation_status": exploitation_status,
        "evidence_confidence": confidence,
        "components": components,
        "factors": factors,
        "explanation": f"{explanation} {asset_note}",
        "model_version": MODEL_VERSION,
        "weights": config["weights"],
        "thresholds": config["thresholds"],
    }


def apply_to_threat(threat: Threat, db: Session | None = None) -> dict:
    result = assess(threat, None, None, db)
    threat.risk_score = result["risk_score"]
    threat.risk_category = result["risk_category"]
    threat.urgency = result["urgency"]
    threat.exploitation_status = result["exploitation_status"]
    threat.confidence = result["evidence_confidence"]
    return result


def next_ref(db: Session, prefix: str) -> str:
    # Derived from the highest stored suffix, not COUNT(*): a deleted assessment must not
    # hand out a ref that already exists, because ref is UNIQUE.
    year = utcnow().year
    pattern = f"{prefix}-{year}-"
    highest = 0
    for (existing,) in db.query(RiskAssessment.ref).filter(RiskAssessment.ref.like(f"{pattern}%")).all():
        suffix = existing[len(pattern):]
        if suffix.isdigit():
            highest = max(highest, int(suffix))
    return f"{pattern}{max(highest, 1000) + 1:05d}"


def persist_assessment(db: Session, threat: Threat, asset=None, match_confidence: float | None = None,
                       user: User | None = None, vulnerability_id: int | None = None) -> RiskAssessment:
    result = assess(threat, asset, match_confidence, db)
    record = RiskAssessment(
        ref=next_ref(db, "RA"),
        threat_id=threat.id,
        vulnerability_id=vulnerability_id or None,
        asset_id=asset.id if asset else None,
        severity=result["components"]["severity"]["value"],
        exploitability=result["components"]["exploitability"]["value"],
        exposure=result["components"]["exposure"]["value"],
        asset_criticality=result["components"]["asset_criticality"]["value"],
        evidence_strength=result["components"]["evidence_strength"]["value"],
        risk_score=result["risk_score"],
        risk_category=result["risk_category"],
        urgency=result["urgency"],
        exploitation_status=result["exploitation_status"],
        evidence_confidence=result["evidence_confidence"],
        factors=result["factors"],
        explanation=result["explanation"],
        model_version=MODEL_VERSION,
        created_by=user.id if user else None,
        created_at=utcnow(),
    )
    db.add(record)
    db.flush()
    return record


def recompute_all(db: Session, user: User | None = None) -> dict:
    threats = db.query(Threat).all()
    categories = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for threat in threats:
        result = apply_to_threat(threat, db)
        categories[result["risk_category"]] += 1
    # Refresh stored assessment factor contributions against the new weights.
    assessments = db.query(RiskAssessment).all()
    for record in assessments:
        threat = db.get(Threat, record.threat_id) if record.threat_id else None
        if not threat:
            continue
        asset = db.get(Asset, record.asset_id) if record.asset_id else None
        result = assess(threat, asset, None, db)
        record.severity = result["components"]["severity"]["value"]
        record.exploitability = result["components"]["exploitability"]["value"]
        record.exposure = result["components"]["exposure"]["value"]
        record.asset_criticality = result["components"]["asset_criticality"]["value"]
        record.evidence_strength = result["components"]["evidence_strength"]["value"]
        record.risk_score = result["risk_score"]
        record.risk_category = result["risk_category"]
        record.urgency = result["urgency"]
        record.exploitation_status = result["exploitation_status"]
        record.evidence_confidence = result["evidence_confidence"]
        record.factors = result["factors"]
        record.explanation = result["explanation"]
    db.commit()
    return {"threats_updated": len(threats), "assessments_updated": len(assessments), "distribution": categories}
