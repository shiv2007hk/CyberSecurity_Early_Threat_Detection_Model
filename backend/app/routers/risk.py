"""Explainable risk-scoring configuration, assessments and analyst feedback."""
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import audit, get_current_user, require_role
from ..models import Asset, RiskAssessment, Setting, Threat, User, Vulnerability, utcnow
from ..schemas import RiskAssessRequest, RiskConfigUpdate, RiskFeedback
from ..serializers import assessment_out
from ..services import risk
from .common import ensure_range, paginate

router = APIRouter(prefix="/risk", tags=["Risk Assessment"])


@router.get("/config")
def risk_config(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    config = risk.get_risk_config(db)
    config["factors"] = [
        {"key": key, "label": label, "weight": config["weights"][key], "direction": "higher score increases risk"}
        for key, label in risk.FACTOR_LABELS.items()
    ]
    config["bands"] = [
        {"name": "Critical", "min": config["thresholds"]["critical"], "max": 100, "colour": "#FF334F"},
        {"name": "High", "min": config["thresholds"]["high"], "max": config["thresholds"]["critical"], "colour": "#FF703B"},
        {"name": "Medium", "min": config["thresholds"]["medium"], "max": config["thresholds"]["high"], "colour": "#F5B942"},
        {"name": "Low", "min": 0, "max": config["thresholds"]["medium"], "colour": "#20C997"},
    ]
    return config


@router.put("/config")
def update_risk_config(payload: RiskConfigUpdate, request: Request, db: Session = Depends(get_db),
                       user: User = Depends(require_role("admin"))):
    try:
        config = risk.save_risk_config(db, payload.weights.model_dump(), payload.thresholds.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    audit(db, request, user, "risk.config.updated", "setting", "risk_weights",
          f"weights={config['weights']} thresholds={config['thresholds']}")
    db.commit()
    result = risk.recompute_all(db, user)
    audit(db, request, user, "risk.recomputed", "risk_assessment", "", str(result["threats_updated"]) + " threats rescored")
    db.commit()
    return {"config": config, "recompute": result, "message": "Weights saved and existing records rescored."}


@router.get("/summary")
def risk_summary(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    assessments = db.query(RiskAssessment).all()
    threats = db.query(Threat).all()
    config = risk.get_risk_config(db)
    bands = Counter(a.risk_category for a in assessments)
    threat_bands = Counter(t.risk_category for t in threats)
    avg_components = {}
    for key in risk.DEFAULT_WEIGHTS:
        values = [getattr(a, key) or 0 for a in assessments]
        avg_components[key] = round(sum(values) / len(values), 2) if values else 0
    exploitation = Counter(a.exploitation_status for a in assessments)
    return {
        "assessments": len(assessments),
        "threats_scored": len(threats),
        "average_score": round(sum(a.risk_score or 0 for a in assessments) / len(assessments), 1) if assessments else 0,
        "distribution": [
            {"name": name, "value": bands.get(name, 0)} for name in ["Critical", "High", "Medium", "Low"]
        ],
        "threat_distribution": [
            {"name": name, "value": threat_bands.get(name, 0)} for name in ["Critical", "High", "Medium", "Low"]
        ],
        "average_components": avg_components,
        "exploitation_status": [{"name": name.replace("_", " ").title(), "value": count} for name, count in exploitation.most_common()],
        "config": config,
        "disclaimer": (
            "Scores are prioritisation aids. High risk does not imply confirmed exploitation, and no score "
            "represents a probability of a real-world attack."
        ),
    }


@router.get("/assessments")
def list_assessments(
    category: str | None = None,
    asset: int | None = None,
    threat: int | None = None,
    range_key: str = Query("90d", alias="range"),
    start: str | None = Query(None, alias="from"),
    end: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    start_dt, end_dt = ensure_range(range_key, start, end)
    query = db.query(RiskAssessment).filter(
        RiskAssessment.created_at >= start_dt, RiskAssessment.created_at <= end_dt
    )
    if category:
        query = query.filter(RiskAssessment.risk_category == category)
    if asset:
        query = query.filter(RiskAssessment.asset_id == asset)
    if threat:
        query = query.filter(RiskAssessment.threat_id == threat)
    query = query.order_by(RiskAssessment.risk_score.desc(), RiskAssessment.created_at.desc())
    result = paginate(
        query, page, size,
        lambda record: assessment_out(
            record,
            db.get(Threat, record.threat_id) if record.threat_id else None,
            db.get(Asset, record.asset_id) if record.asset_id else None,
            db.get(Vulnerability, record.vulnerability_id) if record.vulnerability_id else None,
        ),
    )
    in_range = db.query(RiskAssessment).filter(
        RiskAssessment.created_at >= start_dt, RiskAssessment.created_at <= end_dt
    ).all()
    counts = Counter(a.risk_category for a in in_range)
    result["facets"] = [
        {"name": name, "count": counts.get(name, 0)} for name in ["Critical", "High", "Medium", "Low"]
    ]
    return result


@router.get("/assessments/{assessment_id}")
def assessment_detail(assessment_id: int, db: Session = Depends(get_db),
                      user: User = Depends(get_current_user)):
    record = db.get(RiskAssessment, assessment_id)
    if not record:
        raise HTTPException(status_code=404, detail="Assessment not found")
    threat = db.get(Threat, record.threat_id) if record.threat_id else None
    asset = db.get(Asset, record.asset_id) if record.asset_id else None
    vuln = db.get(Vulnerability, record.vulnerability_id) if record.vulnerability_id else None
    result = assessment_out(record, threat, asset, vuln)
    result["evidence"] = {
        "severity": {"source": "CVSS score or mapped threat severity", "value": record.severity},
        "exploitability": {"source": "Known-exploited evidence and EPSS probability", "value": record.exploitability},
        "exposure": {"source": "Asset internet exposure", "value": record.exposure},
        "asset_criticality": {"source": "Operator-assigned business criticality", "value": record.asset_criticality},
        "evidence_strength": {"source": "Source reliability and corroboration", "value": record.evidence_strength},
        "exploitation_status": record.exploitation_status,
        "evidence_confidence": record.evidence_confidence,
    }
    result["limitations"] = [
        "Factor inputs are normalised heuristics; changing weights changes the ranking.",
        "Evidence confidence describes data quality, not attack likelihood.",
        "The assessment applies only to the linked asset, or to a generic asset profile when no asset is linked.",
    ]
    return result


@router.post("/assess")
def create_assessment(payload: RiskAssessRequest, request: Request, db: Session = Depends(get_db),
                      user: User = Depends(require_role("analyst"))):
    threat = db.get(Threat, payload.threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    asset = db.get(Asset, payload.asset_id) if payload.asset_id else None
    if payload.asset_id and not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == threat.cve_id).first() if threat.cve_id else None
    record = risk.persist_assessment(db, threat, asset, user=user, vulnerability_id=vuln.id if vuln else None)
    audit(db, request, user, "risk.assessment.created", "risk_assessment", record.ref,
          f"Threat {threat.ref}, asset {asset.ref if asset else 'generic'}, score {record.risk_score}")
    db.commit()
    return {
        "assessment": assessment_out(record, threat, asset, vuln),
        "breakdown": risk.assess(threat, asset, None, db),
    }


@router.post("/recompute")
def recompute_risk(request: Request, db: Session = Depends(get_db),
                   user: User = Depends(require_role("admin"))):
    result = risk.recompute_all(db, user)
    audit(db, request, user, "risk.recomputed", "risk_assessment", "",
          f"{result['threats_updated']} threats and {result['assessments_updated']} assessments rescored")
    db.commit()
    return result


@router.get("/feedback")
def list_feedback(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    row = db.get(Setting, "risk_feedback")
    items = (row.value if row and isinstance(row.value, list) else [])[-100:]
    return {"items": list(reversed(items)), "count": len(items)}


@router.post("/feedback", status_code=201)
def submit_feedback(payload: RiskFeedback, request: Request, db: Session = Depends(get_db),
                    user: User = Depends(require_role("analyst"))):
    record = db.get(RiskAssessment, payload.assessment_id)
    if not record:
        raise HTTPException(status_code=404, detail="Assessment not found")
    row = db.get(Setting, "risk_feedback") or Setting(key="risk_feedback")
    items = list(row.value) if isinstance(row.value, list) else []
    entry = {
        "assessment_id": record.id,
        "assessment_ref": record.ref,
        "score": record.risk_score,
        "verdict": payload.verdict,
        "note": payload.note,
        "user": user.email,
        "created_at": utcnow().isoformat(),
    }
    items.append(entry)
    row.value = items[-500:]
    row.updated_at = utcnow()
    db.add(row)
    audit(db, request, user, "risk.feedback", "risk_assessment", record.ref, f"{payload.verdict}: {payload.note[:300]}")
    db.commit()
    return {"feedback": entry, "message": "Feedback recorded. Scores are only changed by an administrator through the model configuration."}
