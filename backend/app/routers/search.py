"""Cross-entity global search for the command palette."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import Alert, Asset, Recommendation, Threat, User, Vulnerability
from ..serializers import iso

router = APIRouter(prefix="/search", tags=["Search"])


@router.get("")
def search(
    q: str = Query(min_length=2, max_length=120),
    limit: int = Query(5, ge=1, le=10),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    pattern = f"%{q.strip()}%"
    threats = (
        db.query(Threat)
        .filter(or_(Threat.name.ilike(pattern), Threat.ref.ilike(pattern), Threat.cve_id.ilike(pattern),
                    Threat.affected_technology.ilike(pattern), Threat.description.ilike(pattern)))
        .order_by(Threat.risk_score.desc()).limit(limit).all()
    )
    vulns = (
        db.query(Vulnerability)
        .filter(or_(Vulnerability.cve_id.ilike(pattern), Vulnerability.title.ilike(pattern),
                    Vulnerability.description.ilike(pattern)))
        .order_by(Vulnerability.cvss_score.desc()).limit(limit).all()
    )
    assets = (
        db.query(Asset)
        .filter(or_(Asset.name.ilike(pattern), Asset.ref.ilike(pattern), Asset.software.ilike(pattern),
                    Asset.identifier.ilike(pattern), Asset.owner.ilike(pattern)))
        .order_by(Asset.criticality.desc()).limit(limit).all()
    )
    alerts = (
        db.query(Alert)
        .filter(or_(Alert.title.ilike(pattern), Alert.ref.ilike(pattern), Alert.trigger_reason.ilike(pattern)))
        .order_by(Alert.detected_at.desc()).limit(limit).all()
    )
    recommendations = (
        db.query(Recommendation)
        .filter(or_(Recommendation.title.ilike(pattern), Recommendation.ref.ilike(pattern),
                    Recommendation.action.ilike(pattern)))
        .order_by(Recommendation.created_at.desc()).limit(limit).all()
    )
    results = {
        "threats": [
            {"kind": "threat", "ref": t.ref, "title": t.name, "subtitle": f"{t.severity} · {t.category} · risk {t.risk_score}",
             "route": f"/app/threats?focus={t.ref}", "badge": t.severity}
            for t in threats
        ],
        "vulnerabilities": [
            {"kind": "vulnerability", "ref": v.cve_id, "title": v.title, "subtitle": f"CVSS {v.cvss_score or 'n/a'} · {v.cvss_severity or 'unscored'}",
             "route": f"/app/vulnerabilities?focus={v.cve_id}", "badge": v.cvss_severity}
            for v in vulns
        ],
        "assets": [
            {"kind": "asset", "ref": a.ref, "title": a.name, "subtitle": f"{a.software} {a.software_version} · {a.category}",
             "route": f"/app/assets?focus={a.ref}", "badge": f"crit {a.criticality}/5"}
            for a in assets
        ],
        "alerts": [
            {"kind": "alert", "ref": a.ref, "title": a.title, "subtitle": f"{a.severity} · {a.status} · {iso(a.detected_at)}",
             "route": f"/app/alerts?focus={a.ref}", "badge": a.severity}
            for a in alerts
        ],
        "recommendations": [
            {"kind": "recommendation", "ref": r.ref, "title": r.title, "subtitle": f"{r.priority} · {r.status}",
             "route": f"/app/recommendations?focus={r.ref}", "badge": r.priority}
            for r in recommendations
        ],
    }
    total = sum(len(group) for group in results.values())
    return {"query": q, "results": results, "total": total}
