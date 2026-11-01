"""Advanced analytics aggregations, correlation graph and data exports."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import audit, get_current_user, require_role
from ..models import Alert, Threat, User, Vulnerability, utcnow
from ..services import analytics, correlation
from ..utils import csv_response_bytes
from .common import ensure_range

router = APIRouter(prefix="/analytics", tags=["Analytics"])


def _range(range_key: str | None, start: str | None, end: str | None):
    if range_key == "all":
        range_key = "90d"
    start_dt, end_dt = ensure_range(range_key, start, end)
    if (end_dt - start_dt).days > 366:
        raise HTTPException(status_code=422, detail="Analytics windows are limited to 366 days")
    return start_dt, end_dt


@router.get("")
def analytics_overview(
    range_key: str = Query("30d", alias="range"),
    start: str | None = Query(None, alias="from"),
    end: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    source: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    start_dt, end_dt = _range(range_key, start, end)
    data = analytics.build(db, start_dt, end_dt, {
        "severity": severity, "category": category, "source": source,
    })
    return data


@router.get("/correlation")
def correlation_graph(
    days: int = Query(90, ge=7, le=365),
    min_score: float = Query(0.45, ge=0, le=1),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return correlation.graph(db, days=days, min_score=min_score)


@router.post("/correlation/rebuild")
def rebuild_correlations(
    request: Request,
    days: int = Query(180, ge=7, le=365),
    db: Session = Depends(get_db),
    user: User = Depends(require_role("analyst")),
):
    result = correlation.build(db, days=days)
    audit(db, request, user, "correlation.rebuilt", "threat_correlation", "", str(result))
    db.commit()
    return {"result": result, "graph": correlation.graph(db, days=days)}


@router.get("/export.csv")
def export_dataset(
    dataset: str = Query("threats", pattern="^(threats|vulnerabilities|alerts)$"),
    range_key: str = Query("90d", alias="range"),
    start: str | None = Query(None, alias="from"),
    end: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    start_dt, end_dt = _range(range_key, start, end)
    if dataset == "threats":
        records = db.query(Threat).filter(
            Threat.published_at >= start_dt, Threat.published_at <= end_dt
        ).order_by(Threat.risk_score.desc()).limit(10000).all()
        headers = ["ref", "name", "category", "severity", "source", "cve", "cvss", "epss", "known_exploited",
                   "risk_score", "risk_category", "evidence_confidence", "exploitation_status", "published_at"]
        rows = [[t.ref, t.name, t.category, t.severity, t.source, t.cve_id, t.cvss_score, t.epss_score,
                 t.known_exploited, t.risk_score, t.risk_category, t.confidence, t.exploitation_status,
                 t.published_at.isoformat()] for t in records]
    elif dataset == "vulnerabilities":
        records = db.query(Vulnerability).filter(
            Vulnerability.published_at >= start_dt, Vulnerability.published_at <= end_dt
        ).order_by(Vulnerability.published_at.desc()).limit(10000).all()
        headers = ["cve", "title", "cvss", "severity", "epss", "known_exploited", "published_at", "source"]
        rows = [[v.cve_id, v.title, v.cvss_score, v.cvss_severity, v.epss_score, v.known_exploited,
                 v.published_at.isoformat(), v.source] for v in records]
    else:
        records = db.query(Alert).filter(
            Alert.detected_at >= start_dt, Alert.detected_at <= end_dt
        ).order_by(Alert.detected_at.desc()).limit(10000).all()
        headers = ["ref", "title", "severity", "status", "category", "detected_at", "risk_score", "confidence",
                   "rule", "source"]
        rows = [[a.ref, a.title, a.severity, a.status, a.category, a.detected_at.isoformat(), a.risk_score,
                 a.confidence, a.rule_key, a.source] for a in records]
    return StreamingResponse(
        iter([csv_response_bytes(headers, rows)]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="cyberguard-{dataset}-{utcnow().date()}.csv"'},
    )
