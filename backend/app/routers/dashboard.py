"""Command-centre dashboard aggregate endpoint."""
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import Recommendation, ThreatSource, User, Vulnerability
from ..serializers import source_out, threat_out, vuln_out
from ..services import analytics
from ..utils import parse_range
from .common import ensure_range

router = APIRouter(prefix="/dashboard", tags=["Command Centre"])


@router.get("")
def dashboard(
    range_key: str = Query("7d", alias="range"),
    start: str | None = Query(None, alias="from"),
    end: str | None = Query(None),
    severity: str | None = None,
    category: str | None = None,
    source: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if range_key == "all":
        range_key = "90d"
    start_dt, end_dt = ensure_range(range_key, start, end)
    data = analytics.build(db, start_dt, end_dt, {"severity": severity, "category": category, "source": source})
    latest_vulns = (
        db.query(Vulnerability)
        .filter(Vulnerability.published_at >= start_dt, Vulnerability.published_at <= end_dt)
        .order_by(Vulnerability.published_at.desc())
        .limit(5)
        .all()
    )
    recommendations = (
        db.query(Recommendation)
        .filter(Recommendation.status.in_(["open", "in_progress"]))
        .order_by(Recommendation.created_at.desc())
        .limit(5)
        .all()
    )
    sources = db.query(ThreatSource).all()
    return {
        "range": data["range"],
        "generated_at": data["generated_at"],
        "kpis": data["kpis"],
        "deltas": data["deltas"],
        "summary": data["summary"],
        "summary_disclaimer": data["summary_disclaimer"],
        "data_quality": data["data_quality"],
        "threat_series": data["threat_series"],
        "vuln_series": data["vuln_series"],
        "alert_series": data["alert_series"],
        "risk_series": data["risk_series"],
        "severity_distribution": data["severity_distribution"],
        "category_distribution": data["category_distribution"],
        "classification_distribution": data["classification_distribution"],
        "source_distribution": data["source_distribution"],
        "top_technologies": data["top_technologies"],
        "top_assets": data["top_assets"],
        "risk_distribution": data["risk_distribution"],
        "recent_alerts": data["recent_alerts"],
        "critical_recent": data["critical_recent"],
        "source_status": [source_out(s) for s in sources],
        "active_alert_severity": data["active_alert_severity"],
        "total_sources": len(sources),
        "latest_vulnerabilities": [vuln_out(v) for v in latest_vulns],
        "open_recommendations": [
            {"id": r.id, "ref": r.ref, "title": r.title, "priority": r.priority, "status": r.status, "due_at": r.due_at.isoformat() if r.due_at else None}
            for r in recommendations
        ],
        "geo_activity": data["geo_activity"],
        "geo_note": data["geo_note"],
        "assessment_count": data["assessment_count"],
        "correlation_stats": data["correlation_stats"],
    }
