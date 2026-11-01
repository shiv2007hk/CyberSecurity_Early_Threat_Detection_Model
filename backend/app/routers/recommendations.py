"""Actionable remediation recommendations and workflow."""
from collections import Counter
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import audit, get_current_user, require_role
from ..models import Alert, Asset, Recommendation, Threat, User, Vulnerability, utcnow
from ..schemas import RecommendationUpdate
from ..serializers import recommendation_out
from ..utils import csv_response_bytes
from .common import paginate, serialize_facets, split_multi

router = APIRouter(prefix="/recommendations", tags=["Recommendations"])


def _filtered(db, q, priority, status, asset_id, range_key, start, end):
    from .common import ensure_range
    start_dt, end_dt = ensure_range(range_key or "90d", start, end)
    query = db.query(Recommendation).filter(
        Recommendation.created_at >= start_dt, Recommendation.created_at <= end_dt
    )
    if q:
        pattern = f"%{q.strip()}%"
        query = query.filter(or_(
            Recommendation.title.ilike(pattern), Recommendation.action.ilike(pattern),
            Recommendation.reason.ilike(pattern), Recommendation.ref.ilike(pattern),
        ))
    priorities = split_multi(priority)
    if priorities:
        query = query.filter(Recommendation.priority.in_(priorities))
    statuses = split_multi(status)
    if statuses:
        query = query.filter(Recommendation.status.in_(statuses))
    if asset_id:
        query = query.filter(Recommendation.asset_id == asset_id)
    return query


def _enrich(db: Session, rec: Recommendation) -> dict:
    data = recommendation_out(rec)
    asset = db.get(Asset, rec.asset_id) if rec.asset_id else None
    threat = db.get(Threat, rec.threat_id) if rec.threat_id else None
    vuln = db.get(Vulnerability, rec.vulnerability_id) if rec.vulnerability_id else None
    alert = db.get(Alert, rec.alert_id) if rec.alert_id else None
    owner = db.get(User, rec.owner_id) if rec.owner_id else None
    data["asset"] = {"ref": asset.ref, "name": asset.name, "category": asset.category} if asset else None
    data["threat"] = {"ref": threat.ref, "name": threat.name, "severity": threat.severity} if threat else None
    data["vulnerability"] = {"cve_id": vuln.cve_id, "title": vuln.title, "cvss": vuln.cvss_score} if vuln else None
    data["alert"] = {"ref": alert.ref, "title": alert.title, "severity": alert.severity} if alert else None
    data["owner"] = {"id": owner.id, "full_name": owner.full_name} if owner else None
    return data


@router.get("")
def list_recommendations(
    q: str | None = None,
    priority: str | None = None,
    status: str | None = None,
    asset_id: int | None = Query(None, alias="asset"),
    range_key: str = Query("90d", alias="range"),
    start: str | None = Query(None, alias="from"),
    end: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = _filtered(db, q, priority, status, asset_id, range_key, start, end)
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_items = query.all()
    all_items.sort(key=lambda r: (
        priority_order.get(r.priority, 9),
        r.due_at or datetime.max,
        -r.created_at.timestamp(),
    ))
    start_index = (page - 1) * size
    page_items = all_items[start_index:start_index + size]
    counts = Counter(r.status for r in all_items)
    priority_counts = Counter(r.priority for r in all_items)
    overdue = [r for r in all_items if r.due_at and r.due_at < utcnow() and r.status not in {"done", "dismissed"}]
    return {
        "items": [_enrich(db, r) for r in page_items],
        "total": len(all_items),
        "page": page,
        "size": size,
        "pages": max(1, -(-len(all_items) // size)) if all_items else 0,
        "facets": {
            "priorities": [{"name": name, "count": priority_counts.get(name, 0)} for name in ["critical", "high", "medium", "low"]],
            "statuses": serialize_facets(all_items, "status"),
        },
        "stats": {
            "open": counts.get("open", 0),
            "in_progress": counts.get("in_progress", 0),
            "done": counts.get("done", 0),
            "overdue": len(overdue),
            "critical_open": sum(1 for r in all_items if r.priority == "critical" and r.status in {"open", "in_progress"}),
        },
        "note": "Recommendations are defensive and non-disruptive. No response action is executed automatically.",
    }


@router.get("/summary")
def recommendation_summary(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    recs = db.query(Recommendation).all()
    by_priority = Counter(r.priority for r in recs if r.status in {"open", "in_progress"})
    by_status = Counter(r.status for r in recs)
    return {
        "total": len(recs),
        "open": by_status.get("open", 0),
        "in_progress": by_status.get("in_progress", 0),
        "done": by_status.get("done", 0),
        "active_by_priority": [{"name": name.title(), "value": by_priority.get(name, 0)} for name in ["critical", "high", "medium", "low"]],
        "status_distribution": [{"name": key.replace("_", " ").title(), "value": value} for key, value in by_status.most_common()],
    }


@router.get("/export.csv")
def export_recommendations(
    q: str | None = None, priority: str | None = None, status: str | None = None,
    asset_id: int | None = Query(None, alias="asset"),
    range_key: str = Query("90d", alias="range"), start: str | None = Query(None, alias="from"),
    end: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user),
):
    query = _filtered(db, q, priority, status, asset_id, range_key, start, end)
    headers = ["ref", "title", "priority", "status", "action", "reason", "threat_ref", "cve", "asset_ref",
               "owner", "due_at", "source_url", "created_at"]
    rows = []
    for rec in query.order_by(Recommendation.created_at.desc()).limit(5000).all():
        asset = db.get(Asset, rec.asset_id) if rec.asset_id else None
        threat = db.get(Threat, rec.threat_id) if rec.threat_id else None
        vuln = db.get(Vulnerability, rec.vulnerability_id) if rec.vulnerability_id else None
        owner = db.get(User, rec.owner_id) if rec.owner_id else None
        rows.append([rec.ref, rec.title, rec.priority, rec.status, rec.action, rec.reason,
                     threat.ref if threat else "", vuln.cve_id if vuln else "", asset.ref if asset else "",
                     owner.full_name if owner else "", rec.due_at.isoformat() if rec.due_at else "",
                     rec.source_url, rec.created_at.isoformat()])
    return StreamingResponse(
        iter([csv_response_bytes(headers, rows)]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="cyberguard-recommendations-{utcnow().date()}.csv"'},
    )


def _resolve(db: Session, identifier: str) -> Recommendation:
    rec = db.query(Recommendation).filter(Recommendation.ref == identifier.upper()).first()
    if not rec and identifier.isdigit():
        rec = db.get(Recommendation, int(identifier))
    if not rec:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    return rec


@router.get("/{identifier}")
def recommendation_detail(identifier: str, db: Session = Depends(get_db),
                          user: User = Depends(get_current_user)):
    rec = _resolve(db, identifier)
    data = _enrich(db, rec)
    data["evidence"] = rec.evidence or []
    data["methodology"] = (
        "Recommendations are generated from validated exposure matches, known-exploited evidence and alert triggers. "
        "Actions are advisory only; containment and blocking require human approval through approved processes."
    )
    return data


@router.patch("/{identifier}")
def update_recommendation(identifier: str, payload: RecommendationUpdate, request: Request,
                          db: Session = Depends(get_db), user: User = Depends(require_role("analyst"))):
    rec = _resolve(db, identifier)
    changes = []
    fields = payload.model_fields_set
    if payload.status is not None:
        rec.status = payload.status
        changes.append(f"status={payload.status}")
    if "owner_id" in fields:
        if payload.owner_id is None:
            rec.owner_id = None
            changes.append("owner=unassigned")
        else:
            owner = db.get(User, payload.owner_id)
            if not owner or not owner.is_active:
                raise HTTPException(status_code=422, detail="Owner not found or inactive")
            rec.owner_id = owner.id
            changes.append(f"owner={owner.email}")
    if payload.due_in_days is not None:
        rec.due_at = utcnow() + timedelta(days=payload.due_in_days)
        changes.append(f"due_at={rec.due_at.date().isoformat()}")
    audit(db, request, user, "recommendation.updated", "recommendation", rec.ref, ", ".join(changes) or "no changes")
    db.commit()
    return {"recommendation": _enrich(db, rec), "message": "Recommendation updated"}
