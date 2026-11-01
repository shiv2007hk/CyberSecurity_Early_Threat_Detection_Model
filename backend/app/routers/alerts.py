"""Early-warning alert management, investigation workflow and detection runs."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import audit, get_current_user, require_role
from ..models import (
    Alert,
    AnalystNote,
    Asset,
    Recommendation,
    Threat,
    User,
    Vulnerability,
    utcnow,
)
from ..schemas import AlertUpdate, NoteCreate
from ..serializers import alert_out, note_out, recommendation_out, threat_out, vuln_out
from ..services import early_warning
from ..utils import csv_response_bytes
from .common import ensure_range, paginate, serialize_facets, split_multi

router = APIRouter(prefix="/alerts", tags=["Early Warning"])

RULE_DESCRIPTIONS = [
    {
        "key": "kev-exposure",
        "name": "Known-exploited exposure",
        "logic": "A vulnerability in the known-exploited evidence set has a version-validated match to registered inventory.",
        "severity": "high / critical when internet-facing with CVSS ≥ 9",
    },
    {
        "key": "multi-source-cve",
        "name": "Multi-source corroboration",
        "logic": "Two or more distinct intelligence sources report the same CVE inside the observation window.",
        "severity": "high when composite risk ≥ 70, otherwise medium",
    },
    {
        "key": "repeated-indicator",
        "name": "Repeated indicator",
        "logic": "The same IP, domain, URL or hash appears across two or more independent reports.",
        "severity": "high when composite risk ≥ 65, otherwise medium",
    },
    {
        "key": "velocity-technology",
        "name": "Technology velocity spike",
        "logic": "Report volume for an affected technology exceeds 2.2× the rolling baseline rate inside the window.",
        "severity": "high when composite risk ≥ 70, otherwise medium",
    },
    {
        "key": "velocity-category",
        "name": "Category velocity spike",
        "logic": "Report volume for a threat category exceeds 2.2× the rolling baseline rate inside the window.",
        "severity": "high when composite risk ≥ 70, otherwise medium",
    },
    {
        "key": "critical-asset-exposure",
        "name": "Critical asset intersection",
        "logic": "A critical-severity record has a validated version match with an asset rated 4–5 on business criticality.",
        "severity": "high",
    },
]

STATUS_FLOW = {
    "new": {"acknowledged", "investigating", "dismissed", "resolved"},
    "acknowledged": {"investigating", "resolved", "dismissed", "new"},
    "investigating": {"resolved", "dismissed", "acknowledged"},
    "resolved": {"new"},
    "dismissed": {"new"},
}


def _filtered(db, q, severity, status, rule, assigned_to, range_key, start, end):
    start_dt, end_dt = ensure_range(range_key, start, end)
    query = db.query(Alert).filter(Alert.detected_at >= start_dt, Alert.detected_at <= end_dt)
    if q:
        pattern = f"%{q.strip()}%"
        query = query.filter(or_(
            Alert.title.ilike(pattern), Alert.ref.ilike(pattern), Alert.trigger_reason.ilike(pattern),
            Alert.category.ilike(pattern), Alert.source.ilike(pattern),
        ))
    severities = split_multi(severity)
    if severities:
        query = query.filter(Alert.severity.in_(severities))
    statuses = split_multi(status)
    if statuses:
        query = query.filter(Alert.status.in_(statuses))
    rules = split_multi(rule)
    if rules:
        query = query.filter(Alert.rule_key.in_(rules))
    if assigned_to:
        query = query.filter(Alert.assignee_id == assigned_to)
    return query, start_dt, end_dt


@router.get("")
def list_alerts(
    q: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    rule: str | None = None,
    assigned_to: int | None = None,
    range_key: str = Query("30d", alias="range"),
    start: str | None = Query(None, alias="from"),
    end: str | None = None,
    sort_by: str = "detected_at",
    order: str = "desc",
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query, start_dt, end_dt = _filtered(db, q, severity, status, rule, assigned_to, range_key, start, end)
    sort_map = {
        "detected_at": Alert.detected_at,
        "risk_score": Alert.risk_score,
        "severity": Alert.severity,
        "status": Alert.status,
    }
    column = sort_map.get(sort_by, Alert.detected_at)
    query = query.order_by(column.asc() if order == "asc" else column.desc())
    result = paginate(query, page, size, lambda a: alert_out(a))
    in_range = db.query(Alert).filter(Alert.detected_at >= start_dt, Alert.detected_at <= end_dt).all()
    active = {"new", "acknowledged", "investigating"}
    result["facets"] = {
        "severities": serialize_facets(in_range, "severity"),
        "statuses": serialize_facets(in_range, "status"),
        "rules": serialize_facets(in_range, "rule_key"),
    }
    result["stats"] = {
        "total": len(in_range),
        "active": sum(1 for a in in_range if a.status in active),
        "critical_active": sum(1 for a in in_range if a.status in active and a.severity == "critical"),
        "unassigned_active": sum(1 for a in in_range if a.status in active and not a.assignee_id),
        "resolved": sum(1 for a in in_range if a.status == "resolved"),
    }
    return result


@router.get("/rules")
def alert_rules(user: User = Depends(get_current_user)):
    return {
        "rules": RULE_DESCRIPTIONS,
        "engine": {
            "window_hours": 36,
            "baseline_days": 14,
            "max_new_alerts_per_run": early_warning.MAX_NEW_ALERTS,
            "duplicate_suppression_days": 7,
            "note": "Rules produce evidence-backed observations, not attack predictions. Detection is deterministic and reproducible.",
        },
    }


@router.get("/summary")
def alert_summary(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    alerts = db.query(Alert).all()
    active = [a for a in alerts if a.status in {"new", "acknowledged", "investigating"}]
    latest = max((a.detected_at for a in alerts), default=None)
    return {
        "total": len(alerts),
        "active": len(active),
        "critical": sum(1 for a in active if a.severity == "critical"),
        "high": sum(1 for a in active if a.severity == "high"),
        "unassigned": sum(1 for a in active if not a.assignee_id),
        "latest_at": latest.isoformat() if latest else None,
        "by_severity": [
            {"name": sev.title(), "value": sum(1 for a in active if a.severity == sev)}
            for sev in ["critical", "high", "medium", "low", "informational"]
        ],
        "recent": [alert_out(a) for a in sorted(alerts, key=lambda a: a.detected_at, reverse=True)[:6]],
    }


@router.get("/export.csv")
def export_alerts(
    q: str | None = None, severity: str | None = None, status: str | None = None,
    rule: str | None = None, assigned_to: int | None = None,
    range_key: str = Query("30d", alias="range"), start: str | None = Query(None, alias="from"), end: str | None = None,
    db: Session = Depends(get_db), user: User = Depends(get_current_user),
):
    query, _, _ = _filtered(db, q, severity, status, rule, assigned_to, range_key, start, end)
    headers = ["ref", "title", "severity", "category", "status", "detected_at", "source", "risk_score",
               "confidence", "rule", "trigger_reason", "recommended_action"]
    rows = [[a.ref, a.title, a.severity, a.category, a.status, a.detected_at.isoformat(), a.source,
             a.risk_score, a.confidence, a.rule_key, a.trigger_reason, a.recommended_action]
            for a in query.order_by(Alert.detected_at.desc()).limit(5000).all()]
    return StreamingResponse(
        iter([csv_response_bytes(headers, rows)]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="cyberguard-alerts-{utcnow().date()}.csv"'},
    )


@router.post("/scan")
def run_detection(
    request: Request,
    window_hours: int = Query(36, ge=2, le=168),
    baseline_days: int = Query(14, ge=2, le=90),
    db: Session = Depends(get_db),
    user: User = Depends(require_role("analyst")),
):
    result = early_warning.detect(db, window_hours=window_hours, baseline_days=baseline_days, user_id=user.id)
    audit(db, request, user, "alerts.scan", "alert", "", f"Created {result['alerts_created']} alert(s) across five rules")
    db.commit()
    return result


def _resolve(db: Session, identifier: str) -> Alert:
    alert = db.query(Alert).filter(Alert.ref == identifier.upper()).first()
    if not alert and identifier.isdigit():
        alert = db.get(Alert, int(identifier))
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.get("/{identifier}")
def alert_detail(identifier: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    alert = _resolve(db, identifier)
    threat = db.get(Threat, alert.threat_id) if alert.threat_id else None
    vuln = db.get(Vulnerability, alert.vulnerability_id) if alert.vulnerability_id else None
    assets = [db.get(Asset, asset_id) for asset_id in (alert.asset_ids or [])]
    assets = [asset for asset in assets if asset]
    notes = db.query(AnalystNote).filter(AnalystNote.alert_id == alert.id).order_by(AnalystNote.created_at.desc()).all()
    recommendations = db.query(Recommendation).filter(Recommendation.alert_id == alert.id).all()
    assignee = db.get(User, alert.assignee_id) if alert.assignee_id else None
    return {
        "alert": alert_out(alert, detailed=True),
        "threat": threat_out(threat) if threat else None,
        "vulnerability": vuln_out(vuln) if vuln else None,
        "assets": [
            {"id": a.id, "ref": a.ref, "name": a.name, "category": a.category, "criticality": a.criticality,
             "exposure": a.exposure, "software": a.software, "software_version": a.software_version}
            for a in assets
        ],
        "assignee": {"id": assignee.id, "full_name": assignee.full_name, "email": assignee.email} if assignee else None,
        "notes": [note_out(note, db.get(User, note.user_id)) for note in notes],
        "recommendations": [recommendation_out(r) for r in recommendations],
        "rule": next((r for r in RULE_DESCRIPTIONS if r["key"] == alert.rule_key), None),
        "timeline": [
            {"at": alert.detected_at.isoformat(), "label": "Detected by rule engine"},
            *([{"at": alert.acknowledged_at.isoformat(), "label": "Acknowledged"}] if alert.acknowledged_at else []),
            *([{"at": alert.resolved_at.isoformat(), "label": "Resolved"}] if alert.resolved_at else []),
        ],
    }


@router.patch("/{identifier}")
def update_alert(identifier: str, payload: AlertUpdate, request: Request,
                 db: Session = Depends(get_db), user: User = Depends(require_role("analyst"))):
    alert = _resolve(db, identifier)
    changed = []
    fields = payload.model_fields_set
    if payload.status is not None and payload.status != alert.status:
        allowed = STATUS_FLOW.get(alert.status, set())
        if payload.status not in allowed:
            raise HTTPException(status_code=422, detail=f"Cannot move alert from {alert.status} to {payload.status}")
        alert.status = payload.status
        if payload.status in {"acknowledged", "investigating"} and not alert.acknowledged_at:
            alert.acknowledged_at = utcnow()
        if payload.status == "resolved":
            alert.resolved_at = utcnow()
            if not alert.acknowledged_at:
                alert.acknowledged_at = utcnow()
        if payload.status == "new":
            alert.resolved_at = None
            alert.acknowledged_at = None
        changed.append(f"status={payload.status}")
    if "assignee_id" in fields:
        if payload.assignee_id is None:
            alert.assignee_id = None
            changed.append("assignee=unassigned")
        else:
            assignee = db.get(User, payload.assignee_id)
            if not assignee or not assignee.is_active:
                raise HTTPException(status_code=422, detail="Assignee not found or inactive")
            alert.assignee_id = assignee.id
            changed.append(f"assignee={assignee.email}")
    audit(db, request, user, "alert.updated", "alert", alert.ref, ", ".join(changed) or "no changes")
    db.commit()
    return {"alert": alert_out(alert, detailed=True), "message": "Alert updated"}


@router.get("/{identifier}/notes")
def list_notes(identifier: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    alert = _resolve(db, identifier)
    notes = db.query(AnalystNote).filter(AnalystNote.alert_id == alert.id).order_by(AnalystNote.created_at.desc()).all()
    return {"items": [note_out(note, db.get(User, note.user_id)) for note in notes]}


@router.post("/{identifier}/notes", status_code=201)
def add_note(identifier: str, payload: NoteCreate, request: Request,
             db: Session = Depends(get_db), user: User = Depends(require_role("analyst"))):
    alert = _resolve(db, identifier)
    note = AnalystNote(user_id=user.id, alert_id=alert.id, body=payload.body, created_at=utcnow())
    db.add(note)
    audit(db, request, user, "alert.note.added", "alert", alert.ref, payload.body[:300])
    db.commit()
    return note_out(note, user)
