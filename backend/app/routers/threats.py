"""Threat intelligence list, detail, investigation, notes and export."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import case, func, or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import audit, get_current_user, require_role
from ..models import (
    Alert,
    AnalystNote,
    Asset,
    AssetVulnerability,
    Recommendation,
    RiskAssessment,
    Threat,
    ThreatCorrelation,
    User,
    Vulnerability,
    utcnow,
)
from ..schemas import NoteCreate, ThreatUpdate
from ..serializers import assessment_out, note_out, recommendation_out, threat_out
from ..services import risk
from ..utils import csv_response_bytes
from .common import ensure_range, paginate, serialize_facets, split_multi

router = APIRouter(prefix="/threats", tags=["Threat Intelligence"])


def _filtered_query(db: Session, q, severity, category, source, status, saved, assigned_to,
                    cve, range_key, start, end):
    start_dt, end_dt = ensure_range(range_key, start, end)
    query = db.query(Threat).filter(Threat.published_at >= start_dt, Threat.published_at <= end_dt)
    if q:
        pattern = f"%{q.strip()}%"
        query = query.filter(or_(
            Threat.name.ilike(pattern), Threat.description.ilike(pattern),
            Threat.cve_id.ilike(pattern), Threat.affected_technology.ilike(pattern),
            Threat.ref.ilike(pattern), Threat.source.ilike(pattern),
        ))
    severities = split_multi(severity)
    if severities:
        query = query.filter(Threat.severity.in_(severities))
    categories = split_multi(category)
    if categories:
        query = query.filter(Threat.category.in_(categories))
    sources = split_multi(source)
    if sources:
        query = query.filter(Threat.source.in_(sources))
    statuses = split_multi(status)
    if statuses:
        query = query.filter(Threat.status.in_(statuses))
    if saved is not None:
        query = query.filter(Threat.is_saved.is_(saved))
    if assigned_to:
        query = query.filter(Threat.assigned_to == assigned_to)
    if cve:
        query = query.filter(Threat.cve_id == cve.upper())
    return query


@router.get("")
def list_threats(
    q: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    source: str | None = None,
    status: str | None = None,
    saved: bool | None = None,
    assigned_to: int | None = None,
    cve: str | None = None,
    range_key: str = Query("90d", alias="range"),
    start: str | None = Query(None, alias="from"),
    end: str | None = None,
    sort_by: str = "risk_score",
    order: str = "desc",
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = _filtered_query(db, q, severity, category, source, status, saved, assigned_to, cve, range_key, start, end)
    severity_order = case(
        (Threat.severity == "critical", 0), (Threat.severity == "high", 1),
        (Threat.severity == "medium", 2), (Threat.severity == "low", 3), else_=4,
    )
    sort_map = {
        "risk_score": Threat.risk_score,
        "published_at": Threat.published_at,
        "cvss": Threat.cvss_score,
        "epss": Threat.epss_score,
        "severity": severity_order,
        "name": Threat.name,
    }
    column = sort_map.get(sort_by, Threat.risk_score)
    query = query.order_by(column.asc() if order == "asc" else column.desc())
    result = paginate(query, page, size, lambda t: threat_out(t))
    range_start, range_end = ensure_range(range_key, start, end)
    facet_rows = (
        db.query(Threat)
        .filter(Threat.published_at >= range_start, Threat.published_at <= range_end)
        .all()
    )
    result["facets"] = {
        "severities": serialize_facets(facet_rows, "severity"),
        "categories": serialize_facets(facet_rows, "category"),
        "sources": serialize_facets(facet_rows, "source"),
        "statuses": serialize_facets(facet_rows, "status"),
    }
    result["analyst_count"] = db.query(func.count(User.id)).filter(User.role == "analyst", User.is_active.is_(True)).scalar()
    return result


@router.get("/export.csv")
def export_threats(
    q: str | None = None, severity: str | None = None, category: str | None = None,
    source: str | None = None, status: str | None = None, saved: bool | None = None,
    assigned_to: int | None = None, cve: str | None = None,
    range_key: str = Query("90d", alias="range"), start: str | None = Query(None, alias="from"), end: str | None = None,
    db: Session = Depends(get_db), user: User = Depends(get_current_user),
):
    query = _filtered_query(db, q, severity, category, source, status, saved, assigned_to, cve, range_key, start, end)
    threats = query.order_by(Threat.risk_score.desc()).limit(5000).all()
    headers = ["ref", "name", "category", "severity", "source", "cve_id", "cvss", "epss", "known_exploited",
               "risk_score", "risk_category", "evidence_confidence", "exploitation_status", "status", "published_at",
               "source_url"]
    rows = [[t.ref, t.name, t.category, t.severity, t.source, t.cve_id, t.cvss_score, t.epss_score,
             t.known_exploited, t.risk_score, t.risk_category, t.confidence, t.exploitation_status, t.status,
             t.published_at.isoformat(), t.source_url] for t in threats]
    return StreamingResponse(
        iter([csv_response_bytes(headers, rows)]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="cyberguard-threats-{utcnow().date()}.csv"'},
    )


def _resolve_threat(db: Session, identifier: str) -> Threat:
    threat = db.query(Threat).filter(Threat.ref == identifier.upper()).first()
    if not threat and identifier.isdigit():
        threat = db.get(Threat, int(identifier))
    if not threat:
        raise HTTPException(status_code=404, detail="Threat record not found")
    return threat


@router.get("/{identifier}")
def threat_detail(identifier: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    threat = _resolve_threat(db, identifier)
    notes = db.query(AnalystNote).filter(AnalystNote.threat_id == threat.id).order_by(AnalystNote.created_at.desc()).all()
    authors = {note.user_id: db.get(User, note.user_id) for note in notes}
    recommendations = db.query(Recommendation).filter(Recommendation.threat_id == threat.id).all()
    pairs = db.query(ThreatCorrelation).filter(
        or_(ThreatCorrelation.threat_a_id == threat.id, ThreatCorrelation.threat_b_id == threat.id)
    ).order_by(ThreatCorrelation.score.desc()).limit(15).all()
    related = []
    for pair in pairs:
        other_id = pair.threat_b_id if pair.threat_a_id == threat.id else pair.threat_a_id
        other = db.get(Threat, other_id)
        if other:
            related.append({
                "threat": threat_out(other),
                "score": pair.score,
                "reasons": pair.reasons,
                "method": pair.method,
            })
    exposed_assets = []
    vulnerability = None
    if threat.cve_id:
        vulnerability = db.query(Vulnerability).filter(Vulnerability.cve_id == threat.cve_id).first()
        if vulnerability:
            links = db.query(AssetVulnerability).filter(AssetVulnerability.vulnerability_id == vulnerability.id).all()
            for link in links:
                asset = db.get(Asset, link.asset_id)
                if asset:
                    exposed_assets.append({
                        "asset": {"id": asset.id, "ref": asset.ref, "name": asset.name, "category": asset.category,
                                  "criticality": asset.criticality, "exposure": asset.exposure},
                        "status": link.status,
                        "confidence": link.match_confidence,
                        "reason": link.match_reason,
                    })
    assessments = db.query(RiskAssessment).filter(RiskAssessment.threat_id == threat.id).order_by(RiskAssessment.created_at.desc()).limit(10).all()
    alerts = db.query(Alert).filter(Alert.threat_id == threat.id).order_by(Alert.detected_at.desc()).limit(10).all()
    return {
        "threat": threat_out(threat, detailed=True),
        "vulnerability": {"cve_id": vulnerability.cve_id, "title": vulnerability.title, "cvss": vulnerability.cvss_score,
                          "epss": vulnerability.epss_score, "known_exploited": vulnerability.known_exploited,
                          "remediation": vulnerability.remediation} if vulnerability else None,
        "notes": [note_out(note, authors.get(note.user_id)) for note in notes],
        "recommendations": [recommendation_out(r) for r in recommendations],
        "correlations": related,
        "exposed_assets": exposed_assets,
        "assessments": [
            assessment_out(a, threat, db.get(Asset, a.asset_id) if a.asset_id else None,
                           db.get(Vulnerability, a.vulnerability_id) if a.vulnerability_id else None)
            for a in assessments
        ],
        "alerts": [
            {"id": a.id, "ref": a.ref, "title": a.title, "severity": a.severity, "status": a.status,
             "detected_at": a.detected_at.isoformat(), "risk_score": a.risk_score}
            for a in alerts
        ],
        "risk_breakdown": risk.assess(threat, None, None, db),
    }


@router.patch("/{identifier}")
def update_threat(identifier: str, payload: ThreatUpdate, request: Request,
                  db: Session = Depends(get_db), user: User = Depends(require_role("analyst"))):
    threat = _resolve_threat(db, identifier)
    changes = []
    if payload.status is not None:
        threat.status = payload.status
        changes.append(f"status={payload.status}")
    if payload.is_saved is not None:
        threat.is_saved = payload.is_saved
        changes.append(f"saved={payload.is_saved}")
    if payload.assigned_to is not None:
        assignee = db.get(User, payload.assigned_to)
        if not assignee or not assignee.is_active:
            raise HTTPException(status_code=422, detail="Assignee not found or inactive")
        threat.assigned_to = assignee.id
        changes.append(f"assigned_to={assignee.email}")
    audit(db, request, user, "threat.updated", "threat", threat.ref, ", ".join(changes) or "no changes")
    db.commit()
    return {"threat": threat_out(threat), "message": "Threat updated"}


@router.get("/{identifier}/notes")
def list_notes(identifier: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    threat = _resolve_threat(db, identifier)
    notes = db.query(AnalystNote).filter(AnalystNote.threat_id == threat.id).order_by(AnalystNote.created_at.desc()).all()
    return {"items": [note_out(note, db.get(User, note.user_id)) for note in notes]}


@router.post("/{identifier}/notes", status_code=201)
def add_note(identifier: str, payload: NoteCreate, request: Request,
             db: Session = Depends(get_db), user: User = Depends(require_role("analyst"))):
    threat = _resolve_threat(db, identifier)
    note = AnalystNote(user_id=user.id, threat_id=threat.id, body=payload.body, created_at=utcnow())
    db.add(note)
    audit(db, request, user, "threat.note.added", "threat", threat.ref, payload.body[:300])
    db.commit()
    return note_out(note, user)


@router.get("/{identifier}/recommendations")
def threat_recommendations(identifier: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    threat = _resolve_threat(db, identifier)
    recs = db.query(Recommendation).filter(Recommendation.threat_id == threat.id).all()
    return {"items": [recommendation_out(r) for r in recs]}
