"""Vulnerability intelligence endpoints."""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import case, or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import (
    Asset,
    AssetVulnerability,
    RiskAssessment,
    Threat,
    User,
    Vulnerability,
    utcnow,
)
from ..serializers import assessment_out, vuln_out
from ..services import risk
from ..utils import csv_response_bytes
from .common import ensure_range, paginate, serialize_facets, split_multi

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerability Intelligence"])


def _query(db, q, severity, kev, epss_min, source, range_key, start, end):
    start_dt, end_dt = ensure_range(range_key, start, end)
    query = db.query(Vulnerability).filter(
        Vulnerability.published_at >= start_dt, Vulnerability.published_at <= end_dt
    )
    if q:
        pattern = f"%{q.strip()}%"
        query = query.filter(or_(
            Vulnerability.cve_id.ilike(pattern),
            Vulnerability.title.ilike(pattern),
            Vulnerability.description.ilike(pattern),
        ))
    severities = split_multi(severity)
    if severities:
        query = query.filter(Vulnerability.cvss_severity.in_([s.lower() for s in severities]))
    if kev is not None:
        query = query.filter(Vulnerability.known_exploited.is_(kev))
    if epss_min is not None:
        query = query.filter(Vulnerability.epss_score.isnot(None), Vulnerability.epss_score >= epss_min)
    if source:
        sources = split_multi(source)
        if sources:
            query = query.filter(Vulnerability.source.in_(sources))
    return query, start_dt, end_dt


@router.get("")
def list_vulnerabilities(
    q: str | None = None,
    severity: str | None = None,
    kev: bool | None = None,
    epss_min: float | None = Query(None, ge=0, le=1),
    source: str | None = None,
    sort_by: str = "published_at",
    order: str = "desc",
    range_key: str = Query("90d", alias="range"),
    start: str | None = Query(None, alias="from"),
    end: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query, start_dt, end_dt = _query(db, q, severity, kev, epss_min, source, range_key, start, end)
    severity_order = case(
        (Vulnerability.cvss_severity == "critical", 0),
        (Vulnerability.cvss_severity == "high", 1),
        (Vulnerability.cvss_severity == "medium", 2),
        (Vulnerability.cvss_severity == "low", 3),
        else_=4,
    )
    sort_map = {
        "published_at": Vulnerability.published_at,
        "cvss": Vulnerability.cvss_score,
        "epss": Vulnerability.epss_score,
        "severity": severity_order,
        "cve": Vulnerability.cve_id,
        "modified_at": Vulnerability.modified_at,
    }
    column = sort_map.get(sort_by, Vulnerability.published_at)
    query = query.order_by(column.asc() if order == "asc" else column.desc())
    result = paginate(query, page, size, lambda v: vuln_out(v))
    in_range = db.query(Vulnerability).filter(
        Vulnerability.published_at >= start_dt, Vulnerability.published_at <= end_dt
    ).all()
    result["facets"] = {
        "severities": serialize_facets(in_range, "cvss_severity"),
        "sources": serialize_facets(in_range, "source"),
    }
    result["stats"] = {
        "critical": sum(1 for v in in_range if (v.cvss_severity or "") == "critical"),
        "known_exploited": sum(1 for v in in_range if v.known_exploited),
        "high_epss": sum(1 for v in in_range if (v.epss_score or 0) >= 0.5),
        "total": len(in_range),
    }
    return result


@router.get("/export.csv")
def export_vulnerabilities(
    q: str | None = None,
    severity: str | None = None,
    kev: bool | None = None,
    epss_min: float | None = Query(None, ge=0, le=1),
    source: str | None = None,
    range_key: str = Query("90d", alias="range"),
    start: str | None = Query(None, alias="from"),
    end: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query, _, _ = _query(db, q, severity, kev, epss_min, source, range_key, start, end)
    rows = []
    for vuln in query.order_by(Vulnerability.cvss_score.desc()).limit(5000).all():
        rows.append([
            vuln.cve_id, vuln.title, vuln.cvss_score, vuln.cvss_severity, vuln.epss_score,
            vuln.epss_percentile, vuln.known_exploited, vuln.ransomware_use,
            vuln.published_at.isoformat(), vuln.modified_at.isoformat(), vuln.source,
            vuln.source_url,
        ])
    headers = ["cve_id", "title", "cvss", "cvss_severity", "epss", "epss_percentile", "known_exploited",
               "ransomware_use", "published_at", "modified_at", "source", "source_url"]
    return StreamingResponse(
        iter([csv_response_bytes(headers, rows)]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="cyberguard-vulnerabilities-{utcnow().date()}.csv"'},
    )


@router.get("/stats")
def vulnerability_stats(
    range_key: str = Query("90d", alias="range"),
    start: str | None = Query(None, alias="from"),
    end: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    start_dt, end_dt = ensure_range(range_key, start, end)
    vulns = db.query(Vulnerability).filter(
        Vulnerability.published_at >= start_dt, Vulnerability.published_at <= end_dt
    ).all()
    all_vulns = db.query(Vulnerability).all()
    by_severity = {}
    for vuln in vulns:
        name = vuln.cvss_severity or "unknown"
        by_severity[name] = by_severity.get(name, 0) + 1
    return {
        "in_range": len(vulns),
        "cvss_severity": [{"name": key.title(), "value": value} for key, value in sorted(by_severity.items())],
        "known_exploited": sum(1 for v in vulns if v.known_exploited),
        "kev_total": sum(1 for v in all_vulns if v.known_exploited),
        "epss_high": sum(1 for v in vulns if (v.epss_score or 0) >= 0.5),
        "average_cvss": round(sum(v.cvss_score or 0 for v in vulns) / len(vulns), 2) if vulns else None,
        "note": "CVSS severity, EPSS probability and known-exploited status are independent evidence signals.",
    }


def _resolve(db: Session, identifier: str) -> Vulnerability:
    vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == identifier.upper()).first()
    if not vuln and identifier.isdigit():
        vuln = db.get(Vulnerability, int(identifier))
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability record not found")
    return vuln


@router.get("/{identifier}")
def vulnerability_detail(identifier: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    vuln = _resolve(db, identifier)
    threats = db.query(Threat).filter(Threat.cve_id == vuln.cve_id).order_by(Threat.published_at.desc()).all()
    links = db.query(AssetVulnerability).filter(AssetVulnerability.vulnerability_id == vuln.id).all()
    assets = []
    for link in links:
        asset = db.get(Asset, link.asset_id)
        if not asset:
            continue
        assets.append({
            "asset": {
                "id": asset.id, "ref": asset.ref, "name": asset.name, "category": asset.category,
                "software": asset.software, "software_version": asset.software_version,
                "criticality": asset.criticality, "exposure": asset.exposure,
                "internet_facing": asset.internet_facing, "organisation_id": asset.organisation_id,
            },
            "status": link.status,
            "confidence": link.match_confidence,
            "reason": link.match_reason,
        })
    assessments = db.query(RiskAssessment).filter(RiskAssessment.vulnerability_id == vuln.id).order_by(
        RiskAssessment.created_at.desc()
    ).limit(20).all()
    return {
        "vulnerability": vuln_out(vuln, detailed=True),
        "threats": [
            {"id": t.id, "ref": t.ref, "name": t.name, "severity": t.severity, "source": t.source,
             "published_at": t.published_at.isoformat(), "risk_score": t.risk_score,
             "exploitation_status": t.exploitation_status}
            for t in threats
        ],
        "asset_matches": assets,
        "validated_count": sum(1 for a in assets if a["status"] == "potentially_exposed"),
        "needs_verification_count": sum(1 for a in assets if a["status"] == "needs_verification"),
        "assessments": [
            assessment_out(record, None, db.get(Asset, record.asset_id) if record.asset_id else None, vuln)
            for record in assessments
        ],
        "evidence_note": (
            "CVSS describes technical severity, EPSS estimates exploitation probability, and known-exploited status "
            "records confirmed exploitation evidence. These are shown separately and are not interchangeable."
        ),
        "is_simulated": vuln.is_simulated,
    }


@router.post("/{identifier}/assess")
def assess_vulnerability_asset(
    identifier: str,
    request: Request,
    asset_id: int | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    vuln = _resolve(db, identifier)
    threat = db.query(Threat).filter(Threat.cve_id == vuln.cve_id).first()
    if not threat:
        raise HTTPException(status_code=409, detail="No linked threat record exists for this CVE, so the shared risk model cannot be applied")
    asset = db.get(Asset, asset_id) if asset_id else None
    if asset_id and not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if user.role == "viewer":
        raise HTTPException(status_code=403, detail="Requires analyst privileges")
    record = risk.persist_assessment(db, threat, asset, user=user, vulnerability_id=vuln.id)
    db.commit()
    return {
        "assessment": assessment_out(record, threat, asset, vuln),
        "breakdown": risk.assess(threat, asset, None, db),
    }
