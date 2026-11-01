"""Vulnerability-to-asset exposure matching and analyst verification."""
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import audit, get_current_user, require_role
from ..models import Asset, AssetVulnerability, Threat, User, Vulnerability, utcnow
from ..schemas import MatchUpdate
from ..services import exposure, risk
from ..utils import csv_response_bytes
from .common import split_multi

router = APIRouter(prefix="/exposure", tags=["Exposure Matching"])

VALID_MATCH_STATUSES = {"potentially_exposed", "needs_verification", "confirmed", "not_affected"}


def _rows(db: Session, q, status, category, asset_id, min_cvss):
    links = db.query(AssetVulnerability).all()
    rows = []
    for link in links:
        asset = db.get(Asset, link.asset_id)
        vuln = db.get(Vulnerability, link.vulnerability_id)
        if not asset or not vuln:
            continue
        statuses = split_multi(status)
        if statuses and link.status not in statuses:
            continue
        if category and asset.category != category:
            continue
        if asset_id and asset.id != asset_id:
            continue
        if min_cvss is not None and (vuln.cvss_score or 0) < min_cvss:
            continue
        if q:
            needle = q.lower().strip()
            haystack = " ".join([
                asset.name, asset.ref, asset.software, asset.software_version, asset.category,
                vuln.cve_id, vuln.title, link.match_reason or "",
            ]).lower()
            if needle not in haystack:
                continue
        threat = db.query(Threat).filter(Threat.cve_id == vuln.cve_id).first()
        rows.append({
            "id": link.id,
            "asset": {
                "id": asset.id, "ref": asset.ref, "name": asset.name, "category": asset.category,
                "software": asset.software, "software_version": asset.software_version,
                "exposure": asset.exposure, "internet_facing": asset.internet_facing,
                "criticality": asset.criticality, "organisation": asset.organisation.name if asset.organisation else None,
            },
            "vulnerability": {
                "id": vuln.id, "cve_id": vuln.cve_id, "title": vuln.title, "cvss": vuln.cvss_score,
                "severity": vuln.cvss_severity, "epss": vuln.epss_score,
                "known_exploited": vuln.known_exploited, "published_at": vuln.published_at.isoformat(),
                "source_url": vuln.source_url,
            },
            "threat": {"ref": threat.ref, "name": threat.name, "risk_score": threat.risk_score} if threat else None,
            "status": link.status,
            "confidence": link.match_confidence,
            "reason": link.match_reason,
            "created_at": link.created_at.isoformat(),
        })
    priority = {"confirmed": 0, "potentially_exposed": 1, "needs_verification": 2, "not_affected": 3}
    rows.sort(key=lambda r: (priority.get(r["status"], 4), -(r["vulnerability"]["cvss"] or 0), r["asset"]["name"]))
    return rows


@router.get("")
def list_matches(
    q: str | None = None,
    status: str | None = None,
    category: str | None = None,
    asset_id: int | None = Query(None, alias="asset"),
    min_cvss: float | None = Query(None, ge=0, le=10),
    page: int = Query(1, ge=1),
    size: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    rows = _rows(db, q, status, category, asset_id, min_cvss)
    start = (page - 1) * size
    all_assets = db.query(Asset).all()
    return {
        "items": rows[start:start + size],
        "total": len(rows),
        "page": page,
        "size": size,
        "pages": max(1, -(-len(rows) // size)) if rows else 0,
        "facets": {
            "statuses": [{"name": key, "count": count} for key, count in Counter(r["status"] for r in rows).most_common()],
            "categories": [{"name": key, "count": count} for key, count in Counter(r["asset"]["category"] for r in rows).most_common()],
        },
        "inventory_categories": sorted({asset.category for asset in all_assets}),
        "methodology": (
            "A row only appears here when the asset's software maps to a known product alias and the installed "
            "version falls inside the vulnerability's affected range. 'needs_verification' indicates an incomplete "
            "version match and is never counted as validated exposure."
        ),
    }


@router.get("/summary")
def exposure_summary(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    assets = db.query(Asset).all()
    links = db.query(AssetVulnerability).all()
    status_counts = Counter(link.status for link in links)
    validated_assets = {link.asset_id for link in links if link.status in {"potentially_exposed", "confirmed"}}
    kev_assets = set()
    critical_exposed = set()
    for link in links:
        if link.status not in {"potentially_exposed", "confirmed"}:
            continue
        vuln = db.get(Vulnerability, link.vulnerability_id)
        asset = db.get(Asset, link.asset_id)
        if vuln and vuln.known_exploited:
            kev_assets.add(link.asset_id)
        if asset and asset.criticality >= 4:
            critical_exposed.add(link.asset_id)
    by_category = Counter()
    for asset in assets:
        if asset.id in validated_assets:
            by_category[asset.category] += 1
    return {
        "assets": len(assets),
        "assets_with_validated_exposure": len(validated_assets),
        "assets_with_known_exploited": len(kev_assets),
        "critical_assets_exposed": len(critical_exposed),
        "matches": len(links),
        "validated_matches": status_counts.get("potentially_exposed", 0) + status_counts.get("confirmed", 0),
        "needs_verification": status_counts.get("needs_verification", 0),
        "confirmed": status_counts.get("confirmed", 0),
        "not_affected": status_counts.get("not_affected", 0),
        "coverage_percent": round(len(validated_assets) / len(assets) * 100, 1) if assets else 0,
        "by_category": [{"name": name, "value": value} for name, value in by_category.most_common()],
        "status_distribution": [
            {"name": key.replace("_", " ").title(), "value": value} for key, value in status_counts.most_common()
        ],
        "note": "Only product- and version-validated matches contribute to exposure counts.",
    }


@router.post("/scan")
def scan(request: Request, db: Session = Depends(get_db), user: User = Depends(require_role("analyst"))):
    result = exposure.run_scan(db, user_id=user.id)
    audit(db, request, user, "exposure.scan", "asset_vulnerability", "",
          f"{result['validated_matches']} validated, {result['needs_verification']} need verification, "
          f"{result['recommendations_created']} recommendation(s)")
    db.commit()
    return result


@router.get("/export.csv")
def export_matches(
    q: str | None = None, status: str | None = None, category: str | None = None,
    asset_id: int | None = Query(None, alias="asset"), min_cvss: float | None = Query(None, ge=0, le=10),
    db: Session = Depends(get_db), user: User = Depends(get_current_user),
):
    rows = _rows(db, q, status, category, asset_id, min_cvss)
    headers = ["asset_ref", "asset_name", "asset_category", "software", "version", "exposure", "criticality",
               "cve", "cvss", "epss", "known_exploited", "match_status", "match_confidence", "match_reason"]
    data = [[
        r["asset"]["ref"], r["asset"]["name"], r["asset"]["category"], r["asset"]["software"],
        r["asset"]["software_version"], r["asset"]["exposure"], r["asset"]["criticality"],
        r["vulnerability"]["cve_id"], r["vulnerability"]["cvss"], r["vulnerability"]["epss"],
        r["vulnerability"]["known_exploited"], r["status"], r["confidence"], r["reason"],
    ] for r in rows]
    return StreamingResponse(
        iter([csv_response_bytes(headers, data)]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="cyberguard-exposure-{utcnow().date()}.csv"'},
    )


@router.patch("/matches/{match_id}")
def update_match(match_id: int, payload: MatchUpdate, request: Request,
                 db: Session = Depends(get_db), user: User = Depends(require_role("analyst"))):
    link = db.get(AssetVulnerability, match_id)
    if not link:
        raise HTTPException(status_code=404, detail="Match not found")
    if payload.status not in VALID_MATCH_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid match status")
    previous = link.status
    link.status = payload.status
    if payload.note:
        link.match_reason = f"{link.match_reason} | Analyst {user.email}: {payload.note}"[:4000]
    asset = db.get(Asset, link.asset_id)
    vuln = db.get(Vulnerability, link.vulnerability_id)
    if payload.status in {"confirmed", "not_affected"} and asset:
        asset.last_assessed_at = utcnow()
    audit(db, request, user, "exposure.match.updated", "asset_vulnerability", str(link.id),
          f"{vuln.cve_id if vuln else ''} on {asset.ref if asset else ''}: {previous} → {payload.status}. {payload.note}")
    db.commit()
    return {
        "match": {
            "id": link.id,
            "status": link.status,
            "reason": link.match_reason,
            "asset": {"ref": asset.ref, "name": asset.name} if asset else None,
            "vulnerability": {"cve_id": vuln.cve_id} if vuln else None,
        },
        "message": "Match status recorded",
    }
