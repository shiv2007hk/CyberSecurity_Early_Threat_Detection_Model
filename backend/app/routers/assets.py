"""Asset inventory, exposure detail and import/export endpoints."""
import csv
import io
from collections import defaultdict, Counter

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import case, or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import audit, get_current_user, require_role
from ..models import (
    Alert,
    AnalystNote,
    Asset,
    AssetVulnerability,
    Organisation,
    Recommendation,
    RiskAssessment,
    Threat,
    User,
    Vulnerability,
    utcnow,
)
from ..schemas import AssetImport, AssetPayload, AssetUpdate
from ..serializers import asset_out, assessment_out, note_out, recommendation_out
from ..services import exposure
from ..utils import csv_response_bytes
from .common import paginate, serialize_facets, split_multi

router = APIRouter(prefix="/assets", tags=["Assets & Exposure"])

CATEGORIES = [
    "Server", "Database", "Hospital System", "Financial System", "Cloud Infrastructure",
    "Enterprise Application", "IoT Device", "Network Infrastructure", "Workstation",
]
EXPOSURES = {"internet-facing", "internal", "air-gapped"}


def _next_ref(db: Session) -> str:
    count = db.query(Asset).count() + 1
    while db.query(Asset).filter(Asset.ref == f"AST-{utcnow().year}-{count:04d}").first():
        count += 1
    return f"AST-{utcnow().year}-{count:04d}"


def _filtered(db, q, category, org_id, exposure_value, criticality, internet_facing, sort_by, order):
    query = db.query(Asset)
    if q:
        pattern = f"%{q.strip()}%"
        query = query.filter(or_(
            Asset.name.ilike(pattern), Asset.software.ilike(pattern), Asset.ref.ilike(pattern),
            Asset.identifier.ilike(pattern), Asset.owner.ilike(pattern), Asset.os.ilike(pattern),
        ))
    categories = split_multi(category)
    if categories:
        query = query.filter(Asset.category.in_(categories))
    if org_id:
        query = query.filter(Asset.organisation_id == org_id)
    exposures = split_multi(exposure_value)
    if exposures:
        query = query.filter(Asset.exposure.in_(exposures))
    if criticality:
        levels = [int(value) for value in split_multi(str(criticality)) if value.isdigit()]
        if levels:
            query = query.filter(Asset.criticality.in_(levels))
    if internet_facing is not None:
        query = query.filter(Asset.internet_facing.is_(internet_facing))
    sort_map = {
        "name": Asset.name,
        "criticality": Asset.criticality,
        "created_at": Asset.created_at,
        "software": Asset.software,
        "risk_score": None,
    }
    column = sort_map.get(sort_by)
    if column is not None:
        query = query.order_by(column.asc() if order == "asc" else column.desc())
    else:
        query = query.order_by(Asset.criticality.desc(), Asset.name.asc())
    return query


@router.get("")
def list_assets(
    q: str | None = None,
    category: str | None = None,
    organisation: int | None = None,
    exposure_value: str | None = Query(None, alias="exposure"),
    criticality: str | None = None,
    internet_facing: bool | None = None,
    sort_by: str = "risk_score",
    order: str = "desc",
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = _filtered(db, q, category, organisation, exposure_value, criticality, internet_facing, sort_by, order)
    total = query.count()
    assets = query.all()
    rows = [(asset, exposure.asset_risk_summary(db, asset)) for asset in assets]
    if sort_by == "risk_score":
        rows.sort(key=lambda pair: pair[1]["risk_score"], reverse=(order != "asc"))
    start = (page - 1) * size
    page_rows = rows[start:start + size]
    all_assets = db.query(Asset).all()
    return {
        "items": [asset_out(asset, summary) for asset, summary in page_rows],
        "total": total,
        "page": page,
        "size": size,
        "pages": max(1, -(-total // size)) if total else 0,
        "facets": {
            "categories": serialize_facets(all_assets, "category"),
            "exposures": serialize_facets(all_assets, "exposure"),
        },
        "stats": {
            "total": len(all_assets),
            "internet_facing": sum(1 for a in all_assets if a.internet_facing),
            "validated_exposed": len({
                link.asset_id for link in db.query(AssetVulnerability).filter(
                    AssetVulnerability.status == "potentially_exposed"
                ).all()
            }),
            "critical_assets": sum(1 for a in all_assets if a.criticality >= 4),
        },
    }


@router.get("/options")
def asset_options(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return {
        "categories": CATEGORIES,
        "exposures": sorted(EXPOSURES),
        "organisations": [
            {"id": org.id, "name": org.name, "sector": org.sector}
            for org in db.query(Organisation).order_by(Organisation.name).all()
        ],
        "software": sorted({a.software for a in db.query(Asset).all()}),
        "criticality_scale": [
            {"value": 1, "label": "Minimal"}, {"value": 2, "label": "Low"}, {"value": 3, "label": "Moderate"},
            {"value": 4, "label": "High"}, {"value": 5, "label": "Mission-critical"},
        ],
        "business_importance": ["standard", "important", "critical", "safety-critical"],
    }


def _csv_cell(value):
    if isinstance(value, str) and value[:1] in {"=", "+", "-", "@"}:
        return "'" + value
    return value


@router.get("/export.csv")
def export_assets(
    q: str | None = None,
    category: str | None = None,
    organisation: int | None = None,
    exposure_value: str | None = Query(None, alias="exposure"),
    criticality: str | None = None,
    internet_facing: bool | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = _filtered(db, q, category, organisation, exposure_value, criticality, internet_facing, "name", "asc")
    headers = ["ref", "name", "category", "organisation", "identifier", "software", "software_version", "os",
               "exposure", "internet_facing", "criticality", "business_importance", "owner", "risk_score",
               "risk_category", "validated_vulnerabilities", "needs_verification"]
    rows = []
    for asset in query.limit(5000).all():
        summary = exposure.asset_risk_summary(db, asset)
        rows.append([_csv_cell(value) for value in [
            asset.ref, asset.name, asset.category, asset.organisation.name if asset.organisation else "",
            asset.identifier, asset.software, asset.software_version, asset.os, asset.exposure,
            asset.internet_facing, asset.criticality, asset.business_importance, asset.owner,
            summary["risk_score"], summary["risk_category"], summary["validated_vulnerabilities"],
            summary["needs_verification"],
        ]])
    return StreamingResponse(
        iter([csv_response_bytes(headers, rows)]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="cyberguard-assets-{utcnow().date()}.csv"'},
    )


@router.post("/import")
def import_assets(payload: AssetImport, request: Request, db: Session = Depends(get_db),
                  user: User = Depends(require_role("analyst"))):
    reader = csv.DictReader(io.StringIO(payload.csv_text))
    if not reader.fieldnames:
        raise HTTPException(status_code=422, detail="CSV header row is missing")
    normalised = {name.strip().lower().replace(" ", "_"): name for name in reader.fieldnames}
    if "name" not in normalised or "software" not in normalised:
        raise HTTPException(status_code=422, detail="CSV must include at least 'name' and 'software' columns")
    orgs = {org.name.lower(): org for org in db.query(Organisation).all()}
    default_org = next(iter(orgs.values()), None)
    created, skipped = 0, []
    for index, raw in enumerate(reader, start=2):
        if index > 502:
            skipped.append("Row limit reached (500 rows per import)")
            break
        row = {key.strip().lower().replace(" ", "_"): (value or "").strip() for key, value in raw.items() if key}
        name = row.get("name", "")
        software = row.get("software", "")
        if len(name) < 2 or not software:
            skipped.append(f"Row {index}: name and software are required")
            continue
        category = row.get("category") or "Server"
        if category not in CATEGORIES:
            category = "Server" if not row.get("category") else row["category"][:60]
        exposure_value = row.get("exposure") or ("internet-facing" if row.get("internet_facing", "").lower() in {"true", "1", "yes"} else "internal")
        if exposure_value not in EXPOSURES:
            exposure_value = "internal"
        try:
            criticality = int(row.get("criticality") or 3)
        except ValueError:
            criticality = 3
        criticality = max(1, min(5, criticality))
        org = orgs.get(row.get("organisation", "").lower(), default_org)
        db.add(Asset(
            ref=_next_ref(db),
            name=name[:160],
            category=category,
            organisation_id=org.id if org else None,
            identifier=row.get("identifier", "")[:120],
            software=software[:120],
            software_version=row.get("software_version", row.get("version", ""))[:60],
            os=row.get("os", "")[:100],
            exposure=exposure_value,
            internet_facing=exposure_value == "internet-facing",
            criticality=criticality,
            business_importance=row.get("business_importance", "standard")[:30],
            owner=row.get("owner", "")[:120],
            notes=row.get("notes", "")[:2000],
            is_simulated=False,
            created_at=utcnow(),
            last_assessed_at=utcnow(),
        ))
        db.flush()
        created += 1
    audit(db, request, user, "assets.imported", "asset", "", f"Imported {created} asset(s); {len(skipped)} skipped")
    db.commit()
    scan = exposure.run_scan(db, user_id=user.id) if created else None
    return {
        "created": created,
        "skipped": skipped,
        "exposure_scan": scan,
        "note": "Imported assets are treated as authorised inventory supplied by the operator. Exposure matches still require product and version validation.",
    }


@router.post("", status_code=201)
def create_asset(payload: AssetPayload, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_role("analyst"))):
    org = db.get(Organisation, payload.organisation_id) if payload.organisation_id else db.query(Organisation).first()
    asset = Asset(
        ref=_next_ref(db),
        name=payload.name.strip(),
        category=payload.category,
        organisation_id=org.id if org else None,
        identifier=payload.identifier,
        software=payload.software.strip(),
        software_version=payload.software_version.strip(),
        os=payload.os,
        exposure=payload.exposure,
        internet_facing=payload.exposure == "internet-facing",
        criticality=payload.criticality,
        business_importance=payload.business_importance,
        owner=payload.owner,
        notes=payload.notes,
        is_simulated=False,
        last_assessed_at=utcnow(),
        created_at=utcnow(),
    )
    db.add(asset)
    db.flush()
    audit(db, request, user, "asset.created", "asset", asset.ref, f"{asset.name} ({asset.software} {asset.software_version})")
    db.commit()
    scan = exposure.run_scan(db, user_id=user.id)
    return {"asset": asset_out(asset, exposure.asset_risk_summary(db, asset)), "exposure_scan": scan}


def _resolve(db: Session, identifier: str) -> Asset:
    asset = db.query(Asset).filter(Asset.ref == identifier.upper()).first()
    if not asset and identifier.isdigit():
        asset = db.get(Asset, int(identifier))
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.get("/graph")
def asset_graph(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    assets = db.query(Asset).order_by(Asset.criticality.desc()).limit(80).all()
    vulnerabilities = db.query(AssetVulnerability).all()
    vuln_counts = Counter(link.asset_id for link in vulnerabilities if link.status == "potentially_exposed")
    nodes = [
        {
            "id": asset.ref, "name": asset.name, "category": asset.category,
            "criticality": asset.criticality, "exposure": asset.exposure,
            "software": asset.software, "risk_score": exposure.asset_risk_summary(db, asset)["risk_score"],
            "validated_vulnerabilities": vuln_counts.get(asset.id, 0),
            "organisation": asset.organisation.name if asset.organisation else "",
        }
        for asset in assets
    ]
    ids = {asset.id: asset for asset in assets}
    edges = []
    seen = set()
    by_software = defaultdict(list)
    by_org = defaultdict(list)
    for asset in assets:
        by_software[asset.software.lower()].append(asset)
        by_org[asset.organisation_id].append(asset)
    for group, relation in ((by_software, "shared software"), (by_org, "same organisation")):
        for members in group.values():
            if len(members) < 2:
                continue
            for i in range(len(members)):
                for j in range(i + 1, min(len(members), i + 10)):
                    a, b = members[i], members[j]
                    key = tuple(sorted((a.id, b.id)))
                    if key in seen:
                        continue
                    seen.add(key)
                    edges.append({"source": a.ref, "target": b.ref, "relation": relation})
                    if len(edges) >= 160:
                        break
                if len(edges) >= 160:
                    break
            if len(edges) >= 160:
                break
        if len(edges) >= 160:
            break
    return {
        "nodes": nodes,
        "edges": edges,
        "note": "Edges represent shared software or organisational grouping inferred from inventory records, not confirmed network dependencies.",
    }


@router.get("/{identifier}")
def asset_detail(identifier: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    asset = _resolve(db, identifier)
    summary = exposure.asset_risk_summary(db, asset)
    links = db.query(AssetVulnerability).filter(AssetVulnerability.asset_id == asset.id).all()
    matches = []
    for link in links:
        vuln = db.get(Vulnerability, link.vulnerability_id)
        if not vuln:
            continue
        threat = db.query(Threat).filter(Threat.cve_id == vuln.cve_id).first()
        matches.append({
            "id": link.id,
            "vulnerability": {
                "id": vuln.id, "cve_id": vuln.cve_id, "title": vuln.title, "cvss": vuln.cvss_score,
                "cvss_severity": vuln.cvss_severity, "epss": vuln.epss_score,
                "known_exploited": vuln.known_exploited, "published_at": vuln.published_at.isoformat(),
                "remediation": vuln.remediation, "source_url": vuln.source_url,
            },
            "threat": {"ref": threat.ref, "name": threat.name, "severity": threat.severity,
                       "risk_score": threat.risk_score} if threat else None,
            "status": link.status,
            "confidence": link.match_confidence,
            "reason": link.match_reason,
            "created_at": link.created_at.isoformat(),
        })
    recommendations = db.query(Recommendation).filter(Recommendation.asset_id == asset.id).order_by(
        Recommendation.created_at.desc()
    ).all()
    alerts = db.query(Alert).all()
    related_alerts = [alert for alert in alerts if asset.id in (alert.asset_ids or [])]
    assessments = db.query(RiskAssessment).filter(RiskAssessment.asset_id == asset.id).order_by(
        RiskAssessment.created_at.desc()
    ).limit(15).all()
    notes = db.query(AnalystNote).filter(AnalystNote.asset_id == asset.id).order_by(AnalystNote.created_at.desc()).all()
    related = []
    peers = db.query(Asset).filter(Asset.software == asset.software, Asset.id != asset.id).limit(8).all()
    for peer in peers:
        related.append({"ref": peer.ref, "name": peer.name, "software": peer.software,
                        "software_version": peer.software_version, "category": peer.category,
                        "relation": "shared software"})
    return {
        "asset": asset_out(asset, summary),
        "matches": sorted(matches, key=lambda m: (m["status"] != "potentially_exposed", -(m["vulnerability"]["cvss"] or 0))),
        "recommendations": [recommendation_out(r) for r in recommendations],
        "alerts": [
            {"id": a.id, "ref": a.ref, "title": a.title, "severity": a.severity, "status": a.status,
             "detected_at": a.detected_at.isoformat()} for a in related_alerts[:10]
        ],
        "assessments": [
            assessment_out(record, db.get(Threat, record.threat_id) if record.threat_id else None,
                           asset, db.get(Vulnerability, record.vulnerability_id) if record.vulnerability_id else None)
            for record in assessments
        ],
        "notes": [note_out(note, db.get(User, note.user_id)) for note in notes],
        "related_assets": related,
        "methodology": (
            "Asset risk is the highest explainable risk score across version-validated vulnerability matches. "
            "Product identity and affected-version ranges are checked before a match is treated as exposure; "
            "unverified name matches remain in 'needs_verification' and do not raise the score."
        ),
    }


@router.patch("/{identifier}")
def update_asset(identifier: str, payload: AssetUpdate, request: Request,
                 db: Session = Depends(get_db), user: User = Depends(require_role("analyst"))):
    asset = _resolve(db, identifier)
    changed = []
    for field, value in payload.model_dump(exclude_unset=True).items():
        if field == "organisation_id" and value is not None and not db.get(Organisation, value):
            raise HTTPException(status_code=422, detail="Organisation not found")
        if value is not None:
            setattr(asset, field, value)
            changed.append(field)
    if payload.exposure is not None:
        asset.internet_facing = payload.exposure == "internet-facing"
    asset.last_assessed_at = utcnow()
    audit(db, request, user, "asset.updated", "asset", asset.ref, f"Updated: {', '.join(changed) or 'none'}")
    db.commit()
    scan = exposure.run_scan(db, user_id=user.id)
    return {"asset": asset_out(asset, exposure.asset_risk_summary(db, asset)), "exposure_scan": scan}


@router.delete("/{identifier}")
def delete_asset(identifier: str, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_role("admin"))):
    asset = _resolve(db, identifier)
    label = f"{asset.ref} {asset.name}"
    db.query(AssetVulnerability).filter(AssetVulnerability.asset_id == asset.id).delete()
    db.query(AnalystNote).filter(AnalystNote.asset_id == asset.id).delete()
    db.query(RiskAssessment).filter(RiskAssessment.asset_id == asset.id).delete()
    db.delete(asset)
    audit(db, request, user, "asset.deleted", "asset", identifier, label)
    db.commit()
    return {"message": f"Asset {label} removed from inventory"}
