"""Public landing-page statistics and health endpoints."""
from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import Alert, Asset, Threat, ThreatCorrelation, ThreatSource, Vulnerability, utcnow
from ..serializers import source_out

router = APIRouter(tags=["Public"])


@router.get("/public/overview")
def public_overview(db: Session = Depends(get_db)):
    threats = db.query(Threat).all()
    vulns = db.query(Vulnerability).all()
    sources = db.query(ThreatSource).all()
    severity = Counter(t.severity for t in threats)
    categories = Counter((t.ai_category or t.category) for t in threats)
    latest = max((t.published_at for t in threats), default=None)
    return {
        "platform": "CyberGuard AI",
        "tagline": "AI-Driven Cyber Threat Intelligence & Risk Analytics Platform",
        "metrics": {
            "threat_records": len(threats),
            "vulnerabilities": len(vulns),
            "assets_monitored": db.query(func.count(Asset.id)).scalar() or 0,
            "alerts_generated": db.query(func.count(Alert.id)).scalar() or 0,
            "known_exploited": sum(1 for v in vulns if v.known_exploited),
            "sources_online": sum(1 for s in sources if s.status in {"operational", "degraded"}),
            "sources_total": len(sources),
            "correlated_pairs": db.query(func.count(ThreatCorrelation.id)).scalar() or 0,
            "last_intelligence_at": latest.isoformat() if latest else None,
        },
        "severity_distribution": [
            {"name": name.title(), "value": severity.get(name, 0)}
            for name in ["critical", "high", "medium", "low", "informational"] if severity.get(name, 0)
        ],
        "category_distribution": [{"name": name, "value": count} for name, count in categories.most_common(6)],
        "capabilities": [
            {"title": "Intelligence ingestion", "detail": "Modular connectors for NVD, CISA KEV and EPSS with source freshness and provenance."},
            {"title": "AI-assisted analysis", "detail": "DeepSeek-grounded chat over stored records, with entity extraction and evidence-linked explanations."},
            {"title": "Exposure correlation", "detail": "Product and affected-version validation against a registered asset inventory."},
            {"title": "Explainable risk", "detail": "Configurable multi-factor scoring with separate exploitation status and evidence confidence."},
            {"title": "Early warning", "detail": "Rule and statistical detection with explicit trigger evidence and analyst workflow."},
            {"title": "Analytics & reporting", "detail": "Live aggregations, exportable charts, and role-controlled reporting."},
        ],
        "source_status": [source_out(s) for s in sources],
        "connectors": settings.connector_status(),
    }


@router.get("/system/health")
def health(db: Session = Depends(get_db)):
    database_ok = True
    try:
        db.execute(text("SELECT 1"))
    except Exception:  # pragma: no cover - defensive health reporting
        database_ok = False
    return {
        "status": "ok" if database_ok else "degraded",
        "version": "1.0.0",
        "timestamp": utcnow().isoformat(),
    }
