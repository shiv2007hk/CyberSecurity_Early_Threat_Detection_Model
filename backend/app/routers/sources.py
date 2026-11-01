"""Threat-source management, synchronisation and indicator enrichment."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..deps import audit, get_current_user, require_role
from ..models import IngestionLog, ThreatSource, User
from ..schemas import EnrichmentRequest, SourceToggle
from ..serializers import ingestion_out, source_out
from ..services import integrations
from .common import paginate, split_multi

router = APIRouter(prefix="/sources", tags=["Sources"])

LIVE_KEYS = {"nvd", "cisa_kev", "epss"}
KEY_FIELDS = {
    "otx": "otx_api_key",
    "virustotal": "virustotal_api_key",
    "abuseipdb": "abuseipdb_api_key",
    "greynoise": "greynoise_api_key",
}


def _key_configured(source: ThreatSource) -> bool:
    field = KEY_FIELDS.get(source.key)
    return bool(getattr(settings, field, "")) if field else True


def _refreshed(source: ThreatSource) -> dict:
    data = source_out(source)
    if source.key in KEY_FIELDS:
        configured = _key_configured(source)
        data["key_configured"] = configured
        if not configured and source.status != "disabled":
            data["status"] = "awaiting_key"
    data["automated_sync"] = source.key in LIVE_KEYS
    return data


@router.get("")
def list_sources(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    sources = db.query(ThreatSource).order_by(ThreatSource.reliability.desc()).all()
    return {
        "items": [_refreshed(source) for source in sources],
        "configuration": {
            "live_feeds_enabled": settings.enable_live_threat_feeds,
            "chat_enabled": settings.deepseek_configured,
            "ai_analysis_enabled": settings.enable_ai_analysis,
            "email_alerts_enabled": settings.enable_email_alerts,
            "connectors": settings.connector_status(),
            "nvd_mode": "api-key" if settings.nvd_api_key else "public-rate-limited",
        },
        "sync_policy": {
            "nvd": "Public endpoint is rate-limited; an API key raises the quota. Maximum 60 records processed per run.",
            "cisa_kev": "Official machine-readable KEV JSON catalogue.",
            "epss": "EPSS scores are applied to stored CVEs; no CVE records are invented.",
            "manual": "VirusTotal, AbuseIPDB and GreyNoise are used only for on-demand indicator enrichment when authorised keys exist.",
        },
        "secret_policy": "API keys are read server-side from environment variables and are never returned to the browser or written to logs.",
    }


@router.get("/logs")
def ingestion_logs(
    source: str | None = None,
    status: str | None = None,
    mode: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(IngestionLog)
    sources = split_multi(source)
    if sources:
        query = query.filter(IngestionLog.source_key.in_(sources))
    statuses = split_multi(status)
    if statuses:
        query = query.filter(IngestionLog.status.in_(statuses))
    modes = split_multi(mode)
    if modes:
        query = query.filter(IngestionLog.mode.in_(modes))
    query = query.order_by(IngestionLog.started_at.desc())
    return paginate(query, page, size, lambda log: ingestion_out(log))


@router.patch("/{key}")
def toggle_source(key: str, payload: SourceToggle, request: Request, db: Session = Depends(get_db),
                  user: User = Depends(require_role("admin"))):
    source = db.query(ThreatSource).filter(ThreatSource.key == key).first()
    if not source:
        raise HTTPException(status_code=404, detail="Source not found")
    if payload.enabled and source.requires_key and not _key_configured(source):
        raise HTTPException(status_code=422, detail="Configure the API key on the server before enabling this connector")
    source.enabled = payload.enabled
    if not payload.enabled:
        source.status = "disabled"
        source.last_message = "Disabled by an administrator."
    elif source.requires_key and not _key_configured(source):
        source.status = "awaiting_key"
    elif source.key in LIVE_KEYS:
        source.status = "operational"
        source.last_message = "Enabled; awaiting next synchronisation."
    elif source.status == "disabled":
        source.status = "reference" if source.category == "knowledge-base" else "manual-import"
        source.last_message = "Enabled. Reference/manual import only."
    audit(db, request, user, "source.toggled", "threat_source", key, f"enabled={payload.enabled}")
    db.commit()
    return {"source": _refreshed(source), "message": f"{source.name} {'enabled' if payload.enabled else 'disabled'}"}


@router.post("/{key}/sync")
def sync_source(key: str, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require_role("analyst"))):
    source = db.query(ThreatSource).filter(ThreatSource.key == key).first()
    if not source:
        raise HTTPException(status_code=404, detail="Source not found")
    source.key_configured = _key_configured(source) if source.requires_key else source.key_configured
    if not settings.enable_live_threat_feeds:
        raise HTTPException(
            status_code=503,
            detail="Live feeds are disabled (ENABLE_LIVE_THREAT_FEEDS=false). Nothing was written in their place.",
        )
    try:
        result = integrations.sync_source(db, key)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    audit(db, request, user, "source.synced", "threat_source", key,
          f"mode={result.get('mode')} found={result.get('items_found')} new={result.get('items_new')}")
    db.commit()
    return {"result": result, "source": _refreshed(db.query(ThreatSource).filter(ThreatSource.key == key).first())}


@router.post("/enrich")
def enrich_indicator(payload: EnrichmentRequest, request: Request,
                     db: Session = Depends(get_db), user: User = Depends(require_role("analyst"))):
    result = integrations.enrich_indicator(payload.indicator_type, payload.value)
    audit(db, request, user, "indicator.enriched", "indicator", payload.value[:80],
          f"type={payload.indicator_type}")
    db.commit()
    return result
