"""Server-side threat-intelligence connectors with graceful failure and audit logging."""
import time
from datetime import timedelta

import httpx
from sqlalchemy.orm import Session

from ..config import settings
from ..models import IngestionLog, Threat, ThreatSource, Vulnerability, utcnow
from ..utils import severity_from_cvss
from . import classifier, risk

USER_AGENT = "CyberGuardAI/1.0 (+threat-intelligence connector)"
TIMEOUT = 20.0


def _get(url: str, params: dict | None = None, headers: dict | None = None) -> httpx.Response:
    merged = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        merged.update(headers)
    response = httpx.get(url, params=params, headers=merged, timeout=TIMEOUT, follow_redirects=True)
    response.raise_for_status()
    return response


def _log(db: Session, source_key: str, status: str, mode: str, found: int, new: int,
         message: str, started_ms: int) -> IngestionLog:
    log = IngestionLog(
        source_key=source_key,
        started_at=utcnow() - timedelta(milliseconds=started_ms),
        finished_at=utcnow(),
        status=status,
        mode=mode,
        items_found=found,
        items_new=new,
        message=message[:1000],
        duration_ms=started_ms,
    )
    db.add(log)
    db.commit()
    return log


def _risk_and_ai(threat: Threat, db: Session) -> None:
    # threat.category here is the upstream feed's own classification of the record, not
    # a value this pipeline produced, so passing it as a hint is external evidence.
    classification = classifier.classify(threat.description, hint=threat.category)
    threat.ai_category = classification["category"]
    threat.ai_confidence = round(classification["confidence"] * 100, 1)
    threat.ai_method = classifier.METHOD
    threat.ai_keywords = classifier.extract_keywords(threat.description)
    threat.ai_entities = classifier.extract_entities(threat.description, [threat.affected_technology] if threat.affected_technology else None)
    threat.ai_summary = classifier.summarise(
        threat.name, threat.description, threat.source, threat.affected_technology,
        threat.indicators, threat.cvss_score,
    )
    threat.ai_explanation = classifier.explain(
        threat.name, classification, threat.ai_entities, threat.indicators or [], threat.cvss_score,
        threat.epss_score, threat.known_exploited, threat.affected_technology,
        threat.source_reliability, threat.recommended_action,
    )
    threat.category = classification["category"] if classification["confidence"] > 0.4 else threat.category
    risk.apply_to_threat(threat, db)


def _extract_nvd_products(configurations: list | None) -> list[dict]:
    products: list[dict] = []
    for config in configurations or []:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) < 6:
                    continue
                vendor, product, version = parts[3], parts[4], parts[5]
                versions = {}
                if version not in {"*", "-", ""}:
                    versions["exact"] = [version]
                else:
                    start = match.get("versionStartIncluding")
                    end = match.get("versionEndIncluding")
                    end_excl = match.get("versionEndExcluding")
                    if start:
                        versions["start"] = start
                    if end:
                        versions["end"] = end
                    elif end_excl:
                        versions["end"] = end_excl
                    if not start and not end and not end_excl:
                        versions["all_versions"] = True
                entry = {
                    "vendor": vendor.replace("_", " "),
                    "product": product.replace("_", " "),
                    "versions": versions,
                }
                if entry not in products:
                    products.append(entry)
    return products[:12]


def _nvd_metric(item: dict) -> tuple[float | None, str | None]:
    metrics = item.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or (severity_from_cvss(score) if score is not None else None)
            return score, severity.lower() if isinstance(severity, str) else severity
    return None, None


def sync_nvd(db: Session, source: ThreatSource, days: int = 7) -> dict:
    started = time.time()
    end = utcnow()
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 100,
    }
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    try:
        response = _get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, headers=headers)
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        source.status = "unavailable"
        source.last_message = "NVD request failed; no records imported."
        source.latency_ms = int((time.time() - started) * 1000)
        db.commit()
        _log(db, "nvd", "error", "live", 0, 0, f"NVD request failed: {type(exc).__name__}. No records were written.", source.latency_ms)
        raise RuntimeError(f"NVD is currently unreachable ({type(exc).__name__}). Existing data was not modified.") from exc
    items = payload.get("vulnerabilities", [])
    new = 0
    considered = 0
    for entry in items[:60]:
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        considered += 1
        descriptions = cve.get("descriptions", [])
        description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
        score, severity = _nvd_metric(cve)
        published = cve.get("published")
        published_at = utcnow()
        try:
            from datetime import datetime
            published_at = datetime.fromisoformat(published.replace("Z", "+00:00")).replace(tzinfo=None) if published else utcnow()
        except (ValueError, AttributeError):
            pass
        affected = _extract_nvd_products(cve.get("configurations"))
        products = [f"{a['vendor']} {a['product']}" for a in affected]
        technology = products[0] if products else None
        version_text = ""
        if affected and affected[0]["versions"].get("exact"):
            version_text = ", ".join(affected[0]["versions"]["exact"][:3])
        elif affected and affected[0]["versions"].get("start"):
            version_text = f"{affected[0]['versions'].get('start')} – {affected[0]['versions'].get('end', 'latest')}"
        vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
        if not vuln:
            vuln = Vulnerability(
                cve_id=cve_id,
                title=(cve.get("descriptions") or [{}])[0].get("value", cve_id)[:255],
                description=description or "No English description supplied by NVD.",
                cvss_score=score,
                cvss_severity=severity or "unknown",
                published_at=published_at,
                modified_at=utcnow(),
                affected_products=affected,
                references=[{"label": ref.get("url", "")[:120], "url": ref.get("url", "")}
                            for ref in cve.get("references", [])[:6]],
                source="NVD",
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                remediation="Refer to vendor advisory and NVD reference links.",
                is_simulated=False,
            )
            db.add(vuln)
            db.flush()
            new += 1
        else:
            vuln.cvss_score = score or vuln.cvss_score
            vuln.cvss_severity = severity or vuln.cvss_severity
            vuln.modified_at = utcnow()
            vuln.affected_products = affected or vuln.affected_products
        existing_threat = db.query(Threat).filter(
            Threat.cve_id == cve_id, Threat.source == "NVD", Threat.is_simulated.is_(False)
        ).first()
        if not existing_threat:
            threat = Threat(
                ref=f"THR-{utcnow().year}-{db.query(Threat).count() + 1:04d}",
                name=f"{technology or cve_id} — {vuln.title}"[:238],
                category="Software Vulnerability",
                description=description or vuln.title,
                source="NVD",
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                published_at=published_at,
                updated_at=utcnow(),
                cve_id=cve_id,
                cvss_score=score,
                cvss_severity=severity or severity_from_cvss(score),
                affected_technology=technology,
                affected_versions=version_text,
                indicators=[],
                source_reliability=94,
                evidence_refs=[{"label": "NVD record", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}],
                recommended_action="Validate affected versions against the asset inventory and apply the vendor patch.",
                severity=severity or severity_from_cvss(score),
                status="new",
                is_simulated=False,
                retrieval_timestamp=utcnow(),
                created_at=utcnow(),
            )
            db.add(threat)
            db.flush()
            _risk_and_ai(threat, db)
            new += 1
    db.commit()
    source.status = "operational"
    source.last_sync_at = utcnow()
    source.last_success_at = utcnow()
    source.items_ingested = (source.items_ingested or 0) + new
    source.latency_ms = int((time.time() - started) * 1000)
    source.last_message = f"Fetched {considered} NVD records; {new} new records stored."
    db.commit()
    _log(db, "nvd", "success", "live", len(items), new, source.last_message, source.latency_ms)
    return {"source": "nvd", "mode": "live", "items_found": len(items), "items_new": new, "message": source.last_message}


def sync_cisa_kev(db: Session, source: ThreatSource) -> dict:
    started = time.time()
    try:
        response = _get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        source.status = "unavailable"
        source.last_message = "CISA KEV request failed; no records imported."
        source.latency_ms = int((time.time() - started) * 1000)
        db.commit()
        _log(db, "cisa_kev", "error", "live", 0, 0, f"CISA KEV request failed: {type(exc).__name__}.", source.latency_ms)
        raise RuntimeError(f"CISA KEV is currently unreachable ({type(exc).__name__}). Existing data was not modified.") from exc
    items = payload.get("vulnerabilities", [])
    cutoff = utcnow() - timedelta(days=45)
    recent = []
    for item in items:
        try:
            from datetime import datetime
            added = datetime.strptime(item.get("dateAdded", ""), "%Y-%m-%d")
        except ValueError:
            continue
        if added >= cutoff:
            recent.append((added, item))
    recent.sort(key=lambda x: x[0], reverse=True)
    new = 0
    for added, item in recent[:60]:
        cve_id = item.get("cveID", "")
        if not cve_id:
            continue
        vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
        if vuln:
            vuln.known_exploited = True
            vuln.ransomware_use = item.get("knownRansomwareCampaignUse") == "Known"
            try:
                from datetime import datetime
                vuln.kev_due_date = datetime.strptime(item.get("dueDate", ""), "%Y-%m-%d")
            except ValueError:
                pass
        else:
            vuln = Vulnerability(
                cve_id=cve_id,
                title=item.get("vulnerabilityName", cve_id)[:255],
                description=item.get("shortDescription", ""),
                cvss_score=None,
                cvss_severity="unknown",
                known_exploited=True,
                ransomware_use=item.get("knownRansomwareCampaignUse") == "Known",
                published_at=added,
                modified_at=utcnow(),
                affected_products=[],
                references=[{"label": "CISA KEV entry", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}],
                source="CISA KEV",
                source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                remediation=item.get("requiredAction", ""),
                is_simulated=False,
            )
            db.add(vuln)
            db.flush()
        exists = db.query(Threat).filter(
            Threat.cve_id == cve_id, Threat.source == "CISA KEV", Threat.is_simulated.is_(False)
        ).first()
        if not exists:
            threat = Threat(
                ref=f"THR-{utcnow().year}-{db.query(Threat).count() + 1:04d}",
                name=f"{item.get('vendorProject', '')} {item.get('product', '')} — {item.get('vulnerabilityName', cve_id)}"[:238].strip(),
                category="Software Vulnerability",
                description=item.get("shortDescription", ""),
                source="CISA KEV",
                source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                published_at=added,
                updated_at=utcnow(),
                cve_id=cve_id,
                known_exploited=True,
                affected_technology=item.get("product"),
                indicators=[],
                source_reliability=97,
                evidence_refs=[{"label": "CISA KEV catalogue", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}],
                recommended_action=item.get("requiredAction", "Apply vendor mitigations according to CISA guidance."),
                severity="high",
                status="new",
                is_simulated=False,
                retrieval_timestamp=utcnow(),
                created_at=utcnow(),
            )
            db.add(threat)
            db.flush()
            _risk_and_ai(threat, db)
            new += 1
    db.commit()
    source.status = "operational"
    source.last_sync_at = utcnow()
    source.last_success_at = utcnow()
    source.items_ingested = (source.items_ingested or 0) + new
    source.latency_ms = int((time.time() - started) * 1000)
    source.last_message = f"Fetched {len(items)} KEV entries; {new} new records stored."
    db.commit()
    _log(db, "cisa_kev", "success", "live", len(items), new, source.last_message, source.latency_ms)
    return {"source": "cisa_kev", "mode": "live", "items_found": len(items), "items_new": new, "message": source.last_message}


def sync_epss(db: Session, source: ThreatSource) -> dict:
    started = time.time()
    cves = [
        v.cve_id for v in db.query(Vulnerability)
        .filter(Vulnerability.is_simulated.is_(False))
        .order_by(Vulnerability.published_at.desc())
        .limit(40).all()
    ]
    if not cves:
        source.last_message = "No live vulnerability records available to enrich with EPSS."
        db.commit()
        _log(db, "epss", "skipped", "live", 0, 0, source.last_message, 0)
        return {"source": "epss", "mode": "live", "items_found": 0, "items_new": 0, "message": source.last_message}
    try:
        response = _get("https://api.first.org/data/v1/epss", params={"cve": ",".join(cves), "limit": 100})
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        source.status = "unavailable"
        source.last_message = "EPSS request failed; no scores updated."
        db.commit()
        _log(db, "epss", "error", "live", 0, 0, f"EPSS request failed: {type(exc).__name__}.", int((time.time() - started) * 1000))
        raise RuntimeError(f"FIRST EPSS is currently unreachable ({type(exc).__name__}). Existing scores were not modified.") from exc
    data = payload.get("data", [])
    updated = 0
    for entry in data:
        vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == entry.get("cve")).first()
        if vuln:
            try:
                vuln.epss_score = float(entry.get("epss"))
                vuln.epss_percentile = float(entry.get("percentile"))
                updated += 1
            except (TypeError, ValueError):
                continue
    db.commit()
    source.status = "operational"
    source.last_sync_at = utcnow()
    source.last_success_at = utcnow()
    source.items_ingested = (source.items_ingested or 0) + updated
    source.latency_ms = int((time.time() - started) * 1000)
    source.last_message = f"Updated EPSS scores for {updated} live vulnerability records."
    db.commit()
    _log(db, "epss", "success", "live", len(cves), updated, source.last_message, source.latency_ms)
    return {"source": "epss", "mode": "live", "items_found": len(cves), "items_new": updated, "message": source.last_message}


def sync_source(db: Session, key: str) -> dict:
    source = db.query(ThreatSource).filter(ThreatSource.key == key).first()
    if not source:
        raise LookupError("Unknown source")
    if not source.enabled:
        raise PermissionError("This connector is disabled in source management.")
    if source.requires_key and not source.key_configured:
        raise PermissionError("This connector requires an API key configured on the server. No secret is exposed to the browser.")
    if key == "nvd":
        return sync_nvd(db, source)
    if key == "cisa_kev":
        return sync_cisa_kev(db, source)
    if key == "epss":
        return sync_epss(db, source)
    raise PermissionError(
        "This connector is reference/manual-import only. No automated ingestion is performed to avoid fabricated records."
    )


def enrich_indicator(indicator_type: str, value: str) -> dict:
    """Optional server-side enrichment. Keys never leave the backend."""
    results = []
    if indicator_type == "ip" and settings.abuseipdb_api_key:
        try:
            response = _get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": value, "maxAgeInDays": 90},
                headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            )
            data = response.json().get("data", {})
            results.append({"source": "AbuseIPDB", "status": "ok", "score": data.get("abuseConfidenceScore"),
                            "reports": data.get("totalReports"), "country": data.get("countryCode")})
        except (httpx.HTTPError, ValueError):
            results.append({"source": "AbuseIPDB", "status": "unavailable"})
    if indicator_type == "ip" and settings.greynoise_api_key:
        try:
            response = _get(f"https://api.greynoise.io/v3/community/{value}", headers={"key": settings.greynoise_api_key})
            data = response.json()
            results.append({"source": "GreyNoise", "status": "ok", "classification": data.get("classification"),
                            "noise": data.get("noise"), "riot": data.get("riot")})
        except (httpx.HTTPError, ValueError):
            results.append({"source": "GreyNoise", "status": "unavailable"})
    if settings.virustotal_api_key:
        try:
            if indicator_type == "ip":
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
            elif indicator_type == "domain":
                url = f"https://www.virustotal.com/api/v3/domains/{value}"
            elif indicator_type == "sha256":
                url = f"https://www.virustotal.com/api/v3/files/{value}"
            else:
                url = f"https://www.virustotal.com/api/v3/urls/{value}"
            response = _get(url, headers={"x-apikey": settings.virustotal_api_key})
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            results.append({"source": "VirusTotal", "status": "ok", "malicious": stats.get("malicious"),
                            "suspicious": stats.get("suspicious"), "reputation": data.get("reputation")})
        except (httpx.HTTPError, ValueError):
            results.append({"source": "VirusTotal", "status": "unavailable"})
    if indicator_type == "ip" and settings.otx_api_key:
        try:
            response = _get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{value}/general",
                headers={"X-OTX-API-KEY": settings.otx_api_key},
            )
            data = response.json()
            results.append({"source": "AlienVault OTX", "status": "ok", "pulses": data.get("pulse_info", {}).get("count")})
        except (httpx.HTTPError, ValueError):
            results.append({"source": "AlienVault OTX", "status": "unavailable"})
    if not results:
        return {
            "configured": False,
            "message": "No enrichment provider is configured. Add server-side API keys in .env; keys are never exposed to the frontend.",
            "results": [],
        }
    return {
        "configured": True,
        "message": "Enrichment results from configured providers. Unavailable providers are reported explicitly and are never filled in with invented values.",
        "results": results,
    }
