"""JSON serialisers for SQLAlchemy records."""
from datetime import datetime


def iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def org_out(org) -> dict | None:
    if not org:
        return None
    return {"id": org.id, "name": org.name, "sector": org.sector, "country": org.country}


def user_out(user) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "organisation": org_out(user.organisation),
        "organisation_id": user.organisation_id,
        "is_active": user.is_active,
        "notification_email": user.notification_email,
        "notification_critical_only": user.notification_critical_only,
        "created_at": iso(user.created_at),
        "last_login_at": iso(user.last_login_at),
        "initials": "".join(part[0] for part in user.full_name.split()[:2]).upper(),
    }


def threat_out(threat, detailed: bool = False) -> dict:
    data = {
        "id": threat.id,
        "ref": threat.ref,
        "name": threat.name,
        "category": threat.category,
        "ai_category": threat.ai_category,
        "description": threat.description,
        "source": threat.source,
        "source_url": threat.source_url,
        "published_at": iso(threat.published_at),
        "updated_at": iso(threat.updated_at),
        "cve_id": threat.cve_id,
        "cvss_score": threat.cvss_score,
        "cvss_severity": threat.cvss_severity,
        "epss_score": threat.epss_score,
        "known_exploited": threat.known_exploited,
        "affected_technology": threat.affected_technology,
        "affected_versions": threat.affected_versions,
        "indicators": threat.indicators or [],
        "indicator_count": len(threat.indicators or []),
        "source_reliability": threat.source_reliability,
        "evidence_refs": threat.evidence_refs or [],
        "ai_summary": threat.ai_summary,
        "ai_confidence": threat.ai_confidence,
        "ai_keywords": threat.ai_keywords or [],
        "ai_entities": threat.ai_entities or {},
        "ai_explanation": threat.ai_explanation or {},
        "ai_method": threat.ai_method,
        "risk_score": threat.risk_score,
        "risk_category": threat.risk_category,
        "confidence": threat.confidence,
        "urgency": threat.urgency,
        "exploitation_status": threat.exploitation_status,
        "recommended_action": threat.recommended_action,
        "severity": threat.severity,
        "status": threat.status,
        "assigned_to": threat.assigned_to,
        "is_saved": threat.is_saved,
        "retrieval_timestamp": iso(threat.retrieval_timestamp),
        "created_at": iso(threat.created_at),
    }
    if detailed:
        data["description"] = threat.description
    return data


def vuln_out(vuln, detailed: bool = False) -> dict:
    data = {
        "id": vuln.id,
        "cve_id": vuln.cve_id,
        "title": vuln.title,
        "description": vuln.description if detailed else (vuln.description[:280] + ("…" if len(vuln.description) > 280 else "")),
        "cvss_score": vuln.cvss_score,
        "cvss_severity": vuln.cvss_severity,
        "epss_score": vuln.epss_score,
        "epss_percentile": vuln.epss_percentile,
        "known_exploited": vuln.known_exploited,
        "kev_due_date": iso(vuln.kev_due_date),
        "ransomware_use": vuln.ransomware_use,
        "published_at": iso(vuln.published_at),
        "modified_at": iso(vuln.modified_at),
        "affected_products": vuln.affected_products or [],
        "references": vuln.references or [],
        "source": vuln.source,
        "source_url": vuln.source_url,
        "remediation": vuln.remediation,
    }
    if detailed:
        data["description"] = vuln.description
    return data


def asset_out(asset, include_risk: dict | None = None) -> dict:
    data = {
        "id": asset.id,
        "ref": asset.ref,
        "name": asset.name,
        "category": asset.category,
        "organisation": org_out(asset.organisation),
        "organisation_id": asset.organisation_id,
        "identifier": asset.identifier,
        "software": asset.software,
        "software_version": asset.software_version,
        "os": asset.os,
        "exposure": asset.exposure,
        "internet_facing": asset.internet_facing,
        "criticality": asset.criticality,
        "business_importance": asset.business_importance,
        "owner": asset.owner,
        "last_assessed_at": iso(asset.last_assessed_at),
        "notes": asset.notes,
        "created_at": iso(asset.created_at),
    }
    if include_risk:
        data["risk"] = include_risk
    return data


def alert_out(alert, detailed: bool = False) -> dict:
    data = {
        "id": alert.id,
        "ref": alert.ref,
        "title": alert.title,
        "severity": alert.severity,
        "category": alert.category,
        "detected_at": iso(alert.detected_at),
        "threat_id": alert.threat_id,
        "vulnerability_id": alert.vulnerability_id,
        "asset_ids": alert.asset_ids or [],
        "source": alert.source,
        "risk_score": alert.risk_score,
        "confidence": alert.confidence,
        "trigger_reason": alert.trigger_reason,
        "evidence": alert.evidence or [],
        "recommended_action": alert.recommended_action,
        "status": alert.status,
        "assignee_id": alert.assignee_id,
        "acknowledged_at": iso(alert.acknowledged_at),
        "resolved_at": iso(alert.resolved_at),
        "rule_key": alert.rule_key,
        "created_at": iso(alert.created_at),
    }
    if detailed:
        data["evidence"] = alert.evidence or []
    return data


def recommendation_out(rec) -> dict:
    return {
        "id": rec.id,
        "ref": rec.ref,
        "title": rec.title,
        "reason": rec.reason,
        "priority": rec.priority,
        "threat_id": rec.threat_id,
        "vulnerability_id": rec.vulnerability_id,
        "asset_id": rec.asset_id,
        "alert_id": rec.alert_id,
        "action": rec.action,
        "evidence": rec.evidence or [],
        "status": rec.status,
        "owner_id": rec.owner_id,
        "due_at": iso(rec.due_at),
        "source_url": rec.source_url,
        "created_at": iso(rec.created_at),
    }


def note_out(note, user=None) -> dict:
    return {
        "id": note.id,
        "body": note.body,
        "created_at": iso(note.created_at),
        "author": {"full_name": user.full_name, "role": user.role, "initials": "".join(p[0] for p in user.full_name.split()[:2]).upper()} if user else None,
        "threat_id": note.threat_id,
        "alert_id": note.alert_id,
        "asset_id": note.asset_id,
    }


def assessment_out(record, threat=None, asset=None, vulnerability=None) -> dict:
    return {
        "id": record.id,
        "ref": record.ref,
        "threat_id": record.threat_id,
        "vulnerability_id": record.vulnerability_id,
        "asset_id": record.asset_id,
        "severity": record.severity,
        "exploitability": record.exploitability,
        "exposure": record.exposure,
        "asset_criticality": record.asset_criticality,
        "evidence_strength": record.evidence_strength,
        "risk_score": record.risk_score,
        "risk_category": record.risk_category,
        "urgency": record.urgency,
        "exploitation_status": record.exploitation_status,
        "evidence_confidence": record.evidence_confidence,
        "factors": record.factors or [],
        "explanation": record.explanation,
        "model_version": record.model_version,
        "created_by": record.created_by,
        "created_at": iso(record.created_at),
        "threat": {
            "id": threat.id,
            "ref": threat.ref,
            "name": threat.name,
            "severity": threat.severity,
            "cve_id": threat.cve_id,
            "cvss_score": threat.cvss_score,
            "epss_score": threat.epss_score,
            "known_exploited": threat.known_exploited,
            "source": threat.source,
        } if threat else None,
        "asset": {"ref": asset.ref, "name": asset.name, "category": asset.category, "criticality": asset.criticality} if asset else None,
        "vulnerability": {"cve_id": vulnerability.cve_id, "title": vulnerability.title, "cvss": vulnerability.cvss_score} if vulnerability else None,
    }


def source_out(source) -> dict:
    return {
        "id": source.id,
        "key": source.key,
        "name": source.name,
        "description": source.description,
        "url": source.url,
        "category": source.category,
        "requires_key": source.requires_key,
        "key_configured": source.key_configured,
        "enabled": source.enabled,
        "status": source.status,
        "reliability": source.reliability,
        "last_sync_at": iso(source.last_sync_at),
        "last_success_at": iso(source.last_success_at),
        "items_ingested": source.items_ingested,
        "latency_ms": source.latency_ms,
        "last_message": source.last_message,
    }


def audit_out(record) -> dict:
    return {
        "id": record.id,
        "user_email": record.user_email,
        "action": record.action,
        "entity_type": record.entity_type,
        "entity_id": record.entity_id,
        "detail": record.detail,
        "ip_address": record.ip_address,
        "created_at": iso(record.created_at),
    }


def ingestion_out(log) -> dict:
    return {
        "id": log.id,
        "source_key": log.source_key,
        "started_at": iso(log.started_at),
        "finished_at": iso(log.finished_at),
        "status": log.status,
        "mode": log.mode,
        "items_found": log.items_found,
        "items_new": log.items_new,
        "message": log.message,
        "duration_ms": log.duration_ms,
    }
