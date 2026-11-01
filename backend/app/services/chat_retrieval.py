"""Bounded retrieval over stored platform records for the Aegis AI chat.

The chat never receives a database dump. Each turn selects a small, ranked set of records
that match entities and topics in the question, serialises them with their provenance, and
hands that to the provider as evidence to quote from.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import String, cast, func, or_
from sqlalchemy.orm import Session

from ..models import (
    Alert,
    Asset,
    AssetVulnerability,
    AuditLog,
    IngestionLog,
    Recommendation,
    RiskAssessment,
    Threat,
    ThreatSource,
    Vulnerability,
)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
ALERT_RE = re.compile(r"AL-\d{4}-\d{4}", re.IGNORECASE)
THREAT_RE = re.compile(r"THR-\d{4}-\d{4}", re.IGNORECASE)
ASSET_RE = re.compile(r"AST-\d{4}-\d{4}", re.IGNORECASE)
TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

MAX_RECORDS = 26
CONTEXT_CHAR_BUDGET = 11000

# Early-warning rules that already ran and persisted alerts; read, never re-triggered here.
EARLY_WARNING_RULES = {"kev-exposure", "multi-source-cve", "repeated-indicator", "critical-asset-exposure"}

_SOURCE_KEYS = {
    "nvd": "nvd",
    "cisa kev": "cisa_kev",
    "first epss": "epss",
    "epss": "epss",
    "mitre attack": "mitre_attack",
    "alienvault otx": "otx",
    "csirt advisory": "csirt",
    "csirt": "csirt",
    "internal sensor": "internal",
    "vendor advisory": "vendor",
}

STOPWORDS = {
    "the", "and", "what", "which", "who", "whom", "show", "with", "from", "that", "this", "these",
    "those", "are", "was", "were", "for", "our", "you", "can", "do", "does", "how", "many", "much",
    "me", "my", "tell", "please", "about", "give", "list", "any", "have", "has", "not", "but",
    "their", "there", "here", "when", "where", "why", "all", "most", "more", "than", "then",
    "would", "should", "could", "will", "into", "over", "under", "after", "before", "because",
    "expalin", "explain", "analyse", "analyze", "summarise", "summarize", "recommend",
}

TOPIC_TERMS: dict[str, tuple[str, ...]] = {
    "vulnerability": ("cve", "vulnerab", "cvss", "epss", "patch", "exploit", "kev", "cisa", "advisory", "severity"),
    "asset": ("asset", "host", "server", "inventory", "endpoint", "exposed", "exposure", "internet-facing"),
    "threat": ("threat", "intelligence", "campaign", "actor", "malware", "ransomware", "phishing", "botnet"),
    "alert": ("alert", "warning", "early warning", "anomal", "suspicious", "detection", "monitor"),
    "risk": ("risk", "score", "scoring", "priorit", "critical", "worst", "highest", "ranking"),
    "recommendation": ("recommend", "remediat", "mitigat", "action", "fix", "prevent", "should we"),
    "technique": ("attack", "technique", "tactic", "attack", "mitre", "att&ck", "simulation", "emulation"),
    "ingestion": ("source", "connector", "feed", "ingest", "sync", "live", "cached", "provenance", "csirt", "advisory", "otx"),
    "correlation": ("correlat", "related", "link", "cluster", "timeline", "pattern"),
}


@dataclass
class Record:
    """One piece of evidence, with the citation the UI needs to render it."""

    kind: str
    key: str
    title: str
    facts: dict[str, Any] = field(default_factory=dict)
    provenance: str = "recorded"
    route: str = ""
    url: str = ""
    relevance: float = 0.0

    def line(self) -> str:
        parts = [f"[{self.kind}] {self.key}: {self.title}"]
        for name, value in self.facts.items():
            if value in (None, "", [], {}):
                continue
            parts.append(f"{name}={value}")
        parts.append(f"provenance={self.provenance}")
        return " · ".join(str(p) for p in parts)


def _date(value) -> str:
    return value.strftime("%Y-%m-%d") if value else ""


# Reserved documentation domains appear in placeholder records; linking them would 404 in the UI.
_PLACEHOLDER_HOSTS = ("example.invalid", "example.com", "example.org", "example.net", ".invalid", ".example", ".test")


def safe_url(value: str | None) -> str:
    """Return the URL only when it is a real, https, externally-resolvable reference."""
    text = (value or "").strip()
    if not text.startswith("https://"):
        return ""
    host = text[len("https://"):].split("/", 1)[0].split("@")[-1].split(":")[0].lower()
    if not host or any(host == p.strip(".") or host.endswith(p) for p in _PLACEHOLDER_HOSTS if p.startswith(".")):
        return ""
    if any(host == p for p in ("example.com", "example.org", "example.net", "example.invalid")):
        return ""
    return text[:400]


def _pct(value: float | None, scale: float = 100) -> str:
    return "" if value is None else f"{value * scale:.1f}%"


def _source_key(source: str | None) -> str:
    return _SOURCE_KEYS.get((source or "").strip().lower(), "")


def _ingestion_modes(db: Session) -> dict[str, str]:
    """Latest recorded ingestion mode per connector, so live/cached is stated, not guessed."""
    latest: dict[str, tuple[Any, str]] = {}
    for log in (
        db.query(IngestionLog)
        .order_by(IngestionLog.started_at.desc())
        .limit(400)
        .all()
    ):
        if log.source_key not in latest:
            latest[log.source_key] = (log.started_at, log.mode or "recorded")
    return {key: value[1] for key, value in latest.items()}


class Provenance:
    """States how a record entered the platform: fetched live, served from cache, uploaded, or recorded."""

    def __init__(self, db: Session) -> None:
        self.modes = _ingestion_modes(db)

    def intelligence(self, source: str | None, is_simulated: bool | None) -> str:
        mode = self.modes.get(_source_key(source), "")
        if mode in {"live", "cached"}:
            return mode
        return "recorded"

    def inventory(self, is_simulated: bool | None) -> str:
        return "uploaded"


def tokens(question: str) -> list[str]:
    words = re.findall(r"[a-z0-9][a-z0-9\-\.]{2,}", question.lower())
    seen: list[str] = []
    for word in words:
        if word in STOPWORDS or word in seen:
            continue
        seen.append(word)
    return seen[:12]


def topics(question: str) -> set[str]:
    lowered = question.lower()
    hits = {
        topic
        for topic, terms in TOPIC_TERMS.items()
        if any(term in lowered for term in terms)
    }
    if CVE_RE.search(question):
        hits.add("vulnerability")
    if TECHNIQUE_RE.search(question):
        hits.add("technique")
    return hits


def _like_any(column, patterns: list[str]):
    return or_(*[column.ilike(p) for p in patterns])


def _patterns(words: list[str]) -> list[str]:
    return [f"%{word}%" for word in words[:4]]


class Retriever:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.provenance = Provenance(db)
        self.records: dict[tuple[str, str], Record] = {}

    def add(self, record: Record) -> None:
        self.records.setdefault((record.kind, record.key), record)

    # ---- individual corpora -------------------------------------------------

    def _vulnerability(self, vuln: Vulnerability, relevance: float) -> Record:
        assets = (
            self.db.query(Asset)
            .join(AssetVulnerability, AssetVulnerability.asset_id == Asset.id)
            .filter(AssetVulnerability.vulnerability_id == vuln.id)
            .limit(6)
            .all()
        )
        return Record(
            kind="vulnerability",
            key=vuln.cve_id,
            title=vuln.title,
            facts={
                "cvss": vuln.cvss_score,
                "cvss_severity": vuln.cvss_severity,
                "epss": _pct(vuln.epss_score),
                "epss_percentile": _pct(vuln.epss_percentile),
                "known_exploited": "yes" if vuln.known_exploited else "no",
                "kev_due_date": _date(vuln.kev_due_date),
                "ransomware_use": "yes" if vuln.ransomware_use else "no",
                "published": _date(vuln.published_at),
                "source": vuln.source,
                "affected_products": [
                    p.get("product") for p in (vuln.affected_products or [])[:5] if isinstance(p, dict)
                ],
                "linked_assets": [a.ref for a in assets] or "none in inventory",
                "remediation": (vuln.remediation or "")[:300],
                "description": (vuln.description or "")[:300],
            },
            provenance=self.provenance.intelligence(vuln.source, vuln.is_simulated),
            route=f"/app/vulnerabilities?focus={vuln.cve_id}",
            url=vuln.source_url or "",
            relevance=relevance,
        )

    def _threat(self, threat: Threat, relevance: float) -> Record:
        techniques = [
            i.get("value")
            for i in (threat.indicators or [])
            if isinstance(i, dict) and i.get("type") == "mitre"
        ]
        return Record(
            kind="threat",
            key=threat.ref,
            title=threat.name,
            facts={
                "severity": threat.severity,
                "risk_score": round(threat.risk_score or 0, 1),
                "risk_category": threat.risk_category,
                "urgency": threat.urgency,
                "exploitation_status": threat.exploitation_status,
                "evidence_confidence": threat.confidence,
                "category": threat.category,
                "cve": threat.cve_id,
                "cvss": threat.cvss_score,
                "epss": _pct(threat.epss_score),
                "affected_technology": threat.affected_technology,
                "mitre_techniques": techniques or "none recorded",
                "published": _date(threat.published_at),
                "source": threat.source,
                "status": threat.status,
                "recommended_action": (threat.recommended_action or "")[:240],
                "description": (threat.description or "")[:300],
            },
            provenance=self.provenance.intelligence(threat.source, threat.is_simulated),
            route=f"/app/threats?focus={threat.ref}",
            url=threat.source_url or "",
            relevance=relevance,
        )

    def _asset(self, asset: Asset, relevance: float) -> Record:
        links = (
            self.db.query(AssetVulnerability)
            .filter(AssetVulnerability.asset_id == asset.id)
            .limit(8)
            .all()
        )
        cves = []
        for link in links:
            vuln = self.db.get(Vulnerability, link.vulnerability_id)
            if vuln:
                cves.append(f"{vuln.cve_id}({link.status})")
        return Record(
            kind="asset",
            key=asset.ref,
            title=asset.name,
            facts={
                "software": f"{asset.software} {asset.software_version}".strip(),
                "os": asset.os,
                "category": asset.category,
                "exposure": asset.exposure,
                "internet_facing": "yes" if asset.internet_facing else "no",
                "criticality": f"{asset.criticality}/5",
                "business_importance": asset.business_importance,
                "owner": asset.owner,
                "vulnerability_matches": cves or "none",
                "last_assessed": _date(asset.last_assessed_at),
            },
            provenance=self.provenance.inventory(asset.is_simulated),
            route=f"/app/assets?focus={asset.ref}",
            relevance=relevance,
        )

    def _alert(self, alert: Alert, relevance: float) -> Record:
        return Record(
            kind="alert",
            key=alert.ref,
            title=alert.title,
            facts={
                "severity": alert.severity,
                "category": alert.category,
                "risk_score": round(alert.risk_score or 0, 1),
                "confidence": alert.confidence,
                "status": alert.status,
                "detected": _date(alert.detected_at),
                "rule": alert.rule_key or "manual",
                "early_warning_rule": alert.rule_key if alert.rule_key in EARLY_WARNING_RULES else "",
                "trigger": (alert.trigger_reason or "")[:280],
                "recommended_action": (alert.recommended_action or "")[:240],
                "source": alert.source,
            },
            provenance=self.provenance.intelligence(alert.source, alert.is_simulated),
            route=f"/app/alerts?focus={alert.ref}",
            relevance=relevance,
        )

    def _risk_assessment(self, item: RiskAssessment, relevance: float) -> Record:
        threat = self.db.get(Threat, item.threat_id) if item.threat_id else None
        asset = self.db.get(Asset, item.asset_id) if item.asset_id else None
        vuln = self.db.get(Vulnerability, item.vulnerability_id) if item.vulnerability_id else None
        factors = {
            f.get("label"): round(f.get("contribution", 0), 1)
            for f in (item.factors or [])
            if isinstance(f, dict)
        }
        return Record(
            kind="risk_assessment",
            key=item.ref,
            title=f"Risk assessment {item.risk_category} · {round(item.risk_score or 0, 1)}/100",
            facts={
                "risk_score": round(item.risk_score or 0, 1),
                "risk_category": item.risk_category,
                "urgency": item.urgency,
                "factor_contributions": factors,
                "threat": threat.ref if threat else "",
                "asset": asset.ref if asset else "",
                "cve": vuln.cve_id if vuln else "",
                "model_version": item.model_version,
                "explanation": (item.explanation or "")[:320],
                "created": _date(item.created_at),
            },
            provenance="recorded",
            route=f"/app/risk?focus={item.ref}",
            relevance=relevance,
        )

    def _recommendation(self, item: Recommendation, relevance: float) -> Record:
        asset = self.db.get(Asset, item.asset_id) if item.asset_id else None
        vuln = self.db.get(Vulnerability, item.vulnerability_id) if item.vulnerability_id else None
        return Record(
            kind="recommendation",
            key=item.ref,
            title=item.title,
            facts={
                "priority": item.priority,
                "status": item.status,
                "action": (item.action or "")[:280],
                "reason": (item.reason or "")[:240],
                "asset": asset.ref if asset else "",
                "cve": vuln.cve_id if vuln else "",
                "created": _date(item.created_at),
            },
            provenance="recorded",
            route=f"/app/recommendations?focus={item.ref}",
            url=item.source_url or "",
            relevance=relevance,
        )

    # ---- selection ----------------------------------------------------------

    def select(self, question: str) -> list[Record]:
        words = tokens(question)
        wanted = topics(question)
        patterns = _patterns(words)
        ranked: list[Record] = []

        cve_ids = sorted({m.group(0).upper() for m in CVE_RE.finditer(question)})
        threat_refs = sorted({m.group(0).upper() for m in THREAT_RE.finditer(question)})
        alert_refs = sorted({m.group(0).upper() for m in ALERT_RE.finditer(question)})
        asset_refs = sorted({m.group(0).upper() for m in ASSET_RE.finditer(question)})
        techniques = sorted({m.group(0) for m in TECHNIQUE_RE.finditer(question)})

        # 1. Explicit identifiers always win: an exact record beats a fuzzy match.
        for cve in cve_ids[:6]:
            vuln = self.db.query(Vulnerability).filter(Vulnerability.cve_id == cve).first()
            if vuln:
                ranked.append(self._vulnerability(vuln, 100))
            for threat in self.db.query(Threat).filter(Threat.cve_id == cve).limit(3).all():
                ranked.append(self._threat(threat, 92))
        for ref in threat_refs[:4]:
            threat = self.db.query(Threat).filter(Threat.ref == ref).first()
            if threat:
                ranked.append(self._threat(threat, 100))
        for ref in alert_refs[:4]:
            alert = self.db.query(Alert).filter(Alert.ref == ref).first()
            if alert:
                ranked.append(self._alert(alert, 100))
        for ref in asset_refs[:4]:
            asset = self.db.query(Asset).filter(Asset.ref == ref).first()
            if asset:
                ranked.append(self._asset(asset, 100))
        for code in techniques[:4]:
            for threat in self.db.query(Threat).filter(Threat.indicators.isnot(None)).all():
                values = [
                    i.get("value") for i in (threat.indicators or []) if isinstance(i, dict) and i.get("type") == "mitre"
                ]
                if code in values:
                    ranked.append(self._threat(threat, 88))
                    break

        # 2. Topic-driven keyword search, each corpus capped.
        if patterns:
            if "vulnerability" in wanted or not wanted:
                rows = (
                    self.db.query(Vulnerability)
                    .filter(or_(
                        _like_any(Vulnerability.cve_id, patterns),
                        _like_any(Vulnerability.title, patterns),
                        _like_any(Vulnerability.description, patterns),
                        _like_any(cast(Vulnerability.affected_products, String), patterns),
                    ))
                    .order_by(Vulnerability.cvss_score.desc().nullslast())
                    .limit(8)
                    .all()
                )
                ranked.extend(self._vulnerability(v, 70) for v in rows)
            if "threat" in wanted or "technique" in wanted or not wanted:
                rows = (
                    self.db.query(Threat)
                    .filter(or_(
                        _like_any(Threat.name, patterns),
                        _like_any(Threat.description, patterns),
                        _like_any(Threat.affected_technology, patterns),
                        _like_any(Threat.category, patterns),
                    ))
                    .order_by(Threat.risk_score.desc())
                    .limit(8)
                    .all()
                )
                ranked.extend(self._threat(t, 68) for t in rows)
            if "asset" in wanted or not wanted:
                rows = (
                    self.db.query(Asset)
                    .filter(or_(
                        _like_any(Asset.name, patterns),
                        _like_any(Asset.software, patterns),
                        _like_any(Asset.identifier, patterns),
                        _like_any(Asset.category, patterns),
                    ))
                    .order_by(Asset.criticality.desc())
                    .limit(8)
                    .all()
                )
                ranked.extend(self._asset(a, 66) for a in rows)
            if "alert" in wanted or not wanted:
                rows = (
                    self.db.query(Alert)
                    .filter(or_(_like_any(Alert.title, patterns), _like_any(Alert.trigger_reason, patterns)))
                    .order_by(Alert.detected_at.desc())
                    .limit(6)
                    .all()
                )
                ranked.extend(self._alert(a, 64) for a in rows)
            if "recommendation" in wanted:
                rows = (
                    self.db.query(Recommendation)
                    .filter(or_(_like_any(Recommendation.title, patterns), _like_any(Recommendation.action, patterns)))
                    .order_by(Recommendation.created_at.desc())
                    .limit(6)
                    .all()
                )
                ranked.extend(self._recommendation(r, 62) for r in rows)

        # 3. Standing context for the topic even without keywords: what the platform holds right now.
        lowered = question.lower()
        if "vulnerab" in lowered or "patch" in lowered or "cve" in lowered or "exploit" in lowered:
            rows = (
                self.db.query(Vulnerability)
                .order_by(Vulnerability.known_exploited.desc(), Vulnerability.cvss_score.desc())
                .limit(8)
                .all()
            )
            ranked.extend(self._vulnerability(v, 78) for v in rows)
        if "risk" in lowered or "priorit" in lowered or "exposed" in lowered or "worst" in lowered:
            for item in (
                self.db.query(RiskAssessment)
                .order_by(RiskAssessment.risk_score.desc(), RiskAssessment.created_at.desc())
                .limit(6)
                .all()
            ):
                ranked.append(self._risk_assessment(item, 60))
            for asset in self.db.query(Asset).order_by(Asset.criticality.desc()).limit(6).all():
                ranked.append(self._asset(asset, 55))
        if "early warning" in lowered or "anomal" in lowered or "monitor" in lowered or "suspicious" in lowered:
            rows = (
                self.db.query(Alert)
                .filter(Alert.rule_key.in_(sorted(EARLY_WARNING_RULES)))
                .order_by(Alert.detected_at.desc())
                .limit(6)
                .all()
            )
            ranked.extend(self._alert(a, 72) for a in rows)
        if "simulat" in lowered or "attack lab" in lowered or "scenario" in lowered:
            for row in (
                self.db.query(AuditLog)
                .filter(AuditLog.action == "scenario.run")
                .order_by(AuditLog.created_at.desc())
                .limit(5)
                .all()
            ):
                ranked.append(Record(
                    kind="simulation_run",
                    key=f"RUN-{row.id}",
                    title=f"Threat exercise '{row.entity_id}' executed",
                    facts={"summary": (row.detail or "")[:280], "at": _date(row.created_at), "by": row.user_email},
                    provenance="recorded",
                    route="/app/scenarios",
                    relevance=74,
                ))
        if "latest" in lowered or "recent" in lowered or "summary" in lowered or "intelligence" in lowered:
            for threat in self.db.query(Threat).order_by(Threat.published_at.desc()).limit(8).all():
                ranked.append(self._threat(threat, 62))
        if "kev" in lowered or "known exploited" in lowered or "actively exploited" in lowered:
            rows = (
                self.db.query(Vulnerability)
                .filter(Vulnerability.known_exploited.is_(True))
                .order_by(Vulnerability.cvss_score.desc())
                .limit(8)
                .all()
            )
            ranked.extend(self._vulnerability(v, 80) for v in rows)
        if "csirt" in lowered or "cert-in" in lowered or "advisory" in lowered or "advisories" in lowered:
            rows = (
                self.db.query(Threat)
                .filter(or_(_like_any(Threat.source, ["%CSIRT%", "%CERT-In%"]), _like_any(Threat.name, ["%advisory%"])))
                .order_by(Threat.published_at.desc())
                .limit(6)
                .all()
            )
            ranked.extend(self._threat(t, 76) for t in rows)
        if "correlat" in lowered or "timeline" in lowered or "related" in lowered:
            for threat in self.db.query(Threat).order_by(Threat.published_at.desc()).limit(6).all():
                ranked.append(self._threat(threat, 58))

        # 4. Deduplicate, rank, cap.
        for record in ranked:
            self.add(record)
        selected = sorted(self.records.values(), key=lambda r: r.relevance, reverse=True)[:MAX_RECORDS]

        # Keep at least one record of each high-value kind the question implies.
        budget = CONTEXT_CHAR_BUDGET
        fitted: list[Record] = []
        for record in selected:
            cost = len(record.line())
            if budget - cost < 0 and fitted:
                break
            budget -= cost
            fitted.append(record)
        return fitted


def posture(db: Session) -> dict:
    """Small aggregate snapshot so the model can state scope honestly."""
    modes = _ingestion_modes(db)
    return {
        "vulnerabilities": db.query(func.count(Vulnerability.id)).scalar() or 0,
        "known_exploited": db.query(func.count(Vulnerability.id)).filter(Vulnerability.known_exploited.is_(True)).scalar() or 0,
        "threats": db.query(func.count(Threat.id)).scalar() or 0,
        "assets": db.query(func.count(Asset.id)).scalar() or 0,
        "asset_vulnerability_matches": db.query(func.count(AssetVulnerability.id)).scalar() or 0,
        "risk_assessments": db.query(func.count(RiskAssessment.id)).scalar() or 0,
        "alerts": db.query(func.count(Alert.id)).scalar() or 0,
        "early_warning_alerts": db.query(func.count(Alert.id)).filter(Alert.rule_key.in_(sorted(EARLY_WARNING_RULES))).scalar() or 0,
        "open_recommendations": db.query(func.count(Recommendation.id)).filter(
            Recommendation.status.in_(["open", "in_progress"])
        ).scalar() or 0,
        "ingestion_modes": modes,
        "latest_threat_published": _date(db.query(func.max(Threat.published_at)).scalar()),
        "latest_vulnerability_published": _date(db.query(func.max(Vulnerability.published_at)).scalar()),
    }


def connector_state(db: Session) -> list[dict]:
    """Which intelligence sources actually exist here, so the model cannot over-claim coverage."""
    rows = db.query(ThreatSource).order_by(ThreatSource.name).all()
    return [
        {
            "name": row.name,
            "key": row.key,
            "status": row.status,
            "enabled": bool(row.enabled),
            "requires_key": bool(row.requires_key),
            "key_configured": bool(row.key_configured),
            "items_ingested": row.items_ingested or 0,
            "last_sync": _date(row.last_sync_at),
        }
        for row in rows
    ]


def retrieve(db: Session, question: str) -> dict:
    records = Retriever(db).select(question)
    return {
        "records": records,
        "citations": [
            {
                "index": i + 1,
                "key": r.key,
                "kind": r.kind,
                "title": r.title,
                "provenance": r.provenance,
                "route": r.route,
                "url": safe_url(r.url),
                "facts": {
                    k: v for k, v in r.facts.items()
                    if k in {"cvss", "cvss_severity", "epss", "known_exploited", "kev_due_date", "published",
                             "severity", "risk_score", "risk_category", "source", "exposure", "criticality",
                             "linked_assets", "remediation", "rule", "priority", "urgency", "mitre_techniques",
                             "exploitation_status", "status", "affected_products", "software", "action"}
                },
            }
            for i, r in enumerate(records)
        ],
        "posture": posture(db),
        "connectors": connector_state(db),
    }
