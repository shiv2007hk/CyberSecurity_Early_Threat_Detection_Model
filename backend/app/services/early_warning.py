"""Rule + statistical early-warning engine with evidence traceability."""
import hashlib
import math
from collections import Counter, defaultdict
from datetime import timedelta

from sqlalchemy.orm import Session

from ..models import Alert, Asset, AssetVulnerability, Recommendation, Threat, Vulnerability, utcnow
from .refs import next_ref

MAX_NEW_ALERTS = 10


def fingerprint(rule_key: str, entity: str) -> str:
    return hashlib.sha1(f"{rule_key}|{entity}".lower().encode()).hexdigest()[:40]


def _next_ref(db: Session) -> str:
    count = db.query(Alert).count() + 1
    while db.query(Alert).filter(Alert.ref == f"AL-{utcnow().year}-{count:04d}").first():
        count += 1
    return f"AL-{utcnow().year}-{count:04d}"


def _maybe_alert(db: Session, *, rule_key: str, entity: str, title: str, severity: str, category: str,
                 threat: Threat | None, vulnerability: Vulnerability | None, assets: list[Asset],
                 source: str, risk_score: float, confidence: float, trigger: str, evidence: list[dict],
                 action: str, is_simulated: bool) -> Alert | None:
    fp = fingerprint(rule_key, entity)
    existing = (
        db.query(Alert)
        .filter(Alert.fingerprint == fp, Alert.created_at >= utcnow() - timedelta(days=7))
        .first()
    )
    if existing:
        return None
    alert = Alert(
        ref=_next_ref(db),
        title=title,
        severity=severity,
        category=category,
        detected_at=utcnow(),
        threat_id=threat.id if threat else None,
        vulnerability_id=vulnerability.id if vulnerability else None,
        asset_ids=[a.id for a in assets],
        source=source,
        risk_score=round(risk_score, 1),
        confidence=round(confidence, 1),
        trigger_reason=trigger,
        evidence=evidence,
        recommended_action=action,
        status="new",
        rule_key=rule_key,
        fingerprint=fp,
        is_simulated=is_simulated,
        created_at=utcnow(),
    )
    db.add(alert)
    db.flush()
    return alert


def _recommendation_for_alert(db: Session, alert: Alert, user_id: int | None) -> None:
    if alert.severity not in {"critical", "high"}:
        return
    if db.query(Recommendation).filter(Recommendation.alert_id == alert.id).first():
        return
    db.add(Recommendation(
        ref=next_ref(db, Recommendation, "REC"),
        title=f"Respond to {alert.ref}: {alert.title}"[:230],
        reason=alert.trigger_reason,
        priority=alert.severity,
        threat_id=alert.threat_id,
        vulnerability_id=alert.vulnerability_id,
        asset_id=(alert.asset_ids or [None])[0],
        alert_id=alert.id,
        action=alert.recommended_action,
        evidence=alert.evidence,
        status="open",
        owner_id=None,
        due_at=utcnow() + timedelta(hours=24 if alert.severity == "critical" else 72),
        created_at=utcnow(),
    ))


def detect(db: Session, window_hours: int = 36, baseline_days: int = 14, user_id: int | None = None) -> dict:
    now = utcnow()
    window_start = now - timedelta(hours=window_hours)
    recent = db.query(Threat).filter(Threat.published_at >= window_start).all()
    baseline_start = now - timedelta(days=baseline_days)
    baseline = (
        db.query(Threat)
        .filter(Threat.published_at >= baseline_start, Threat.published_at < window_start)
        .all()
    )
    candidates: list[Alert] = []

    # Rule 1 — known-exploited vulnerability validated against inventory.
    kev_vulns = db.query(Vulnerability).filter(Vulnerability.known_exploited.is_(True)).all()
    for vuln in kev_vulns:
        if vuln.published_at and vuln.published_at < now - timedelta(days=30):
            continue
        links = (
            db.query(AssetVulnerability)
            .filter(AssetVulnerability.vulnerability_id == vuln.id, AssetVulnerability.status == "potentially_exposed")
            .all()
        )
        if not links:
            continue
        assets = [a for a in (db.get(Asset, link.asset_id) for link in links) if a]
        internet = any(a.internet_facing for a in assets)
        threat = db.query(Threat).filter(Threat.cve_id == vuln.cve_id).order_by(Threat.published_at.desc()).first()
        severity = "critical" if (internet and (vuln.cvss_score or 0) >= 9) else "high"
        score = max(threat.risk_score if threat else 0, min(100, (vuln.cvss_score or 7) * 9))
        alert = _maybe_alert(
            db,
            rule_key="kev-exposure",
            entity=vuln.cve_id,
            title=f"Known-exploited {vuln.cve_id} matches {len(assets)} registered asset(s)",
            severity=severity,
            category=(threat.ai_category if threat else "Software Vulnerability"),
            threat=threat,
            vulnerability=vuln,
            assets=assets,
            source=vuln.source,
            risk_score=score,
            confidence=92 if internet else 82,
            trigger=(
                f"Version validation matched {vuln.cve_id} to {len(assets)} inventory asset(s) and the vulnerability "
                "appears in the known-exploited evidence set. Internet-facing exposure raises urgency."
            ),
            evidence=[
                {"label": "Vulnerability", "value": f"{vuln.cve_id} — CVSS {vuln.cvss_score}"},
                {"label": "Known exploited", "value": "Yes (evidence set)"},
                {"label": "Matched assets", "value": ", ".join(f"{a.ref} ({a.name})" for a in assets[:5])},
                {"label": "Exposure", "value": "Internet-facing" if internet else "Internal"},
                {"label": "Match validation", "value": "Product and affected-version range verified"},
            ],
            action="Patch or mitigate on affected assets first; verify exploitation telemetry and restrict external access until remediated.",
            is_simulated=bool(threat.is_simulated if threat else vuln.is_simulated),
        )
        if alert:
            candidates.append(alert)

    # Rule 2 — multiple sources independently report the same CVE.
    cve_sources: dict[str, dict[str, Threat]] = defaultdict(dict)
    for threat in recent:
        if threat.cve_id:
            cve_sources[threat.cve_id.upper()][threat.source] = threat
    for cve, sources in cve_sources.items():
        if len(sources) < 2:
            continue
        primary = max(sources.values(), key=lambda t: t.risk_score or 0)
        vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve).first()
        alert = _maybe_alert(
            db,
            rule_key="multi-source-cve",
            entity=cve,
            title=f"Multiple sources corroborate {cve}",
            severity="high" if (primary.risk_score or 0) >= 70 else "medium",
            category=primary.ai_category or primary.category,
            threat=primary,
            vulnerability=vuln,
            assets=[],
            source=", ".join(sorted(sources.keys())),
            risk_score=primary.risk_score or 50,
            confidence=min(95, 55 + len(sources) * 12),
            trigger=f"{len(sources)} distinct intelligence sources reported {cve} within the {window_hours}-hour window.",
            evidence=[
                {"label": "Sources", "value": ", ".join(sorted(sources.keys()))},
                {"label": "Records", "value": ", ".join(t.ref for t in sources.values())},
                {"label": "Highest risk score", "value": f"{(primary.risk_score or 0):.1f}"},
            ],
            action="Corroborate vendor advisory details, confirm affected versions, and check inventory for the product.",
            is_simulated=all(t.is_simulated for t in sources.values()),
        )
        if alert:
            candidates.append(alert)

    # Rule 3 — repeated indicator (domain/IP/hash) across independent reports.
    indicator_map: dict[str, list[Threat]] = defaultdict(list)
    for threat in recent:
        for indicator in threat.indicators or []:
            value = str(indicator.get("value", "")).lower()
            if value:
                indicator_map[value].append(threat)
    for value, threats in indicator_map.items():
        unique = {t.id: t for t in threats}
        if len(unique) < 2:
            continue
        members = list(unique.values())
        primary = max(members, key=lambda t: t.risk_score or 0)
        alert = _maybe_alert(
            db,
            rule_key="repeated-indicator",
            entity=value,
            title=f"Repeated indicator observed across {len(members)} reports: {value[:60]}",
            severity="high" if (primary.risk_score or 0) >= 65 else "medium",
            category=primary.ai_category or primary.category,
            threat=primary,
            vulnerability=None,
            assets=[],
            source=", ".join(sorted({t.source for t in members})),
            risk_score=primary.risk_score or 45,
            confidence=min(90, 50 + len(members) * 10),
            trigger=(
                f"The indicator {value} appears in {len(members)} reports inside the observation window. "
                "This is an observed clustering, not proof of an imminent campaign."
            ),
            evidence=[
                {"label": "Indicator", "value": value},
                {"label": "Reports", "value": ", ".join(t.ref for t in members[:6])},
                {"label": "Earliest mention", "value": min(t.published_at for t in members).isoformat()},
                {"label": "Latest mention", "value": max(t.published_at for t in members).isoformat()},
            ],
            action="Hunt for the indicator in telemetry, block only after verification through approved change processes.",
            is_simulated=all(t.is_simulated for t in members),
        )
        if alert:
            candidates.append(alert)

    # Rule 4 — activity velocity against a rolling baseline.
    def velocity_groups(field: str) -> dict[str, list[Threat]]:
        groups: dict[str, list[Threat]] = defaultdict(list)
        for threat in recent:
            value = getattr(threat, field)
            if value:
                groups[str(value)].append(threat)
        return groups

    for field, label in (("affected_technology", "technology"), ("category", "category")):
        groups = velocity_groups(field)
        baseline_groups: dict[str, list[Threat]] = defaultdict(list)
        for threat in baseline:
            value = getattr(threat, field)
            if value:
                baseline_groups[str(value)].append(threat)
        for value, members in groups.items():
            if len(members) < 3:
                continue
            baseline_count = len(baseline_groups.get(value, []))
            baseline_per_window = (baseline_count / max(1, (baseline_days * 24 - window_hours))) * window_hours
            if len(members) < max(3, math.ceil(baseline_per_window * 2.2)):
                continue
            primary = max(members, key=lambda t: t.risk_score or 0)
            ratio = len(members) / max(1.0, baseline_per_window)
            alert = _maybe_alert(
                db,
                rule_key=f"velocity-{field}",
                entity=value,
                title=f"Activity spike for {label}: {value}",
                severity="high" if (primary.risk_score or 0) >= 70 else "medium",
                category=primary.ai_category or primary.category,
                threat=primary,
                vulnerability=None,
                assets=[],
                source=", ".join(sorted({t.source for t in members})),
                risk_score=primary.risk_score or 50,
                confidence=min(88, 45 + len(members) * 6),
                trigger=(
                    f"{len(members)} reports in {window_hours}h versus a baseline rate of "
                    f"{baseline_per_window:.1f} per window ({ratio:.1f}×). This is a statistical observation, "
                    "not a verified prediction."
                ),
                evidence=[
                    {"label": "Observed reports", "value": str(len(members))},
                    {"label": "Baseline per window", "value": f"{baseline_per_window:.2f}"},
                    {"label": "Ratio", "value": f"{ratio:.1f}×"},
                    {"label": "Supporting records", "value": ", ".join(t.ref for t in members[:6])},
                ],
                action="Review the contributing records, confirm whether the pattern is organic, and raise monitoring on affected technology.",
                is_simulated=all(t.is_simulated for t in members),
            )
            if alert:
                candidates.append(alert)

    # Rule 5 — recent critical threat matched to a critical asset.
    for threat in recent:
        if threat.severity != "critical" or not threat.cve_id:
            continue
        vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == threat.cve_id).first()
        if not vuln:
            continue
        links = (
            db.query(AssetVulnerability)
            .filter(AssetVulnerability.vulnerability_id == vuln.id, AssetVulnerability.status == "potentially_exposed")
            .all()
        )
        critical_assets = [a for a in (db.get(Asset, link.asset_id) for link in links) if a and a.criticality >= 4]
        if not critical_assets:
            continue
        alert = _maybe_alert(
            db,
            rule_key="critical-asset-exposure",
            entity=f"{threat.cve_id}-{critical_assets[0].id}",
            title=f"Critical threat {threat.ref} intersects critical asset {critical_assets[0].ref}",
            severity="high",
            category=threat.ai_category or threat.category,
            threat=threat,
            vulnerability=vuln,
            assets=critical_assets,
            source=threat.source,
            risk_score=max(threat.risk_score or 0, 72),
            confidence=80,
            trigger=(
                f"A critical-severity record published inside the window has a validated version match with "
                f"{len(critical_assets)} business-critical asset(s)."
            ),
            evidence=[
                {"label": "Threat record", "value": f"{threat.ref} — {threat.name}"},
                {"label": "Affected assets", "value": ", ".join(a.ref for a in critical_assets)},
                {"label": "Asset criticality", "value": ", ".join(f"{a.criticality}/5" for a in critical_assets)},
            ],
            action="Validate exposure, apply emergency mitigation, and notify the asset owner for remediation.",
            is_simulated=threat.is_simulated,
        )
        if alert:
            candidates.append(alert)

    candidates.sort(key=lambda a: a.risk_score or 0, reverse=True)
    selected = candidates[:MAX_NEW_ALERTS]
    for extra in candidates[MAX_NEW_ALERTS:]:
        db.delete(extra)
    for alert in selected:
        _recommendation_for_alert(db, alert, user_id)
    db.commit()
    return {
        "window_hours": window_hours,
        "baseline_days": baseline_days,
        "rules_evaluated": 5,
        "records_considered": len(recent),
        "alerts_created": len(selected),
        "alerts_suppressed_duplicate": max(0, len(candidates) - len(selected)),
        "alerts": [
            {"ref": a.ref, "title": a.title, "severity": a.severity, "rule": a.rule_key, "risk_score": a.risk_score}
            for a in selected
        ],
        "generated_at": now.isoformat(),
    }
