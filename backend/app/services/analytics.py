"""Analytics aggregation over stored records only."""
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from ..models import (
    Alert,
    Asset,
    AssetVulnerability,
    IngestionLog,
    Recommendation,
    RiskAssessment,
    Threat,
    ThreatCorrelation,
    ThreatSource,
    Vulnerability,
    utcnow,
)
from ..utils import severity_from_cvss
from . import risk
from .exposure import asset_risk_summary

SEVERITIES = ["critical", "high", "medium", "low", "informational"]
RISK_COLORS = {"Critical": "#FF334F", "High": "#FF703B", "Medium": "#F5B942", "Low": "#20C997"}


def _buckets(start: datetime, end: datetime):
    span_hours = max(1, (end - start).total_seconds() / 3600)
    hourly = span_hours <= 48
    buckets = []
    if hourly:
        cursor = start.replace(minute=0, second=0, microsecond=0)
        while cursor < end:
            buckets.append((cursor, min(cursor + timedelta(hours=1), end), cursor.strftime("%d %b %H:%M")))
            cursor += timedelta(hours=1)
    else:
        cursor = start.replace(hour=0, minute=0, second=0, microsecond=0)
        while cursor < end:
            buckets.append((cursor, min(cursor + timedelta(days=1), end), cursor.strftime("%d %b")))
            cursor += timedelta(days=1)
    return buckets, hourly


def _bucket_index(dt: datetime | None, start: datetime, end: datetime, buckets) -> int:
    if not dt:
        return -1
    for i in range(len(buckets) - 1, -1, -1):
        if dt >= buckets[i][0]:
            return i if dt < end else -1
    return -1


def _delta(current: float, previous: float) -> float | None:
    if previous == 0:
        return None
    return round((current - previous) / previous * 100, 1)


def _threat_query(db: Session, start, end, filters: dict | None = None):
    filters = filters or {}
    query = db.query(Threat).filter(Threat.published_at >= start, Threat.published_at <= end)
    if filters.get("severity"):
        query = query.filter(Threat.severity == filters["severity"])
    if filters.get("category"):
        query = query.filter(Threat.category == filters["category"])
    if filters.get("source"):
        query = query.filter(Threat.source == filters["source"])
    return query


def build(db: Session, start: datetime, end: datetime, filters: dict | None = None) -> dict:
    threats = _threat_query(db, start, end, filters).all()
    span = end - start
    prev_start = start - span
    prev_threats = _threat_query(db, prev_start, start, filters).all()
    alerts = db.query(Alert).filter(Alert.detected_at >= start, Alert.detected_at <= end).all()
    prev_alerts = db.query(Alert).filter(Alert.detected_at >= prev_start, Alert.detected_at < start).all()
    vulns = db.query(Vulnerability).filter(Vulnerability.published_at >= start, Vulnerability.published_at <= end).all()
    prev_vulns = db.query(Vulnerability).filter(Vulnerability.published_at >= prev_start, Vulnerability.published_at < start).all()
    all_vulns = db.query(Vulnerability).all()
    all_assets = db.query(Asset).all()
    all_matches = db.query(AssetVulnerability).all()
    all_alerts = db.query(Alert).all()
    recommendations = db.query(Recommendation).all()
    sources = db.query(ThreatSource).all()
    correlations = db.query(ThreatCorrelation).all()

    buckets, hourly = _buckets(start, end)
    index = lambda dt: _bucket_index(dt, start, end, buckets)  # noqa: E731

    threat_series = [{"name": label, "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0} for _, _, label in buckets]
    vuln_series = [{"name": label, "count": 0, "critical": 0} for _, _, label in buckets]
    alert_series = [{"name": label, "total": 0, "critical": 0, "high": 0} for _, _, label in buckets]
    risk_series = [{"name": label, "avg_risk": None, "max_risk": 0, "_sum": 0, "_n": 0} for _, _, label in buckets]
    source_series = {name: [0] * len(buckets) for name in sorted({t.source for t in threats})}

    for threat in threats:
        i = index(threat.published_at)
        if i < 0:
            continue
        threat_series[i]["total"] += 1
        if threat.severity in threat_series[i]:
            threat_series[i][threat.severity] += 1
        risk_series[i]["avg_risk"] = 0
        risk_series[i]["_sum"] += threat.risk_score or 0
        risk_series[i]["_n"] += 1
        risk_series[i]["max_risk"] = max(risk_series[i]["max_risk"], threat.risk_score or 0)
        if threat.source in source_series:
            source_series[threat.source][i] += 1
    for entry in risk_series:
        if entry["_n"]:
            entry["avg_risk"] = round(entry["_sum"] / entry["_n"], 1)
        entry.pop("_sum", None)
        entry.pop("_n", None)
    for vuln in vulns:
        i = index(vuln.published_at)
        if i >= 0:
            vuln_series[i]["count"] += 1
            if (vuln.cvss_score or 0) >= 9:
                vuln_series[i]["critical"] += 1
    for alert in alerts:
        i = index(alert.detected_at)
        if i >= 0:
            alert_series[i]["total"] += 1
            if alert.severity in ("critical", "high"):
                alert_series[i][alert.severity] += 1

    severity_counts = Counter(t.severity for t in threats)
    category_counts = Counter((t.ai_category or t.category) for t in threats)
    source_counts = Counter(t.source for t in threats)
    classification_counts = Counter(t.ai_category or "Unclassified" for t in threats)
    alert_status_counts = Counter(a.status for a in alerts)
    alert_severity_counts = Counter(a.severity for a in all_alerts if a.status in {"new", "acknowledged", "investigating"})
    vuln_severity_counts = Counter(v.cvss_severity or severity_from_cvss(v.cvss_score) for v in vulns)
    risk_counts = Counter(t.risk_category for t in threats)
    asset_category_counts = Counter(a.category for a in all_assets)
    remediation_counts = Counter(r.status for r in recommendations)
    remediation_priority = Counter(r.priority for r in recommendations)

    technologies = Counter(t.affected_technology for t in threats if t.affected_technology)
    tech_risk = defaultdict(list)
    for t in threats:
        if t.affected_technology:
            tech_risk[t.affected_technology].append(t.risk_score or 0)
    top_technologies = [
        {"name": name, "count": count, "avg_risk": round(sum(tech_risk[name]) / len(tech_risk[name]), 1)}
        for name, count in technologies.most_common(10)
    ]
    indicators = Counter()
    indicator_types = {}
    geo = Counter()
    geo_points = {}
    for t in threats:
        for ind in (t.indicators or []):
            value = str(ind.get("value", ""))
            kind = ind.get("type", "unknown")
            if value:
                indicators[(kind, value)] += 1
                indicator_types[value] = kind
            location = ind.get("geo")
            if location and location.get("country"):
                geo[location["country"]] += 1
                geo_points[location["country"]] = location
    common_indicators = [
        {"type": kind, "value": value, "count": count}
        for (kind, value), count in indicators.most_common(12)
    ]

    top_vulns = sorted(
        all_vulns, key=lambda v: ((1 if v.known_exploited else 0), v.cvss_score or 0, v.epss_score or 0), reverse=True
    )[:10]
    top_assets = []
    for asset in all_assets:
        summary = asset_risk_summary(db, asset)
        top_assets.append({
            "id": asset.id,
            "ref": asset.ref,
            "name": asset.name,
            "category": asset.category,
            "criticality": asset.criticality,
            "exposure": asset.exposure,
            "risk_score": summary["risk_score"],
            "risk_category": summary["risk_category"],
            "validated_vulnerabilities": summary["validated_vulnerabilities"],
            "known_exploited": summary["known_exploited"],
        })
    top_assets.sort(key=lambda a: a["risk_score"], reverse=True)

    # Heatmap: threat severity × asset criticality for validated matches.
    matched_by_vuln: dict[int, list[int]] = defaultdict(list)
    for link in all_matches:
        if link.status == "potentially_exposed":
            matched_by_vuln[link.vulnerability_id].append(link.asset_id)
    heatmap = []
    for sev in ["critical", "high", "medium", "low"]:
        row = []
        for crit in range(1, 6):
            count = 0
            for threat in threats:
                if threat.severity != sev:
                    continue
                vuln = next((v for v in all_vulns if threat.cve_id and v.cve_id == threat.cve_id), None)
                if not vuln:
                    continue
                for asset_id in matched_by_vuln.get(vuln.id, []):
                    asset = next((a for a in all_assets if a.id == asset_id), None)
                    if asset and asset.criticality == crit:
                        count += 1
            row.append(count)
        heatmap.append({"severity": sev.title(), "values": row})
    asset_categories = sorted({a.category for a in all_assets})
    matrix = []
    for sev in ["critical", "high", "medium", "low"]:
        row = []
        for cat in asset_categories:
            count = 0
            for vuln in all_vulns:
                if (vuln.cvss_severity or severity_from_cvss(vuln.cvss_score)) != sev:
                    continue
                for asset_id in matched_by_vuln.get(vuln.id, []):
                    asset = next((a for a in all_assets if a.id == asset_id), None)
                    if asset and asset.category == cat:
                        count += 1
            row.append(count)
        matrix.append({"severity": sev.title(), "values": row})

    resolution = []
    for sev in ["critical", "high", "medium", "low"]:
        resolved = [a for a in all_alerts if a.severity == sev and a.resolved_at and a.detected_at]
        hours = [(a.resolved_at - a.detected_at).total_seconds() / 3600 for a in resolved]
        resolution.append({
            "severity": sev.title(),
            "resolved": len(hours),
            "avg_hours": round(sum(hours) / len(hours), 1) if hours else 0,
        })

    # Anomaly detection: compare bucket counts against the preceding baseline buckets.
    # The baseline must be measured at the SAME granularity as the displayed series,
    # otherwise hourly counts are judged against a daily mean.
    baseline_buckets = 24 if hourly else 14
    step = timedelta(hours=1) if hourly else timedelta(days=1)
    first_bucket = (start.replace(minute=0, second=0, microsecond=0) if hourly
                    else start.replace(hour=0, minute=0, second=0, microsecond=0))
    history_start = first_bucket - step * baseline_buckets
    history = db.query(Threat).filter(Threat.published_at >= history_start, Threat.published_at < start).all()
    historical = Counter()
    for threat in history:
        stamp = threat.published_at
        historical[stamp.replace(minute=0, second=0, microsecond=0) if hourly else stamp.date()] += 1
    # Enumerate empty buckets too: a quiet period is evidence, not a missing value.
    keys = [
        (first_bucket - step * offset if hourly
         else (first_bucket - step * offset).date())
        for offset in range(baseline_buckets, 0, -1)
    ]
    baseline_values = [historical.get(key, 0) for key in keys]
    observed_span = len(baseline_values)
    non_empty = sum(1 for value in baseline_values if value)
    mean = sum(baseline_values) / len(baseline_values)
    variance = sum((v - mean) ** 2 for v in baseline_values) / len(baseline_values)
    # A count baseline of all-zero history carries no information; flagging against it
    # would mark every ordinary bucket as anomalous, so the baseline is withheld instead.
    baseline_ready = mean > 0 and non_empty >= 3 and observed_span >= (6 if hourly else 5)
    std = max(1.0, variance ** 0.5)
    if baseline_ready:
        baseline_status = f"Two-sigma baseline over {observed_span} preceding {'hourly' if hourly else 'daily'} buckets."
    elif observed_span < (6 if hourly else 5):
        baseline_status = "Baseline withheld: fewer buckets precede this window than the detector requires."
    else:
        baseline_status = "Baseline withheld: the preceding buckets contain no recorded activity to compare against."
    anomaly_series = []
    for entry in threat_series[-30:]:
        z = round((entry["total"] - mean) / std, 2) if baseline_ready else None
        anomaly_series.append({
            "name": entry["name"],
            "observed": entry["total"],
            "baseline": round(mean, 1),
            "z": z,
            "flagged": bool(baseline_ready and z is not None and z >= 2),
            "baseline_ready": baseline_ready,
            "baseline_granularity": "hourly" if hourly else "daily",
            "baseline_status": baseline_status,
        })

    kpis = {
        "total_threats": db.query(func.count(Threat.id)).scalar() or 0,
        "new_threats": len(threats),
        "critical_threats": severity_counts.get("critical", 0),
        "high_risk_vulnerabilities": sum(1 for v in all_vulns if (v.cvss_score or 0) >= 7 or v.known_exploited),
        "active_alerts": sum(1 for a in all_alerts if a.status in {"new", "acknowledged", "investigating"}),
        "critical_alerts": sum(1 for a in all_alerts if a.status in {"new", "acknowledged", "investigating"} and a.severity == "critical"),
        "exposed_assets": len({m.asset_id for m in all_matches if m.status == "potentially_exposed"}),
        "total_assets": len(all_assets),
        "investigating": sum(1 for t in threats if t.status == "investigating"),
        "resolved": sum(1 for t in threats if t.status == "resolved"),
        "sources_online": sum(1 for s in sources if s.status in {"operational", "degraded"}),
        "sources_total": len(sources),
        "known_exploited": sum(1 for v in all_vulns if v.known_exploited),
        "avg_risk": round(sum(t.risk_score or 0 for t in threats) / len(threats), 1) if threats else 0,
        "new_alerts": len(alerts),
        "new_vulnerabilities": len(vulns),
        "validated_matches": sum(1 for m in all_matches if m.status == "potentially_exposed"),
        "needs_verification": sum(1 for m in all_matches if m.status == "needs_verification"),
        "last_sync": max((s.last_success_at for s in sources if s.last_success_at), default=None),
        "open_recommendations": sum(1 for r in recommendations if r.status == "open"),
    }
    deltas = {
        "new_threats": _delta(len(threats), len(prev_threats)),
        "critical_threats": _delta(severity_counts.get("critical", 0), sum(1 for t in prev_threats if t.severity == "critical")),
        "new_alerts": _delta(len(alerts), len(prev_alerts)),
        "new_vulnerabilities": _delta(len(vulns), len(prev_vulns)),
    }

    critical_recent = sorted(
        [t for t in threats if t.severity in ("critical", "high")],
        key=lambda t: (t.risk_score or 0, t.published_at), reverse=True,
    )[:8]
    recent_alerts = sorted(all_alerts, key=lambda a: a.detected_at, reverse=True)[:8]
    recent_ingestion = db.query(IngestionLog).order_by(IngestionLog.started_at.desc()).limit(8).all()

    summary_bits = [
        f"{len(threats)} threat records were recorded in the selected period, of which {severity_counts.get('critical', 0)} were critical.",
        f"{len(vulns)} vulnerability records were published, including {sum(1 for v in vulns if v.known_exploited)} known-exploited entries.",
        f"{len(alerts)} alerts were generated; {kpis['active_alerts']} remain active overall.",
        f"{kpis['exposed_assets']} of {kpis['total_assets']} registered assets have at least one version-validated exposure.",
        f"Average risk for records in the period is {kpis['avg_risk']}/100; {risk_counts.get('Critical', 0)} records fall in the critical band.",
    ]
    if top_technologies:
        summary_bits.append(f"Most-mentioned technology: {top_technologies[0]['name']} ({top_technologies[0]['count']} records).")
    flagged_anomalies = [a for a in anomaly_series if a["flagged"]]
    if flagged_anomalies:
        summary_bits.append(f"{len(flagged_anomalies)} interval(s) exceeded the two-sigma activity baseline.")
    else:
        summary_bits.append("No interval exceeded the two-sigma activity baseline in the displayed window.")

    geo_activity = []
    for country, count in geo.most_common(8):
        location = geo_points[country]
        geo_activity.append({
            "country": country,
            "code": location.get("code", ""),
            "count": count,
            "lat": location.get("lat"),
            "lon": location.get("lon"),
        })

    return {
        "range": {"start": start.isoformat(), "end": end.isoformat(), "granularity": "hourly" if hourly else "daily"},
        "generated_at": utcnow().isoformat(),
        "data_quality": {
            "note": "Every record carries its source and retrieval timestamp. Charts aggregate stored records only.",
        },
        "kpis": kpis,
        "deltas": deltas,
        "threat_series": threat_series,
        "vuln_series": vuln_series,
        "alert_series": alert_series,
        "risk_series": risk_series,
        "source_series": {
            "labels": [label for _, _, label in buckets],
            "series": [{"name": name, "data": values} for name, values in source_series.items()],
        },
        "severity_distribution": [
            {"name": sev.title(), "value": severity_counts.get(sev, 0)} for sev in SEVERITIES if severity_counts.get(sev, 0)
        ],
        "category_distribution": [
            {"name": name, "value": count} for name, count in category_counts.most_common(9)
        ],
        "classification_distribution": [
            {"name": name, "value": count} for name, count in classification_counts.most_common(9)
        ],
        "source_distribution": [{"name": name, "value": count} for name, count in source_counts.most_common(10)],
        "vuln_severity_distribution": [
            {"name": sev.title(), "value": vuln_severity_counts.get(sev, 0)}
            for sev in SEVERITIES if vuln_severity_counts.get(sev, 0)
        ],
        "risk_distribution": [{"name": name, "value": risk_counts.get(name, 0)} for name in ["Critical", "High", "Medium", "Low"]],
        "asset_categories": [{"name": name, "value": count} for name, count in asset_category_counts.most_common()],
        "alert_status_distribution": [
            {"name": name.title(), "value": count} for name, count in alert_status_counts.most_common()
        ],
        "active_alert_severity": [
            {"name": name.title(), "value": alert_severity_counts.get(name, 0)} for name in SEVERITIES
        ],
        "alerts_by_priority": [
            {"name": name.title(), "value": count} for name, count in alert_severity_counts.most_common()
        ],
        "remediation_backlog": [
            {"name": name.replace("_", " ").title(), "value": count} for name, count in remediation_counts.most_common()
        ],
        "remediation_priority": [
            {"name": name.title(), "value": count} for name, count in remediation_priority.most_common()
        ],
        "top_technologies": top_technologies,
        "top_vulnerabilities": [
            {
                "id": v.id, "cve_id": v.cve_id, "title": v.title, "cvss": v.cvss_score,
                "epss": v.epss_score, "known_exploited": v.known_exploited, "published_at": v.published_at.isoformat(),
            } for v in top_vulns
        ],
        "top_assets": top_assets[:10],
        "common_indicators": common_indicators,
        "heatmap": {
            "rows": ["Critical", "High", "Medium", "Low"],
            "cols": [str(c) for c in range(1, 6)],
            "data": heatmap,
        },
        "vuln_asset_matrix": {"cols": asset_categories, "rows": matrix},
        "resolution_time": resolution,
        "anomaly_series": anomaly_series,
        "source_reliability": [
            {"name": s.name, "reliability": s.reliability, "status": s.status, "items": s.items_ingested}
            for s in sorted(sources, key=lambda s: s.reliability, reverse=True)
        ],
        "geo_activity": geo_activity,
        "geo_note": (
            "Locations are estimates attached to indicator metadata, not verified attacker attribution. "
            "An IP's physical location does not identify a person or organisation."
        ),
        "recent_alerts": [
            {
                "id": a.id, "ref": a.ref, "title": a.title, "severity": a.severity, "status": a.status,
                "detected_at": a.detected_at.isoformat(), "risk_score": a.risk_score,
            } for a in recent_alerts
        ],
        "critical_recent": [
            {
                "id": t.id, "ref": t.ref, "name": t.name, "severity": t.severity, "category": t.category,
                "published_at": t.published_at.isoformat(), "risk_score": t.risk_score, "source": t.source,
                "technology": t.affected_technology,
            } for t in critical_recent
        ],
        "source_status": [
            {
                "key": s.key, "name": s.name, "status": s.status, "last_sync_at": s.last_sync_at.isoformat() if s.last_sync_at else None,
                "last_success_at": s.last_success_at.isoformat() if s.last_success_at else None,
                "items_ingested": s.items_ingested, "reliability": s.reliability, "requires_key": s.requires_key,
                "key_configured": s.key_configured,
            } for s in sources
        ],
        "correlation_stats": {
            "pairs": len(correlations),
            "avg_score": round(sum(c.score for c in correlations) / len(correlations), 3) if correlations else 0,
        },
        "assessment_count": db.query(func.count(RiskAssessment.id)).scalar() or 0,
        "ingestion_recent": [
            {
                "source": log.source_key, "status": log.status, "mode": log.mode, "items_new": log.items_new,
                "started_at": log.started_at.isoformat(), "message": log.message,
            } for log in recent_ingestion
        ],
        "summary": " ".join(summary_bits),
        "summary_disclaimer": (
            "Analytics summary generated from stored records. Each entry carries its source and retrieval "
            "timestamp; totals describe stored intelligence, not ongoing attack activity."
        ),
    }
