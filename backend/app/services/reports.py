"""Threat-intelligence report generation and CSV exports from stored records."""
from datetime import timedelta

from sqlalchemy.orm import Session

from ..models import (
    Alert,
    Asset,
    AssetVulnerability,
    ModelEvaluation,
    Recommendation,
    Threat,
    ThreatSource,
    Vulnerability,
    utcnow,
)
from ..utils import csv_response_bytes
from . import analytics, exposure

REPORT_TYPES = {
    "daily": ("Daily Threat Intelligence Report", 1),
    "weekly": ("Weekly Threat Intelligence Report", 7),
    "monthly": ("Monthly Cybersecurity Report", 30),
    "critical": ("Critical Threat Report", 14),
    "exposure": ("Vulnerability Exposure Report", 30),
    "asset-risk": ("Asset Risk Assessment Report", 0),
}


def _section(section_id: str, title: str, paragraphs: list[str] | None = None,
             items: list | None = None, columns: list[str] | None = None, rows: list | None = None) -> dict:
    return {
        "id": section_id,
        "title": title,
        "paragraphs": paragraphs or [],
        "items": items or [],
        "columns": columns or [],
        "rows": rows or [],
    }


def build_report(db: Session, kind: str, start, end, user) -> dict:
    if kind not in REPORT_TYPES:
        raise ValueError("Unknown report type")
    title, _ = REPORT_TYPES[kind]
    data = analytics.build(db, start, end)
    kpis = data["kpis"]

    threats = (
        db.query(Threat)
        .filter(Threat.published_at >= start, Threat.published_at <= end)
        .order_by(Threat.risk_score.desc())
        .all()
    )
    if kind == "critical":
        threats = [t for t in threats if t.severity == "critical"]
    vulns = (
        db.query(Vulnerability)
        .filter(Vulnerability.published_at >= start, Vulnerability.published_at <= end)
        .order_by(Vulnerability.cvss_score.desc())
        .all()
    )
    alerts = (
        db.query(Alert)
        .filter(Alert.detected_at >= start, Alert.detected_at <= end)
        .order_by(Alert.risk_score.desc())
        .all()
    )
    recommendations = db.query(Recommendation).filter(Recommendation.status.in_(["open", "in_progress"])).all()
    sources = db.query(ThreatSource).all()
    matches = (
        db.query(AssetVulnerability)
        .filter(AssetVulnerability.status == "potentially_exposed")
        .all()
    )
    matched_assets = {m.asset_id for m in matches}
    assets = db.query(Asset).all()
    evaluations = db.query(ModelEvaluation).order_by(ModelEvaluation.evaluated_at.desc()).limit(1).all()

    exposure_rows = []
    for link in matches[:20]:
        asset = db.get(Asset, link.asset_id)
        vuln = db.get(Vulnerability, link.vulnerability_id)
        if asset and vuln:
            exposure_rows.append([asset.ref, asset.name, asset.software_version, vuln.cve_id, vuln.cvss_score,
                                  "Yes" if vuln.known_exploited else "No", f"{link.match_confidence:.0f}%", link.status])
    asset_rows = []
    for asset in assets:
        summary = exposure.asset_risk_summary(db, asset)
        asset_rows.append([asset.ref, asset.name, asset.category, f"{asset.criticality}/5", summary["risk_score"],
                           summary["risk_category"], summary["validated_vulnerabilities"]])
    asset_rows.sort(key=lambda r: r[4], reverse=True)

    categories = ", ".join(f"{c['name']} ({c['value']})" for c in data["category_distribution"][:4]) or "no classified activity"
    severity_text = ", ".join(f"{s['name'].lower()}: {s['value']}" for s in data["severity_distribution"]) or "no severity records"
    top_alerts = sorted(alerts, key=lambda a: (a.severity == "critical", a.risk_score or 0), reverse=True)[:8]

    executive = [
        f"This report covers {start.strftime('%d %b %Y %H:%M')} UTC to {end.strftime('%d %b %Y %H:%M')} UTC and was generated from {len(threats)} in-range threat records, {len(vulns)} vulnerability records and {len(alerts)} alerts.",
        f"Severity mix in the period: {severity_text}. Predominant classifications: {categories}.",
        f"{kpis['exposed_assets']} of {kpis['total_assets']} registered assets have at least one version-validated vulnerability exposure; {kpis['active_alerts']} alerts are currently active across the platform.",
        f"Average threat risk in the period is {kpis['avg_risk']}/100. Risk is a prioritisation score, not a probability of compromise; exploitation status is reported separately.",
    ]
    if kind == "critical":
        executive.append("This report is filtered to critical-severity records and should be read alongside the full daily intelligence report.")
    if kind == "exposure":
        executive.append("Exposure claims in this report require validated product identity and affected-version ranges; products matched without version evidence are labelled as requiring verification.")
    if kind == "asset-risk":
        executive.append("Asset risk rankings combine validated vulnerability exposure, exploit evidence, external exposure and asset criticality using the configurable model.")

    sections = [
        _section("executive", "Executive summary", paragraphs=executive),
        _section(
            "metrics", "Key metrics",
            items=[
                {"label": "Threat records in range", "value": len(threats)},
                {"label": "Critical threats", "value": sum(1 for t in threats if t.severity == "critical")},
                {"label": "New vulnerabilities", "value": len(vulns)},
                {"label": "Active alerts (platform)", "value": kpis["active_alerts"]},
                {"label": "Exposed assets", "value": kpis["exposed_assets"]},
                {"label": "Average risk", "value": f"{kpis['avg_risk']}/100"},
                {"label": "Open recommendations", "value": kpis["open_recommendations"]},
            ],
        ),
        _section(
            "threat-overview", "Threat overview",
            paragraphs=[data["summary"]],
            columns=["Reference", "Threat", "Severity", "Risk", "Source", "Published"],
            rows=[[t.ref, t.name[:80], t.severity, f"{t.risk_score:.1f}", t.source, t.published_at.strftime("%Y-%m-%d %H:%M")]
                  for t in threats[:12]],
        ),
        _section(
            "vulnerabilities", "Newly detected vulnerabilities",
            paragraphs=[f"{len(vulns)} vulnerability records were published in the selected period; {sum(1 for v in vulns if v.known_exploited)} carry known-exploited evidence."],
            columns=["CVE", "Title", "CVSS", "EPSS", "Known exploited", "Published"],
            rows=[[v.cve_id, v.title[:72], v.cvss_score if v.cvss_score is not None else "n/a",
                   f"{v.epss_score:.2f}" if v.epss_score is not None else "n/a",
                   "Yes" if v.known_exploited else "No", v.published_at.strftime("%Y-%m-%d")]
                  for v in vulns[:10]],
        ),
        _section(
            "alerts", "Critical and high-priority alerts",
            paragraphs=[f"{len(alerts)} alerts were detected in range. Lifecycle status and assignment are tracked in the alert centre."],
            columns=["Alert", "Title", "Severity", "Status", "Risk", "Detected"],
            rows=[[a.ref, a.title[:78], a.severity, a.status, f"{a.risk_score:.1f}", a.detected_at.strftime("%Y-%m-%d %H:%M")]
                  for a in top_alerts],
        ),
        _section(
            "technologies", "Affected technologies",
            items=[{"name": t["name"], "count": t["count"], "avg_risk": t["avg_risk"]} for t in data["top_technologies"]],
        ),
        _section(
            "exposure", "Potentially exposed assets",
            paragraphs=[
                f"{kpis['exposed_assets']} assets have version-validated exposure; {kpis['needs_verification']} product-name matches still require version verification.",
                "No asset is declared vulnerable solely from a loose text match.",
            ],
            columns=["Asset", "Name", "Version", "CVE", "CVSS", "Known exploited", "Match", "Status"],
            rows=exposure_rows,
        ),
        _section(
            "risk", "Risk score distribution",
            items=[{"name": s["name"], "count": s["value"]} for s in data["risk_distribution"]],
        ),
        _section(
            "emerging", "Emerging-threat observations",
            paragraphs=[
                f"{sum(1 for a in data['anomaly_series'] if a['flagged'])} intervals exceeded the two-sigma activity baseline.",
                "Correlated patterns describe observed reporting clusters and do not predict future attacks with certainty.",
            ],
            columns=["Interval", "Observed", "Baseline", "Z-score", "Flagged"],
            rows=[[a["name"], a["observed"], a["baseline"], a["z"], "Yes" if a["flagged"] else "No"] for a in data["anomaly_series"][-10:]],
        ),
        _section(
            "ai", "AI-assisted analysis",
            paragraphs=[
                "Threat classification uses a deterministic heuristic NLP lexicon (offline mode). It summarises source text and does not independently verify source claims.",
                (f"Latest classifier run: precision {evaluations[0].precision:.2f}, recall {evaluations[0].recall:.2f}, F1 {evaluations[0].f1:.2f} on {evaluations[0].samples} curated samples ({evaluations[0].dataset_name})."
                 if evaluations else "No model evaluation is available."),
            ],
            items=[{"name": c["name"], "count": c["value"]} for c in data["classification_distribution"]],
        ),
        _section(
            "recommendations", "Recommended preventive measures",
            columns=["Priority", "Recommendation", "Reason", "Status"],
            rows=[[r.priority, r.title[:78], r.reason[:100], r.status] for r in sorted(
                recommendations, key=lambda r: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(r.priority, 4)
            )[:12]],
        ),
        _section(
            "sources", "Sources, retrieval times and provenance",
            paragraphs=[
                "Every externally sourced record stores its source, reliability weighting and retrieval timestamp.",
                f"{len(threats)} threat records, {len(vulns)} vulnerability records and {len(alerts)} alerts fall inside the selected window.",
            ],
            columns=["Source", "Status", "Reliability", "Last success", "Items"],
            rows=[[s.name, s.status, s.reliability,
                   s.last_success_at.strftime("%Y-%m-%d %H:%M") if s.last_success_at else "never",
                   s.items_ingested] for s in sources],
        ),
    ]
    if kind == "asset-risk":
        sections.insert(2, _section(
            "asset-ranking", "Asset risk ranking",
            columns=["Asset", "Name", "Category", "Criticality", "Risk", "Band", "Validated CVEs"],
            rows=asset_rows[:20],
        ))

    return {
        "kind": kind,
        "title": title,
        "generated_at": utcnow().isoformat(),
        "generated_by": {"name": user.full_name, "role": user.role, "organisation_id": user.organisation_id},
        "range": {"start": start.isoformat(), "end": end.isoformat()},
        "classification": "Internal use. Generated from stored platform records; each entry carries its source and retrieval timestamp.",
        "executive_summary": executive,
        "sections": sections,
        "metrics": {
            "threats": len(threats),
            "vulnerabilities": len(vulns),
            "alerts": len(alerts),
            "exposed_assets": kpis["exposed_assets"],
            "known_exploited": sum(1 for v in vulns if v.known_exploited),
            "open_recommendations": kpis["open_recommendations"],
        },
        "sources": [
            {"name": s.name, "key": s.key, "status": s.status, "last_success_at": s.last_success_at.isoformat() if s.last_success_at else None,
             "reliability": s.reliability}
            for s in sources
        ],
        "provenance_note": "Live, cached and imported material are distinguished by the source and retrieval timestamp stored on each record.",
    }


def report_csv(db: Session, kind: str, start, end) -> tuple[str, bytes]:
    if kind in {"daily", "weekly", "monthly", "critical"}:
        query = db.query(Threat).filter(Threat.published_at >= start, Threat.published_at <= end)
        if kind == "critical":
            query = query.filter(Threat.severity == "critical")
        threats = query.order_by(Threat.risk_score.desc()).all()
        headers = ["ref", "name", "category", "severity", "source", "cve", "cvss", "epss", "risk_score",
                   "risk_category", "evidence_confidence", "exploitation_status", "status", "published_at"]
        rows = [[t.ref, t.name, t.category, t.severity, t.source, t.cve_id, t.cvss_score, t.epss_score,
                 t.risk_score, t.risk_category, t.confidence, t.exploitation_status, t.status,
                 t.published_at.isoformat()] for t in threats]
        return f"aegis-sentinel-{kind}-{utcnow().date()}.csv", csv_response_bytes(headers, rows)
    if kind == "exposure":
        links = db.query(AssetVulnerability).all()
        headers = ["asset_ref", "asset_name", "software", "version", "cve", "cvss", "known_exploited",
                   "match_confidence", "match_status", "match_reason"]
        rows = []
        for link in links:
            asset = db.get(Asset, link.asset_id)
            vuln = db.get(Vulnerability, link.vulnerability_id)
            if asset and vuln:
                rows.append([asset.ref, asset.name, asset.software, asset.software_version, vuln.cve_id,
                             vuln.cvss_score, vuln.known_exploited, link.match_confidence, link.status, link.match_reason])
        return f"aegis-sentinel-exposure-{utcnow().date()}.csv", csv_response_bytes(headers, rows)
    if kind == "asset-risk":
        assets = db.query(Asset).all()
        headers = ["asset_ref", "name", "category", "organisation_id", "software", "version", "exposure",
                   "criticality", "risk_score", "risk_category", "validated_vulnerabilities", "needs_verification"]
        rows = []
        for asset in assets:
            summary = exposure.asset_risk_summary(db, asset)
            rows.append([asset.ref, asset.name, asset.category, asset.organisation_id, asset.software,
                         asset.software_version, asset.exposure, asset.criticality, summary["risk_score"],
                         summary["risk_category"], summary["validated_vulnerabilities"], summary["needs_verification"]])
        return f"aegis-sentinel-asset-risk-{utcnow().date()}.csv", csv_response_bytes(headers, rows)
    raise ValueError("Unknown report type")
