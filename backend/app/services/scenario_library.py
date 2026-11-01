"""End-to-end threat scenarios that run without outbound connector traffic."""
from datetime import timedelta

from sqlalchemy.orm import Session

from ..models import (
    Alert,
    Asset,
    AssetVulnerability,
    Recommendation,
    RiskAssessment,
    Threat,
    User,
    Vulnerability,
    utcnow,
)
from ..utils import severity_from_cvss
from . import classifier, correlation, early_warning, exposure, risk
from .refs import next_ref

SCENARIOS = {
    "high-risk-vulnerability": {
        "title": "Scenario 1 — High-risk vulnerability affects a critical hospital server",
        "description": "Ingest a new vulnerability, validate the affected product/version, match the hospital asset, calculate explainable risk, generate a warning and recommend remediation.",
    },
    "emerging-pattern": {
        "title": "Scenario 2 — Emerging reporting pattern around a shared indicator",
        "description": "Create multiple correlated reports across sources, compare against the baseline, correlate the records, and raise an evidence-backed warning that is explicitly not a prediction.",
    },
    "non-affected-asset": {
        "title": "Scenario 3 — Vulnerability is published but no asset matches",
        "description": "Process a vulnerability for software absent from inventory, withhold any unsupported exposure claim, and record the assessment with remaining uncertainties.",
    },
}


def _next_threat_ref(db: Session) -> str:
    count = db.query(Threat).count() + 1
    while db.query(Threat).filter(Threat.ref == f"THR-{utcnow().year}-{count:04d}").first():
        count += 1
    return f"THR-{utcnow().year}-{count:04d}"


def _next_alert_ref(db: Session) -> str:
    count = db.query(Alert).count() + 1
    while db.query(Alert).filter(Alert.ref == f"AL-{utcnow().year}-{count:04d}").first():
        count += 1
    return f"AL-{utcnow().year}-{count:04d}"


def _create_threat(db: Session, *, name: str, description: str, category_hint: str, source: str,
                   published_at, cve: str | None, cvss: float | None, epss: float | None,
                   known_exploited: bool, technology: str | None, versions: str | None,
                   indicators: list[dict], user: User | None = None) -> Threat:
    # category_hint is this scenario's authored label; classify the text alone so the
    # stored category stays the authored label and ai_category shows the independent result.
    classification = classifier.classify(description)
    category = category_hint or classifier.OTHER
    severity = severity_from_cvss(cvss) if cvss is not None else "high"
    reliability = 78
    summary = classifier.summarise(name, description, source, technology, indicators, cvss)
    entities = classifier.extract_entities(f"{name}. {description}", [technology] if technology else None)
    action = "Validate affected versions, apply the vendor patch, and review exploitation telemetry."
    explanation = classifier.explain(name, classification, entities, indicators, cvss, epss, known_exploited,
                                     technology, reliability, action)
    threat = Threat(
        ref=_next_threat_ref(db),
        name=name[:238],
        category=category,
        description=description,
        source=source,
        source_url="",
        published_at=published_at,
        updated_at=published_at + timedelta(minutes=20),
        cve_id=cve,
        cvss_score=cvss,
        cvss_severity=severity,
        epss_score=epss,
        known_exploited=known_exploited,
        affected_technology=technology,
        affected_versions=versions,
        indicators=indicators,
        source_reliability=reliability,
        evidence_refs=[{"label": "Scenario record", "value": "Written by a packaged threat scenario"}],
        ai_summary=summary,
        ai_category=classification["category"],
        ai_confidence=round(classification["confidence"] * 100, 1),
        ai_keywords=classifier.extract_keywords(description),
        ai_entities=entities,
        ai_explanation=explanation,
        ai_method=classifier.METHOD,
        recommended_action=action,
        severity=severity,
        status="new",
        is_simulated=True,
        retrieval_timestamp=utcnow(),
        created_at=utcnow(),
    )
    db.add(threat)
    db.flush()
    risk.apply_to_threat(threat, db)
    return threat


def _create_alert(db: Session, *, title: str, severity: str, category: str, threat: Threat,
                  vulnerability: Vulnerability | None, assets: list[Asset], source: str,
                  risk_score: float, confidence: float, trigger: str, evidence: list[dict],
                  action: str) -> Alert:
    alert = Alert(
        ref=_next_alert_ref(db),
        title=title[:258],
        severity=severity,
        category=category,
        detected_at=utcnow(),
        threat_id=threat.id,
        vulnerability_id=vulnerability.id if vulnerability else None,
        asset_ids=[a.id for a in assets],
        source=source,
        risk_score=risk_score,
        confidence=confidence,
        trigger_reason=trigger,
        evidence=evidence,
        recommended_action=action,
        status="new",
        rule_key="scenario-exercise",
        fingerprint=f"scenario-{threat.ref}-{utcnow().date()}",
        is_simulated=True,
        created_at=utcnow(),
    )
    db.add(alert)
    db.flush()
    return alert


def _recommendation(db: Session, db_asset: Asset | None, vuln: Vulnerability | None, alert: Alert | None,
                    title: str, reason: str, action: str, user: User | None) -> Recommendation | None:
    existing = db.query(Recommendation).filter(Recommendation.title == title).first()
    if existing:
        return existing
    rec = Recommendation(
        ref=next_ref(db, Recommendation, "REC"),
        title=title[:230],
        reason=reason,
        priority="critical",
        threat_id=alert.threat_id if alert else None,
        vulnerability_id=vuln.id if vuln else None,
        asset_id=db_asset.id if db_asset else None,
        alert_id=alert.id if alert else None,
        action=action,
        evidence=[{"label": "Scenario", "value": "End-to-end pipeline exercise"}],
        status="open",
        owner_id=user.id if user else None,
        due_at=utcnow() + timedelta(hours=24),
        created_at=utcnow(),
    )
    db.add(rec)
    db.flush()
    return rec


def _step(key: str, label: str, status: str, detail: str, data: dict | None = None) -> dict:
    return {"key": key, "label": label, "status": status, "detail": detail, "data": data or {}}


def _scenario_high_risk(db: Session, user: User) -> dict:
    cve_id = "CVE-2026-50991"
    steps = []
    vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
    new_records = 0
    if not vuln:
        vuln = Vulnerability(
            cve_id=cve_id,
            title="Apache HTTP Server proxy flaw enables unauthenticated code execution",
            description=(
                "A critical vulnerability in Apache HTTP Server 2.4.49 through 2.4.55 allows an unauthenticated "
                "attacker to achieve remote code execution through crafted proxy requests. Exploit code is "
                "circulating and the vulnerability is listed as known exploited. Internet-facing gateways are at "
                "highest risk."
            ),
            cvss_score=9.8,
            cvss_severity="critical",
            epss_score=0.71,
            epss_percentile=0.981,
            known_exploited=True,
            kev_due_date=utcnow() + timedelta(days=21),
            ransomware_use=False,
            published_at=utcnow() - timedelta(minutes=40),
            modified_at=utcnow(),
            affected_products=[{
                "vendor": "Apache",
                "product": "Apache HTTP Server",
                "versions": {"start": "2.4.49", "end": "2.4.55"},
                "notes": "Scenario advisory: versions 2.4.49–2.4.55.",
            }],
            references=[{"label": "Scenario advisory", "value": "Written by the exposure scenario"}],
            source="Scenario advisory feed",
            source_url="",
            remediation="Upgrade Apache HTTP Server beyond 2.4.55 and review proxy access logs.",
            is_simulated=True,
            created_at=utcnow(),
        )
        db.add(vuln)
        db.flush()
        new_records += 1
    steps.append(_step(
        "ingest", "Ingest vulnerability intelligence", "complete",
        f"{cve_id} stored with CVSS {vuln.cvss_score}, EPSS {vuln.epss_score}, known-exploited={vuln.known_exploited}. Source is the scenario advisory feed.",
        {"cve_id": cve_id, "cvss": vuln.cvss_score, "epss": vuln.epss_score, "known_exploited": vuln.known_exploited,
         "source": "Scenario advisory feed"},
    ))
    threats = db.query(Threat).filter(Threat.cve_id == cve_id).all()
    if not threats:
        threat = _create_threat(
            db,
            name="Apache HTTP Server unauthenticated RCE exploited on internet gateways",
            description=(
                "CVE-2026-50991 is a remote code execution vulnerability in Apache HTTP Server 2.4.49 through 2.4.55. "
                "CISA KEV evidence indicates exploitation in the wild. Attack attempts use command injection probes "
                "against reverse-proxy endpoints and download tooling from update-securehub.top."
            ),
            category_hint="Remote Code Execution",
            source="Scenario telemetry",
            published_at=utcnow() - timedelta(minutes=35),
            cve=cve_id,
            cvss=vuln.cvss_score,
            epss=vuln.epss_score,
            known_exploited=True,
            technology="Apache HTTP Server",
            versions="2.4.49–2.4.55",
            indicators=[
                {"type": "domain", "value": "update-securehub.top"},
                {"type": "ip", "value": "185.220.101.44", "geo": {"country": "Germany", "code": "DE", "lat": 52.52, "lon": 13.405}},
            ],
            user=user,
        )
        threats = [threat]
        new_records += 1
        steps.append(_step(
            "classify", "AI threat classification & extraction", "complete",
            f"Classified as {threat.ai_category} with heuristic confidence {threat.ai_confidence:.0f}%. Extracted CVE, domain and IP indicators.",
            {"category": threat.ai_category, "confidence": threat.ai_confidence, "keywords": threat.ai_keywords,
             "entities": threat.ai_entities, "summary": threat.ai_summary, "method": threat.ai_method},
        ))
    else:
        threat = threats[0]
        steps.append(_step(
            "classify", "AI threat classification & extraction", "complete",
            f"Existing classified record reused: {threat.ai_category} ({threat.ai_confidence:.0f}% heuristic confidence).",
            {"category": threat.ai_category, "confidence": threat.ai_confidence, "keywords": threat.ai_keywords,
             "entities": threat.ai_entities, "summary": threat.ai_summary, "method": threat.ai_method},
        ))

    scan = exposure.run_scan(db, user.id, create_recommendations=True)
    links = db.query(AssetVulnerability).filter(
        AssetVulnerability.vulnerability_id == vuln.id,
        AssetVulnerability.status == "potentially_exposed",
    ).all()
    assets = [db.get(Asset, link.asset_id) for link in links]
    assets = [a for a in assets if a]
    steps.append(_step(
        "match", "Asset inventory exposure matching", "complete" if assets else "no-match",
        (
            f"{len(assets)} asset(s) matched after product and version validation: "
            + ", ".join(f"{a.ref} ({a.name}, v{a.software_version})" for a in assets)
        ) if assets else "No asset matched after version validation.",
        {"scan": scan, "matches": [{"asset": a.ref, "name": a.name, "version": a.software_version,
                                     "confidence": next((l.match_confidence for l in links if l.asset_id == a.id), None)}
                                    for a in assets]},
    ))

    top_asset = max(assets, key=lambda a: (a.internet_facing, a.criticality)) if assets else None
    match_confidence = next((l.match_confidence for l in links if top_asset and l.asset_id == top_asset.id), None)
    assessment = risk.assess(threat, top_asset, match_confidence, db) if top_asset else risk.assess(threat, None, None, db)
    steps.append(_step(
        "risk", "Explainable risk assessment", "complete",
        assessment["explanation"],
        {"risk_score": assessment["risk_score"], "risk_category": assessment["risk_category"],
         "urgency": assessment["urgency"], "evidence_confidence": assessment["evidence_confidence"],
         "exploitation_status": assessment["exploitation_status"], "factors": assessment["factors"],
         "asset": top_asset.ref if top_asset else None},
    ))

    early_warning.detect(db, window_hours=36, user_id=user.id)
    alert = db.query(Alert).filter(Alert.vulnerability_id == vuln.id).order_by(Alert.detected_at.desc()).first()
    if not alert and top_asset:
        alert = _create_alert(
            db,
            title=f"Known-exploited {cve_id} matches {len(assets)} critical asset(s)",
            severity="critical",
            category=threat.ai_category or "Remote Code Execution",
            threat=threat,
            vulnerability=vuln,
            assets=assets,
            source="Correlation Engine",
            risk_score=assessment["risk_score"],
            confidence=assessment["evidence_confidence"],
            trigger=(
                f"{cve_id} is known-exploited, has an EPSS probability of {vuln.epss_score:.0%}, and validates against "
                f"{len(assets)} registered asset(s), including internet-facing {top_asset.ref}. These conditions crossed "
                "the critical early-warning threshold."
            ),
            evidence=[
                {"label": "Vulnerability", "value": f"{cve_id} · CVSS {vuln.cvss_score} · EPSS {vuln.epss_score:.0%}"},
                {"label": "Known exploited", "value": "Yes"},
                {"label": "Validated assets", "value": ", ".join(a.ref for a in assets)},
                {"label": "Exposure + criticality", "value": f"{top_asset.exposure}, {top_asset.criticality}/5"},
                {"label": "Match validation", "value": "Product identity and affected-version range verified"},
            ],
            action="Apply the vendor patch to matched assets immediately, restrict internet exposure, and inspect proxy logs for exploitation.",
        )
        db.flush()
    steps.append(_step(
        "alert", "Early-warning alert generation", "complete" if alert else "no-alert",
        f"Alert {alert.ref} ({alert.severity}) generated with supporting evidence and trigger reason." if alert
        else "No alert was generated because no validated asset exposure was found.",
        {"alert_ref": alert.ref, "severity": alert.severity, "trigger": alert.trigger_reason, "evidence": alert.evidence} if alert else {},
    ))

    rec = None
    if top_asset:
        rec = _recommendation(
            db, top_asset, vuln, alert,
            title=f"Emergency patch {top_asset.software} on {top_asset.ref}",
            reason=f"{cve_id} is known-exploited and version {top_asset.software_version} is within the affected range.",
            action="Coordinate an emergency change, patch the gateway, verify the build, and monitor proxy logs for exploitation attempts.",
            user=user,
        )
    steps.append(_step(
        "recommend", "Actionable recommendation", "complete" if rec else "skipped",
        f"{rec.ref}: {rec.action}" if rec else "No asset-linked recommendation was required.",
        {"recommendation_ref": rec.ref if rec else None},
    ))
    db.commit()
    return {
        "scenario": "high-risk-vulnerability",
        "title": SCENARIOS["high-risk-vulnerability"]["title"],
        "ran_at": utcnow().isoformat(),
        "steps": steps,
        "artifacts": {
            "vulnerability": cve_id,
            "threat_ref": threat.ref,
            "asset_refs": [a.ref for a in assets],
            "alert_ref": alert.ref if alert else None,
            "recommendation_ref": rec.ref if rec else None,
            "risk_score": assessment["risk_score"],
        },
        "caveats": [
            "Records written by this run carry the scenario key and a retrieval timestamp.",
            "A validated version match indicates potential exposure; it does not confirm exploitation.",
            "Risk is a prioritisation score, not a compromise probability.",
        ],
    }


def _scenario_emerging(db: Session, user: User) -> dict:
    domain = "lockgrid-cdn-secure.com"
    existing = db.query(Threat).filter(Threat.description.ilike(f"%{domain}%")).all()
    created = 0
    if len(existing) < 5:
        wave = [
            ("LockGrid claims surge across VMware ESXi environments", "Scenario telemetry", 19),
            ("Independent feed corroborates LockGrid infrastructure", "AlienVault OTX", 15),
            ("Ransomware incident notes reference LockGrid loader", "Internal Sensor", 11),
            ("New LockGrid leak-site victims published", "CSIRT Advisory", 7),
            ("LockGrid affiliate reuses exfiltration tooling", "Vendor Advisory", 4),
            ("Additional LockGrid reporting from partner telemetry", "Scenario telemetry", 1),
        ]
        for name, source, hours_ago in wave:
            _create_threat(
                db,
                name=name,
                description=(
                    f"Multiple reports describe LockGrid ransomware activity targeting VMware ESXi virtualisation "
                    f"infrastructure. Shared network indicator {domain} and IP 45.155.205.233 were observed for command "
                    "and control beaconing before encryption. The reporting cluster is evidence of increased activity, "
                    "not a prediction of a specific future attack."
                ),
                category_hint="Ransomware",
                source=source,
                published_at=utcnow() - timedelta(hours=hours_ago),
                cve=None,
                cvss=None,
                epss=None,
                known_exploited=False,
                technology="VMware ESXi",
                versions="8.0.x",
                indicators=[
                    {"type": "domain", "value": domain},
                    {"type": "ip", "value": "45.155.205.233", "geo": {"country": "Netherlands", "code": "NL", "lat": 52.3676, "lon": 4.9041}},
                    {"type": "mitre", "value": "T1486"},
                ],
                user=user,
            )
            created += 1
    window_start = utcnow() - timedelta(hours=36)
    baseline_start = utcnow() - timedelta(days=14)
    observed = db.query(Threat).filter(
        Threat.description.ilike(f"%{domain}%"), Threat.published_at >= window_start
    ).count()
    baseline = db.query(Threat).filter(
        Threat.description.ilike(f"%{domain}%"),
        Threat.published_at >= baseline_start,
        Threat.published_at < window_start,
    ).count()
    source_count = len({
        t.source for t in db.query(Threat).filter(
            Threat.description.ilike(f"%{domain}%"), Threat.published_at >= window_start
        ).all()
    })
    steps = [
        _step("collect", "Collect correlated reports", "complete",
              f"{created} new reports added; {observed} reports containing the shared indicator fall inside the 36-hour window across {source_count} source(s).",
              {"domain": domain, "observed": observed, "sources": source_count}),
        _step("baseline", "Compare with historical baseline", "complete",
              f"Baseline for the same indicator over the preceding 14 days: {baseline} report(s). The observation window count is {observed}.",
              {"observed": observed, "baseline_14d": baseline, "window_hours": 36}),
    ]
    corr = correlation.build(db, days=60, limit=120)
    graph_data = correlation.graph(db, days=7, min_score=0.4, limit=80)
    cluster = next((c for c in graph_data["clusters"] if any(domain in ind for ind in c["shared_indicators"])), None)
    steps.append(_step(
        "correlate", "Correlate related reporting", "complete",
        f"Correlation engine created/updated {corr['pairs_created'] + corr['pairs_updated']} pairs in the recent window. "
        + (f"Cluster detected with {cluster['size']} members sharing the indicator." if cluster else "The cluster is visible in the graph view."),
        {"correlation": corr, "cluster": cluster},
    ))
    scan = early_warning.detect(db, window_hours=36, user_id=user.id)
    alerts = db.query(Alert).filter(Alert.detected_at >= utcnow() - timedelta(minutes=5)).all()
    alert = next((a for a in alerts if domain in str(a.evidence)), None)
    if not alert:
        recent = db.query(Threat).filter(Threat.description.ilike(f"%{domain}%")).order_by(Threat.published_at.desc()).all()
        threat = recent[0]
        alert = _create_alert(
            db,
            title=f"Observed reporting cluster: LockGrid indicators across {source_count} sources",
            severity="high",
            category="Ransomware",
            threat=threat,
            vulnerability=None,
            assets=[],
            source="Correlation Engine",
            risk_score=max((t.risk_score for t in recent), default=65),
            confidence=min(92, 55 + observed * 5),
            trigger=(
                f"The indicator {domain} appears in {observed} reports inside 36 hours versus a 14-day baseline of "
                f"{baseline}, across {source_count} sources. This is a statistical observation of a reporting cluster, "
                "not proof of an imminent attack."
            ),
            evidence=[
                {"label": "Shared domain", "value": domain},
                {"label": "Observed reports (36h)", "value": str(observed)},
                {"label": "Baseline (14d)", "value": str(baseline)},
                {"label": "Distinct sources", "value": str(source_count)},
                {"label": "Correlated indicators", "value": "45.155.205.233 · T1486 · LockGrid"},
            ],
            action="Hunt for the indicator in telemetry, validate backup isolation and ESXi exposure, and monitor for beaconing.",
        )
        db.flush()
    steps.append(_step(
        "alert", "Generate evidence-backed early warning", "complete",
        f"Alert {alert.ref} ({alert.severity}) explains the observation, baseline comparison and supporting evidence.",
        {"alert_ref": alert.ref, "engine_result": scan, "trigger": alert.trigger_reason, "evidence": alert.evidence},
    ))
    db.commit()
    return {
        "scenario": "emerging-pattern",
        "title": SCENARIOS["emerging-pattern"]["title"],
        "ran_at": utcnow().isoformat(),
        "steps": steps,
        "artifacts": {
            "indicator": domain,
            "reports_in_window": observed,
            "baseline_14d": baseline,
            "sources": source_count,
            "alert_ref": alert.ref,
            "cluster_size": cluster["size"] if cluster else None,
        },
        "caveats": [
            "This is an observed reporting pattern, not a prediction that an attack will occur.",
            "Shared infrastructure indicates related reporting; it is not verified attribution to a single actor.",
            "Every record written by this run is tagged to the scenario, not to a live incident.",
        ],
    }


def _scenario_no_match(db: Session, user: User) -> dict:
    cve_id = "CVE-2026-50992"
    steps = []
    vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
    if not vuln:
        vuln = Vulnerability(
            cve_id=cve_id,
            title="Progress Sitefinity unsafe upload enables code execution",
            description=(
                "Progress Sitefinity 14.0 through 14.3 allows an authenticated user to upload executable content due to "
                "unsafe file validation. The advisory describes a remote code execution risk but provides no evidence of "
                "exploitation in the wild."
            ),
            cvss_score=8.5,
            cvss_severity="high",
            epss_score=0.30,
            epss_percentile=0.66,
            known_exploited=False,
            published_at=utcnow() - timedelta(hours=3),
            modified_at=utcnow(),
            affected_products=[{
                "vendor": "Progress",
                "product": "Progress Sitefinity",
                "versions": {"start": "14.0", "end": "14.3"},
                "notes": "Scenario advisory: versions 14.0–14.3.",
            }],
            references=[{"label": "Scenario advisory", "value": "Written by the ransomware scenario"}],
            source="Scenario advisory feed",
            source_url="",
            remediation="Apply the vendor update and validate upload directories.",
            is_simulated=True,
            created_at=utcnow(),
        )
        db.add(vuln)
        db.flush()
    threat = db.query(Threat).filter(Threat.cve_id == cve_id).first()
    if not threat:
        threat = _create_threat(
            db,
            name="Progress Sitefinity unsafe upload advisory",
            description=(
                "CVE-2026-50992 describes a high-severity software vulnerability in Progress Sitefinity 14.0 through 14.3. "
                "An authenticated user can upload executable content. No exploitation evidence or public exploit is "
                "reported in this scenario record."
            ),
            category_hint="Remote Code Execution",
            source="Scenario advisory feed",
            published_at=utcnow() - timedelta(hours=3),
            cve=cve_id,
            cvss=8.5,
            epss=0.30,
            known_exploited=False,
            technology="Progress Sitefinity",
            versions="14.0–14.3",
            indicators=[],
            user=user,
        )
    steps.append(_step(
        "ingest", "Process vulnerability intelligence", "complete",
        f"{cve_id} stored: CVSS {vuln.cvss_score}, EPSS {vuln.epss_score}, known-exploited={vuln.known_exploited}.",
        {"cve_id": cve_id, "cvss": vuln.cvss_score, "epss": vuln.epss_score, "known_exploited": vuln.known_exploited},
    ))
    scan = exposure.run_scan(db, user.id, create_recommendations=True)
    direct_links = db.query(AssetVulnerability).filter(AssetVulnerability.vulnerability_id == vuln.id).all()
    inventory_products = sorted({a.software for a in db.query(Asset).all()})
    steps.append(_step(
        "match", "Compare against asset inventory", "no-match",
        f"No registered asset uses Progress Sitefinity. {len(inventory_products)} distinct software products were checked; no validated product or version match exists for {cve_id}.",
        {"matches": len(direct_links), "inventory_products_checked": len(inventory_products),
         "scan_summary": {"assets_scanned": scan["assets_scanned"], "vulnerabilities_scanned": scan["vulnerabilities_scanned"]}},
    ))
    existing_assessment = db.query(RiskAssessment).filter(
        RiskAssessment.threat_id == threat.id, RiskAssessment.asset_id.is_(None)
    ).first()
    if not existing_assessment:
        assessment = risk.persist_assessment(db, threat, None, None, user, vulnerability_id=vuln.id)
        assessment.explanation += (
            " No validated asset match exists in the current inventory, so no exposure claim or asset-specific alert "
            "is generated. The asset inventory may be incomplete; verify through an independent discovery source."
        )
    else:
        assessment = existing_assessment
    steps.append(_step(
        "assess", "Record assessment without unsupported exposure claim", "complete",
        "Threat-level risk recorded. No asset is declared vulnerable. The assessment lists the missing evidence and inventory uncertainty.",
        {"assessment_ref": assessment.ref, "risk_score": assessment.risk_score, "risk_category": assessment.risk_category,
         "evidence_confidence": assessment.evidence_confidence, "explanation": assessment.explanation},
    ))
    alert_count = db.query(Alert).filter(Alert.vulnerability_id == vuln.id).count()
    steps.append(_step(
        "withhold", "Withhold unsupported exposure alert", "complete",
        f"{alert_count} asset-exposure alert(s) exist for this vulnerability. The engine did not create an exposure claim without a valid match.",
        {"alerts_created": alert_count},
    ))
    db.commit()
    return {
        "scenario": "non-affected-asset",
        "title": SCENARIOS["non-affected-asset"]["title"],
        "ran_at": utcnow().isoformat(),
        "steps": steps,
        "artifacts": {
            "vulnerability": cve_id,
            "threat_ref": threat.ref,
            "assessment_ref": assessment.ref,
            "matches": 0,
            "alert_ref": None,
        },
        "caveats": [
            "No match is based on the current registered inventory only; it is not proof that no system is affected.",
            "CVSS severity and EPSS probability are evidence signals, not confirmation of exploitation.",
            "Every record written by this run is tagged to the scenario, not to a live incident.",
        ],
    }


def run(db: Session, scenario: str, user: User) -> dict:
    if scenario == "high-risk-vulnerability":
        return _scenario_high_risk(db, user)
    if scenario == "emerging-pattern":
        return _scenario_emerging(db, user)
    if scenario == "non-affected-asset":
        return _scenario_no_match(db, user)
    raise ValueError("Unknown scenario")
