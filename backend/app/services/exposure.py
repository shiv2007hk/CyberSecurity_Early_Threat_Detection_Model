"""Asset inventory exposure matching with product and version validation."""
import re

from sqlalchemy.orm import Session

from ..models import Asset, AssetVulnerability, Recommendation, Threat, Vulnerability, utcnow
from ..utils import version_matches
from . import risk
from .refs import next_ref


def _norm(value: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (value or "").lower()).strip()


PRODUCT_ALIASES = {
    "http server": ["apache http server", "apache", "httpd", "http server"],
    "apache tomcat": ["tomcat", "apache tomcat"],
    "exchange server": ["exchange", "microsoft exchange", "exchange server"],
    "netweaver": ["sap netweaver", "netweaver"],
    "confluence": ["atlassian confluence", "confluence"],
    "jira": ["atlassian jira", "jira"],
    "fortios": ["fortinet fortios", "fortigate", "fortios"],
    "ios xe": ["cisco ios xe", "ios xe"],
    "pan os": ["palo alto pan os", "pan os", "palo alto"],
    "netscaler": ["citrix netscaler", "netscaler", "adc"],
}


def _product_candidates(product: str) -> list[str]:
    normalized = _norm(product)
    candidates = {normalized, normalized.replace(" ", "")}
    for canonical, aliases in PRODUCT_ALIASES.items():
        if canonical in normalized or normalized in canonical:
            candidates.update({_norm(a) for a in aliases})
    return {c for c in candidates if len(c) >= 4}


def product_matches(asset_software: str, product: str, vendor: str | None = None) -> tuple[bool, str]:
    asset_norm = f" {_norm(asset_software)} "
    vendor_norm = _norm(vendor)
    candidates = _product_candidates(product)
    for candidate in candidates:
        if f" {candidate} " in asset_norm or asset_norm.strip() == candidate:
            if vendor_norm and vendor_norm not in asset_norm and _norm(asset_software) not in vendor_norm:
                # Vendor mismatch is not fatal for aliases such as "apache" but lowers the match strength.
                return True, "product-name-alias"
            return True, "product-name-exact"
    return False, "no-product-match"


def match_vulnerability(vuln: Vulnerability, asset: Asset) -> dict | None:
    """Validate product identity and version ranges. Loose text overlap is never enough."""
    best = None
    for entry in vuln.affected_products or []:
        product = entry.get("product") or ""
        vendor = entry.get("vendor")
        if not product:
            continue
        matched, strength = product_matches(asset.software, product, vendor)
        if not matched:
            continue
        versions = entry.get("versions") or {}
        if versions.get("all_versions"):
            validated = True
            reason = f"Product matched and vendor states all versions are affected."
        elif versions.get("exact"):
            validated = str(asset.software_version).strip().lower() in {
                str(v).strip().lower() for v in versions["exact"]
            }
            reason = f"Asset version {asset.software_version} {'is' if validated else 'is not'} in the supplied exact-version list."
            if not validated:
                continue
        elif versions.get("start") or versions.get("end"):
            validated = version_matches(asset.software_version, versions)
            range_text = f"{versions.get('start', 'earliest')} – {versions.get('end', 'latest')}"
            reason = (
                f"Asset version {asset.software_version} is {'within' if validated else 'outside'} the affected range {range_text}."
            )
            if not validated:
                continue
        else:
            validated = False
            reason = (
                f"Product name matched but no affected-version range was supplied; exposure is unverified "
                f"and must not be treated as confirmed."
            )
        confidence = 96 if validated else 58
        if strength == "product-name-alias":
            confidence -= 6
        if not validated:
            confidence = min(confidence, 58)
        candidate = {
            "validated": validated,
            "confidence": confidence,
            "status": "potentially_exposed" if validated else "needs_verification",
            "reason": f"{reason} Product match strength: {strength}.",
            "product": product,
            "vendor": vendor,
            "version_spec": versions,
        }
        if best is None or (candidate["validated"] and not best["validated"]) or candidate["confidence"] > best["confidence"]:
            best = candidate
        if candidate["validated"]:
            break
    return best


def _recommendation_for(db: Session, vuln: Vulnerability, asset: Asset, user_id: int | None) -> bool:
    action = f"Validate and patch {asset.software} {asset.software_version} on {asset.name} for {vuln.cve_id}."
    existing = (
        db.query(Recommendation)
        .filter(Recommendation.vulnerability_id == vuln.id, Recommendation.asset_id == asset.id)
        .first()
    )
    if existing:
        return False
    priority = "critical" if (vuln.known_exploited and vuln.cvss_score and vuln.cvss_score >= 9) else (
        "high" if (vuln.cvss_score or 0) >= 7 or vuln.known_exploited else "medium"
    )
    reason = (
        f"{vuln.cve_id} affects {asset.software} versions in the validated exposure range. "
        f"Asset is {asset.exposure} with criticality {asset.criticality}/5."
    )
    if vuln.known_exploited:
        reason += " The vulnerability is in the known-exploited evidence set."
    rec = Recommendation(
        ref=next_ref(db, Recommendation, "REC"),
        title=f"Remediate {vuln.cve_id} on {asset.ref}",
        reason=reason,
        priority=priority,
        vulnerability_id=vuln.id,
        asset_id=asset.id,
        action=action,
        evidence=[
            f"Product/version validation: {asset.software} {asset.software_version}",
            f"CVSS {vuln.cvss_score if vuln.cvss_score is not None else 'not supplied'}",
            f"Known exploited: {'yes' if vuln.known_exploited else 'no'}",
        ],
        status="open",
        owner_id=user_id,
        due_at=utcnow(),
        source_url=vuln.source_url,
        created_at=utcnow(),
    )
    if vuln.kev_due_date:
        rec.due_at = vuln.kev_due_date
    db.add(rec)
    return True


def run_scan(db: Session, user_id: int | None = None, create_recommendations: bool = True) -> dict:
    assets = db.query(Asset).all()
    vulns = db.query(Vulnerability).filter(Vulnerability.affected_products.isnot(None)).all()
    existing = {(m.asset_id, m.vulnerability_id): m for m in db.query(AssetVulnerability).all()}
    computed: dict[tuple[int, int], dict] = {}
    for vuln in vulns:
        for asset in assets:
            match = match_vulnerability(vuln, asset)
            if match:
                computed[(asset.id, vuln.id)] = match
    created = updated = removed = recommendations = 0
    for key, match in computed.items():
        asset_id, vuln_id = key
        current = existing.get(key)
        if current:
            if current.status == "confirmed":
                continue
            current.match_confidence = match["confidence"]
            current.match_reason = match["reason"]
            current.status = match["status"]
            updated += 1
        else:
            db.add(AssetVulnerability(
                asset_id=asset_id,
                vulnerability_id=vuln_id,
                match_confidence=match["confidence"],
                match_reason=match["reason"],
                status=match["status"],
                created_at=utcnow(),
            ))
            created += 1
        if create_recommendations and match["validated"]:
            vuln = db.get(Vulnerability, vuln_id)
            asset = db.get(Asset, asset_id)
            if _recommendation_for(db, vuln, asset, user_id):
                recommendations += 1
    for key, record in existing.items():
        if key not in computed and record.status in {"potentially_exposed", "needs_verification"}:
            db.delete(record)
            removed += 1
    db.commit()
    validated = sum(1 for m in computed.values() if m["validated"])
    return {
        "assets_scanned": len(assets),
        "vulnerabilities_scanned": len(vulns),
        "validated_matches": validated,
        "needs_verification": len(computed) - validated,
        "matches_created": created,
        "matches_updated": updated,
        "stale_matches_removed": removed,
        "recommendations_created": recommendations,
        "exposed_assets": len({k[0] for k, m in computed.items() if m["validated"]}),
        "scanned_at": utcnow().isoformat(),
    }


def asset_risk_summary(db: Session, asset: Asset) -> dict:
    links = db.query(AssetVulnerability).filter(AssetVulnerability.asset_id == asset.id).all()
    vulns = [db.get(Vulnerability, link.vulnerability_id) for link in links]
    vulns = [v for v in vulns if v]
    validated = [link for link in links if link.status == "potentially_exposed"]
    highest = 0.0
    for link in validated:
        vuln = db.get(Vulnerability, link.vulnerability_id)
        threat = db.query(Threat).filter(Threat.cve_id == vuln.cve_id).first() if vuln else None
        if threat:
            highest = max(highest, risk.assess(threat, asset, link.match_confidence, db)["risk_score"])
        elif vuln:
            severity = min(10.0, vuln.cvss_score or 5)
            exploit = 10.0 if vuln.known_exploited else min(10.0, (vuln.epss_score or 0) * 10)
            weights = risk.get_risk_config(db)["weights"]
            components = {
                "severity": {"value": severity},
                "exploitability": {"value": exploit},
                "exposure": {"value": 9.5 if asset.internet_facing else 5.0},
                "asset_criticality": {"value": asset.criticality * 2},
                "evidence_strength": {"value": 7.0},
            }
            highest = max(highest, risk.compute_score(components, weights))
    return {
        "risk_score": round(highest, 1),
        "risk_category": risk.category_for(highest, risk.get_risk_config(db)["thresholds"]),
        "matched_vulnerabilities": len(vulns),
        "validated_vulnerabilities": len(validated),
        "needs_verification": len(links) - len(validated),
        "known_exploited": sum(1 for v in vulns if v.known_exploited),
        "matches": [
            {
                "vulnerability_id": link.vulnerability_id,
                "cve_id": next((v.cve_id for v in vulns if v.id == link.vulnerability_id), ""),
                "status": link.status,
                "confidence": link.match_confidence,
                "reason": link.match_reason,
                "cvss": next((v.cvss_score for v in vulns if v.id == link.vulnerability_id), None),
                "known_exploited": next((v.known_exploited for v in vulns if v.id == link.vulnerability_id), False),
            }
            for link in links
        ],
    }
