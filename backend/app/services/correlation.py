"""Threat correlation: shared entities, lexical similarity and campaign clusters."""
import re
from collections import Counter, defaultdict
from datetime import timedelta

from sqlalchemy.orm import Session

from ..models import Threat, ThreatCorrelation, utcnow
from .classifier import STOPWORDS

_TOKEN_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9\-]{3,}")


def _tokens(threat: Threat) -> set[str]:
    text = f"{threat.name} {threat.description} {threat.affected_technology or ''}".lower()
    return {t for t in _TOKEN_RE.findall(text) if t not in STOPWORDS}


def _indicator_values(threat: Threat) -> set[str]:
    return {str(i.get("value", "")).lower() for i in threat.indicators or [] if i.get("value")}


def _jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def compare(a: Threat, b: Threat) -> dict | None:
    score = 0.0
    reasons: list[dict] = []
    if a.cve_id and b.cve_id and a.cve_id.lower() == b.cve_id.lower():
        score += 0.45
        reasons.append({"type": "shared-cve", "label": f"Shared CVE {a.cve_id}", "weight": 0.45})
    shared_indicators = _indicator_values(a) & _indicator_values(b)
    if shared_indicators:
        bonus = min(0.55, 0.32 + 0.08 * (len(shared_indicators) - 1))
        score += bonus
        reasons.append({
            "type": "shared-indicator",
            "label": f"{len(shared_indicators)} shared indicator(s): {', '.join(sorted(shared_indicators)[:3])}",
            "weight": round(bonus, 2),
        })
    if a.affected_technology and b.affected_technology and a.affected_technology.lower() == b.affected_technology.lower():
        score += 0.12
        reasons.append({"type": "shared-product", "label": f"Same product: {a.affected_technology}", "weight": 0.12})
    if a.ai_category and a.ai_category == b.ai_category:
        score += 0.05
        reasons.append({"type": "same-classification", "label": f"Same AI classification: {a.ai_category}", "weight": 0.05})
    lexical = _jaccard(_tokens(a), _tokens(b))
    if lexical >= 0.18:
        score += min(0.35, lexical * 0.45)
        reasons.append({"type": "text-similarity", "label": f"Description token similarity {lexical * 100:.0f}%", "weight": round(lexical * 0.45, 2)})
    if a.published_at and b.published_at:
        gap = abs((a.published_at - b.published_at).total_seconds()) / 86400
        if gap <= 3:
            score += 0.1
            reasons.append({"type": "time-proximity", "label": f"Published {gap:.1f} days apart", "weight": 0.1})
        elif gap <= 7:
            score += 0.05
            reasons.append({"type": "time-proximity", "label": f"Published {gap:.1f} days apart", "weight": 0.05})
    score = round(min(0.99, score), 3)
    if score < 0.42 or not reasons:
        return None
    return {"score": score, "reasons": reasons, "method": "entity-overlap+lexical"}


def build(db: Session, days: int = 180, limit: int = 180) -> dict:
    cutoff = utcnow() - timedelta(days=days)
    threats = (
        db.query(Threat)
        .filter(Threat.published_at >= cutoff)
        .order_by(Threat.published_at.desc())
        .limit(limit)
        .all()
    )
    existing = {(c.threat_a_id, c.threat_b_id): c for c in db.query(ThreatCorrelation).all()}
    created = updated = 0
    for i, a in enumerate(threats):
        for b in threats[i + 1:]:
            pair = (min(a.id, b.id), max(a.id, b.id))
            result = compare(a, b)
            if not result:
                if pair in existing:
                    db.delete(existing[pair])
                continue
            current = existing.get(pair)
            if current:
                current.score = result["score"]
                current.reasons = result["reasons"]
                current.method = result["method"]
                updated += 1
            else:
                db.add(ThreatCorrelation(
                    threat_a_id=pair[0], threat_b_id=pair[1], score=result["score"],
                    reasons=result["reasons"], method=result["method"], created_at=utcnow(),
                ))
                created += 1
    db.commit()
    return {"threats_considered": len(threats), "pairs_created": created, "pairs_updated": updated}


def graph(db: Session, days: int = 90, min_score: float = 0.45, limit: int = 120) -> dict:
    cutoff = utcnow() - timedelta(days=days)
    threats = (
        db.query(Threat)
        .filter(Threat.published_at >= cutoff)
        .order_by(Threat.published_at.desc())
        .limit(limit)
        .all()
    )
    by_id = {t.id: t for t in threats}
    correlations = db.query(ThreatCorrelation).all()
    edges = []
    degree: dict[int, int] = defaultdict(int)
    cluster_map: dict[int, dict] = {}
    for record in correlations:
        if record.score < min_score or record.threat_a_id not in by_id or record.threat_b_id not in by_id:
            continue
        a, b = by_id[record.threat_a_id], by_id[record.threat_b_id]
        edges.append({
            "id": record.id,
            "source": a.ref,
            "target": b.ref,
            "source_id": a.id,
            "target_id": b.id,
            "score": record.score,
            "reasons": record.reasons,
            "method": record.method,
        })
        degree[a.id] += 1
        degree[b.id] += 1
    parent = {tid: tid for tid in by_id}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: int, y: int):
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[ry] = rx

    for edge in edges:
        union(edge["source_id"], edge["target_id"])
    groups: dict[int, list[int]] = defaultdict(list)
    for tid in by_id:
        groups[find(tid)].append(tid)
    clusters = []
    for member_ids in groups.values():
        if len(member_ids) < 3:
            continue
        members = [by_id[i] for i in member_ids]
        indicators = Counter(
            str(ind.get("value")) for m in members for ind in (m.indicators or []) if ind.get("value")
        )
        cves = Counter(m.cve_id for m in members if m.cve_id)
        products = Counter(m.affected_technology for m in members if m.affected_technology)
        label = (
            (products.most_common(1)[0][0] if products else None)
            or (cves.most_common(1)[0][0] if cves else "Correlated activity")
        )
        clusters.append({
            "id": f"cluster-{find(member_ids[0])}",
            "label": f"Campaign cluster: {label}",
            "size": len(members),
            "max_risk": max((m.risk_score or 0) for m in members),
            "max_severity": max(members, key=lambda m: m.risk_score or 0).severity,
            "first_seen": min(m.published_at for m in members).isoformat(),
            "last_seen": max(m.published_at for m in members).isoformat(),
            "shared_cves": [cve for cve, _ in cves.most_common(3)],
            "shared_indicators": [value for value, _ in indicators.most_common(3)],
            "threat_refs": [m.ref for m in sorted(members, key=lambda m: m.risk_score or 0, reverse=True)[:8]],
            "categories": list({m.ai_category or m.category for m in members}),
        })
    clusters.sort(key=lambda c: (c["size"], c["max_risk"]), reverse=True)
    nodes = [
        {
            "id": t.id,
            "ref": t.ref,
            "name": t.name,
            "category": t.ai_category or t.category,
            "severity": t.severity,
            "risk": t.risk_score,
            "published_at": t.published_at.isoformat(),
            "technology": t.affected_technology,
            "degree": degree[t.id],
            "saved": t.is_saved,
        }
        for t in threats
    ]
    return {
        "generated_at": utcnow().isoformat(),
        "nodes": nodes,
        "edges": edges,
        "clusters": clusters,
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "clusters": len(clusters),
            "avg_score": round(sum(e["score"] for e in edges) / len(edges), 3) if edges else 0,
            "isolated_nodes": sum(1 for n in nodes if n["degree"] == 0),
        },
    }
