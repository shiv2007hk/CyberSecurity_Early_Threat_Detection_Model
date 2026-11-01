"""Offline threat classifier: entity extraction, keyword scoring and explanation.

This is a transparent, deterministic keyword/lexicon scorer. It is not a trained
neural network and claims no learned accuracy. `METHOD` names the technique as it
is, so the interface never presents rule matching as model inference.
"""
import math
import re
from collections import Counter

METHOD = "keyword-lexicon"
OTHER = "Other"

CATEGORY_LEXICON: dict[str, list[tuple[str, float]]] = {
    "Ransomware": [
        ("ransomware", 6), ("ransom", 4), ("extortion", 4), ("leak site", 4),
        ("double extortion", 6), ("encrypts files", 4), ("lockbit", 4), ("clop", 3),
        ("akira", 3), ("blackcat", 3), ("alphv", 3), ("play ransomware", 4), ("medusa", 2),
    ],
    "Phishing": [
        ("phishing", 6), ("credential harvesting", 5), ("smishing", 5), ("email lure", 4),
        ("malicious attachment", 3), ("fake login", 4), ("spoofed", 3), ("vishing", 4),
        ("business email compromise", 4), ("quishing", 4), ("typosquat", 3),
    ],
    "Remote Code Execution": [
        ("remote code execution", 7), ("rce", 6), ("arbitrary code", 5), ("execute arbitrary", 5),
        ("deserialization", 4), ("command injection", 5), ("unauthenticated attacker", 2),
        ("code execution", 4), ("memory corruption", 2),
    ],
    "Denial of Service": [
        ("denial of service", 6), ("ddos", 6), ("dos", 3), ("resource exhaustion", 4),
        ("infinite loop", 2), ("service disruption", 2), ("packet flood", 4),
    ],
    "Credential Compromise": [
        ("account takeover", 5), ("authentication bypass", 5), ("stolen credentials", 6),
        ("credential stuffing", 5), ("session token", 3), ("kerberoasting", 5),
        ("mfa fatigue", 5), ("password spray", 5), ("token theft", 4), ("pass-the-hash", 5),
    ],
    "Data Breach": [
        ("data breach", 6), ("exfiltration", 5), ("stolen data", 5), ("leaked records", 6),
        ("database dump", 5), ("exposed records", 5), ("unauthorized data access", 4),
        ("customer data", 2), ("sensitive information", 2),
    ],
    "Supply Chain Compromise": [
        ("supply chain", 7), ("malicious package", 6), ("dependency confusion", 6),
        ("compromised update", 5), ("build pipeline", 4), ("signed installer", 3),
        ("npm package", 4), ("pypi package", 4), ("third-party component", 3),
    ],
    "Malware": [
        ("malware", 6), ("trojan", 5), ("backdoor", 5), ("botnet", 4), ("worm", 4),
        ("infostealer", 5), ("rootkit", 5), ("dropper", 3), ("loader", 2), ("rat", 3),
        ("spyware", 4), ("cryptominer", 4), ("qakbot", 3), ("emotet", 3), ("asyncrat", 3),
    ],
    "Software Vulnerability": [
        ("vulnerability", 4), ("cve-", 5), ("improper", 2), ("out-of-bounds", 4),
        ("use-after-free", 4), ("buffer overflow", 4), ("privilege escalation", 4),
        ("cvss", 3), ("patch", 1), ("flaw", 2), ("advisory", 1), ("affected versions", 2),
    ],
    "Suspicious Network Activity": [
        ("port scan", 5), ("brute force", 5), ("command and control", 6), ("beaconing", 5),
        ("c2", 4), ("lateral movement", 5), ("dns tunneling", 5), ("suspicious traffic", 4),
        ("anomalous connection", 4), ("scanner", 2),
    ],
}

PRODUCTS = {
    "Apache HTTP Server": ["apache http server", "apache", "httpd"],
    "OpenSSL": ["openssl"],
    "Windows Server": ["windows server", "windows"],
    "Linux Kernel": ["linux kernel", "linux"],
    "PostgreSQL": ["postgresql", "postgres"],
    "Cisco IOS XE": ["ios xe", "cisco"],
    "VMware ESXi": ["esxi", "vmware"],
    "Fortinet FortiOS": ["fortios", "fortinet", "fortigate"],
    "Google Chrome": ["chrome", "chromium"],
    "Kubernetes": ["kubernetes", "k8s"],
    "Zoom": ["zoom"],
    "Atlassian Confluence": ["confluence"],
    "Ivanti Connect Secure": ["ivanti", "connect secure"],
    "Atlassian Jira": ["jira"],
    "MySQL": ["mysql"],
    "Redis": ["redis"],
    "WordPress": ["wordpress"],
    "Drupal": ["drupal"],
    "Microsoft Exchange": ["exchange server", "exchange"],
    "Apache Tomcat": ["tomcat"],
    "nginx": ["nginx"],
    "GitLab": ["gitlab"],
    "SAP NetWeaver": ["netweaver", "sap"],
    "Oracle WebLogic": ["weblogic", "oracle"],
    "Citrix NetScaler": ["netscaler", "citrix"],
    "Palo Alto PAN-OS": ["pan-os", "palo alto"],
    "SonicWall": ["sonicwall"],
    "Zimbra": ["zimbra"],
    "Mozilla Firefox": ["firefox"],
    "Adobe Acrobat": ["adobe acrobat", "acrobat"],
    "Docker": ["docker"],
    "Elasticsearch": ["elasticsearch"],
    "Jenkins": ["jenkins"],
    "TeamCity": ["teamcity"],
    "MOVEit Transfer": ["moveit"],
    "SharePoint": ["sharepoint"],
    "Android": ["android"],
    "macOS": ["macos", "apple"],
    "Cisco ASA": ["cisco asa"],
}

MALWARE_FAMILIES = [
    "lockbit", "blackcat", "alphv", "cl0p", "clop", "akira", "play", "medusa",
    "qakbot", "emotet", "trickbot", "redline", "lumma", "cobalt strike", "asyncrat",
    "remcos", "mirai", "gootloader", "socgholish", "raccoon", "agenttesla", "lockgrid",
    "bumblebee", "icedid", "darkgate", "pikabot",
]

STOPWORDS = set(
    """a an the and or but if then than that this these those with without from into onto over under
    is are was were be been being has have had do does did can could may might must should would
    will of to in on for by as at it its their his her they them we our you your i not no nor so
    which who whom whose what when where why how about after before during while through between
    also more most other such only own same very just via using used use new known according
    security vulnerability threat attack report reports system systems issue issues information
    """.split()
)

ENTITY_PATTERNS = {
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "url": re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|onion|ai|co)\b", re.IGNORECASE),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "mitre": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
}


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def detect_products(text: str) -> list[str]:
    low = _normalise(text)
    found = []
    for product, aliases in PRODUCTS.items():
        if any(re.search(rf"\b{re.escape(alias)}\b", low) for alias in aliases):
            found.append(product)
    return found


def detect_malware(text: str) -> list[str]:
    low = _normalise(text)
    return [family for family in MALWARE_FAMILIES if family in low]


def extract_entities(text: str, known_products: list[str] | None = None) -> dict:
    text = text or ""
    entities: dict[str, list[str]] = {}
    for key, pattern in ENTITY_PATTERNS.items():
        matches = []
        seen = set()
        for match in pattern.findall(text):
            value = match if isinstance(match, str) else match[0]
            if value.lower() in seen:
                continue
            if key == "ipv4":
                parts = value.split(".")
                if any(int(p) > 255 for p in parts):
                    continue
                if value.startswith(("0.", "255.")):
                    continue
            seen.add(value.lower())
            matches.append(value)
        if matches:
            entities[key] = matches[:10]
    products = detect_products(text)
    if known_products:
        products = list(dict.fromkeys([*products, *known_products]))
    if products:
        entities["products"] = products
    families = detect_malware(text)
    if families:
        entities["malware_families"] = families
    return entities


def extract_keywords(text: str, limit: int = 10) -> list[str]:
    words = re.findall(r"[a-zA-Z][a-zA-Z0-9\-]{3,}", _normalise(text))
    counts = Counter(w for w in words if w not in STOPWORDS)
    return [word for word, _ in counts.most_common(limit)]


def classify(text: str, hint: str | None = None) -> dict:
    """Score `text` against the keyword lexicon.

    `hint` is an EXTERNAL signal only — a category the upstream source asserts
    itself (a feed's own label, an analyst's pre-tag). Never pass the record's
    stored category back in: that is the value being predicted, and feeding it
    here makes the result a restatement of the input rather than a classification.
    """
    low = _normalise(text)
    scores: dict[str, float] = {}
    matches: dict[str, list[str]] = {}
    for category, terms in CATEGORY_LEXICON.items():
        score = 0.0
        hit_terms = []
        for term, weight in terms:
            if term in low:
                score += weight
                hit_terms.append(term)
        if score:
            scores[category] = score
            matches[category] = hit_terms
    if hint:
        scores[hint] = scores.get(hint, 0) + 3.5
        matches.setdefault(hint, []).append(f"external hint: {hint}")
    if not scores:
        fallback = "Software Vulnerability" if re.search(r"cve-\d{4}", low) else OTHER
        return {
            "category": fallback,
            "confidence": 0.35,
            "scores": {fallback: 1},
            "evidence_terms": {fallback: []},
            "method": METHOD,
        }
    total = sum(scores.values())
    ordered = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    top_category, top_score = ordered[0]
    runner_up = ordered[1][1] if len(ordered) > 1 else 0
    margin = (top_score - runner_up) / max(top_score, 1)
    confidence = (top_score / total) * 0.65 + margin * 0.25 + 0.1
    return {
        "category": top_category,
        "confidence": round(min(0.97, max(0.3, confidence)), 3),
        "scores": {k: round(v, 2) for k, v in scores.items()},
        "evidence_terms": matches,
        "method": METHOD,
    }


def summarise(name: str, description: str, source: str, technology: str | None,
              indicators: list | None = None, cvss: float | None = None) -> str:
    entities = extract_entities(f"{name}. {description}")
    indicator_count = len(indicators or [])
    first_sentence = re.split(r"(?<=[.!?])\s+", description.strip())[0][:240]
    tech = technology or (entities.get("products") or ["an unspecified product"])[0]
    parts = [
        f"{name} is reported as activity affecting {tech}.",
        f"Recorded severity evidence: CVSS {cvss:.1f}." if cvss else "No CVSS score was supplied with this record.",
        f"The report contains {indicator_count} structured indicator(s)." if indicator_count
        else "No structured indicators were supplied with this record.",
    ]
    if first_sentence and first_sentence.lower() not in name.lower():
        parts.append(f"Source extract: “{first_sentence}”")
    parts.append(
        f"Summary generated by the offline NLP pipeline from {source} text; it summarises the source record and does not independently verify it."
    )
    return " ".join(parts)


def explain(name: str, classification: dict, entities: dict, indicators: list,
            cvss: float | None, epss: float | None, known_exploited: bool,
            technology: str | None, source_reliability: int, recommended_action: str) -> dict:
    contributing = []
    for term in classification.get("evidence_terms", {}).get(classification["category"], [])[:6]:
        contributing.append(f"Lexical evidence: “{term}”")
    if cvss:
        contributing.append(f"CVSS base score {cvss:.1f}")
    if epss is not None:
        contributing.append(f"EPSS probability {epss * 100:.1f}%")
    if known_exploited:
        contributing.append("Listed in the known-exploited evidence set")
    if indicators:
        contributing.append(f"{len(indicators)} structured indicator(s)")
    contributing.append(f"Source reliability rating {source_reliability}/100")
    missing = []
    if cvss is None:
        missing.append("CVSS score")
    if epss is None:
        missing.append("EPSS probability")
    if not indicators:
        missing.append("structured indicators")
    if not technology:
        missing.append("affected product identification")
    if not entities.get("cve"):
        missing.append("CVE identifier")
    return {
        "what_was_detected": f"Classified as {classification['category']} with heuristic confidence {classification['confidence'] * 100:.0f}%.",
        "contributing_indicators": contributing,
        "supporting_evidence": [
            "Classified from the supplied summary text using transparent keyword rules.",
            f"Record sourced from {name and 'the referenced intelligence source'}; source reliability informs evidence confidence.",
        ],
        "why_it_matters": (
            f"Potential impact relates to {technology or 'the affected technology'}. "
            "Importance is elevated where exploitation evidence exists or the product is present in the asset inventory."
        ),
        "potentially_affected_systems": [technology] if technology else ["Not determined from this record"],
        "recommended_action": recommended_action,
        "missing_information": missing,
        "disclaimer": "AI-assisted assessment from unverified source text; not a confirmed statement of compromise.",
    }


# Curated classification benchmark (author-written).
EVAL_SET = [
    ("A ransomware crew encrypted hospital file servers and posted a leak-site notice demanding payment.", "Ransomware"),
    ("LockBit affiliate deployed ransomware encrypting VMware ESXi datastores.", "Ransomware"),
    ("Double extortion operation threatens to publish stolen records unless a ransom is paid.", "Ransomware"),
    ("Phishing emails impersonating payroll deliver a malicious attachment harvesting credentials.", "Phishing"),
    ("A smishing campaign spoofs a bank login page to steal one-time codes.", "Phishing"),
    ("Business email compromise lure uses a fake invoice link to harvest passwords.", "Phishing"),
    ("The vulnerability allows unauthenticated remote code execution via a crafted request.", "Remote Code Execution"),
    ("A deserialization flaw enables arbitrary code execution on vulnerable servers.", "Remote Code Execution"),
    ("Command injection in the management interface permits an attacker to run code as root.", "Remote Code Execution"),
    ("A packet flood causes denial of service and resource exhaustion on the gateway.", "Denial of Service"),
    ("Attackers launched a DDoS campaign disrupting public services.", "Denial of Service"),
    ("An infinite loop in request parsing leads to service disruption.", "Denial of Service"),
    ("Stolen session tokens enabled account takeover across customer portals.", "Credential Compromise"),
    ("Credential stuffing against the identity provider led to password spray follow-up.", "Credential Compromise"),
    ("Kerberoasting allowed the actor to crack service account credentials.", "Credential Compromise"),
    ("Exfiltration of customer data resulted in a data breach affecting sensitive information.", "Data Breach"),
    ("A database dump containing leaked records appeared on a criminal forum.", "Data Breach"),
    ("Unauthorized data access exposed exposed records from a marketing database.", "Data Breach"),
    ("A malicious npm package was published in a supply chain attack targeting developers.", "Supply Chain Compromise"),
    ("Dependency confusion in the build pipeline delivered a compromised update.", "Supply Chain Compromise"),
    ("A signed installer was trojanised as part of a third-party component compromise.", "Supply Chain Compromise"),
    ("Malware loader installs an info-stealer and establishes a backdoor.", "Malware"),
    ("The botnet recruits IoT devices and drops a rootkit.", "Malware"),
    ("A trojan payload is distributed through malicious advertising.", "Malware"),
    ("The record documents CVE-2026-48211, an improper input validation vulnerability with a CVSS score of 9.8 affecting Apache HTTP Server.", "Software Vulnerability"),
    ("A use-after-free flaw in the affected versions can lead to privilege escalation.", "Software Vulnerability"),
    ("An out-of-bounds write vulnerability was patched in the advisory.", "Software Vulnerability"),
    ("Beaconing traffic to command and control infrastructure suggests lateral movement.", "Suspicious Network Activity"),
    ("Port scanning and brute force attempts were observed against VPN endpoints.", "Suspicious Network Activity"),
    ("DNS tunneling carried C2 traffic from an internal host.", "Suspicious Network Activity"),
]


def evaluate() -> dict:
    labels = sorted({label for _, label in EVAL_SET})
    # OTHER is a real output of classify(), so it gets its own row. Without it, any
    # out-of-scheme prediction would crash the false-positive accounting below.
    rows = [*labels, OTHER]
    confusion = {actual: {pred: 0 for pred in rows} for actual in rows}
    correct = 0
    per_category = {label: {"tp": 0, "fp": 0, "fn": 0} for label in rows}
    for text, actual in EVAL_SET:
        predicted = classify(text)["category"]
        if predicted not in rows:
            predicted = OTHER
        confusion[actual][predicted] += 1
        if predicted == actual:
            correct += 1
            per_category[actual]["tp"] += 1
        else:
            per_category[actual]["fn"] += 1
            per_category[predicted]["fp"] += 1
    precisions, recalls, f1s = [], [], []
    # Macro averages cover the labelled categories only; OTHER is reported for
    # completeness but is never a correct answer on this set.
    for label in labels:
        counts = per_category[label]
        tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
        precision = tp / (tp + fp) if tp + fp else 0
        recall = tp / (tp + fn) if tp + fn else 0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
        counts.update(precision=round(precision, 3), recall=round(recall, 3), f1=round(f1, 3))
        precisions.append(precision)
        recalls.append(recall)
        f1s.append(f1)
    for label in rows:
        per_category[label].setdefault("precision", 0)
        per_category[label].setdefault("recall", 0)
        per_category[label].setdefault("f1", 0)
    macro_f1 = round(sum(f1s) / len(f1s), 3) if f1s else 0
    return {
        "model_name": f"aegis-nlp-lexicon-v1 ({METHOD})",
        "dataset_name": "Curated classification benchmark (author-labelled)",
        "samples": len(EVAL_SET),
        "accuracy": round(correct / len(EVAL_SET), 3),
        "precision": round(sum(precisions) / len(precisions), 3) if precisions else 0,
        "recall": round(sum(recalls) / len(recalls), 3) if recalls else 0,
        "f1": macro_f1,
        "macro_f1": macro_f1,
        "per_category": per_category,
        "confusion": confusion,
        "notes": (
            f"Deterministic keyword model ({METHOD}) evaluated on {len(EVAL_SET)} curated descriptions. "
            "The benchmark was authored alongside the lexicon, so the score measures coverage of those "
            "phrasings and does not generalise to unseen reporting. Scoring is rule matching, not a "
            "trained model."
        ),
    }
