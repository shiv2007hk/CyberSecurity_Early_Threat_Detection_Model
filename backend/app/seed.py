"""Curated intelligence corpus written when the database is first initialised."""
import random
from datetime import timedelta

from sqlalchemy.orm import Session

from .config import settings
from .models import (
    Alert,
    AnalystNote,
    Asset,
    AssetVulnerability,
    AuditLog,
    IngestionLog,
    ModelEvaluation,
    Organisation,
    Recommendation,
    RiskAssessment,
    Setting,
    Threat,
    ThreatSource,
    User,
    Vulnerability,
    utcnow,
)
from .security import hash_password
from .services import classifier, correlation, early_warning, exposure, risk
from .services.refs import next_ref
from .utils import severity_from_cvss

RNG = random.Random(20261031)
NOW = utcnow()

SOURCE_RELIABILITY = {
    "NVD": 94,
    "CISA KEV": 97,
    "CSIRT Advisory": 91,
    "MITRE ATT&CK": 90,
    "AlienVault OTX": 78,
    "Internal Sensor": 72,
    "OSINT Digest": 64,
    "Vendor Advisory": 93,
}

ACTION_BY_CATEGORY = {
    "Ransomware": "Isolate affected systems, validate backups, review encryption telemetry, and apply vendor mitigations before restoring service.",
    "Phishing": "Hunt for matching lures, reset affected credentials through approved processes, and block verified domains at the mail gateway.",
    "Remote Code Execution": "Apply the vendor patch on validated affected versions, restrict management interfaces, and review exploitation telemetry.",
    "Denial of Service": "Apply mitigations, rate-limit exposed services, and monitor availability SLIs for anomalies.",
    "Credential Compromise": "Rotate affected credentials and sessions, enforce phishing-resistant MFA, and review authentication logs.",
    "Data Breach": "Preserve evidence, assess data scope, review access logs, and follow the organisation's incident-response process.",
    "Supply Chain Compromise": "Pin verified dependency versions, verify signatures, and audit build artefacts for unauthorised changes.",
    "Malware": "Hunt for the indicators, isolate compromised hosts, and review endpoint telemetry for persistence.",
    "Software Vulnerability": "Validate affected versions against inventory, schedule the vendor patch, and monitor for exploitation attempts.",
    "Suspicious Network Activity": "Inspect flow and DNS telemetry, verify the destination, and escalate if the indicator is confirmed internally.",
    "Other": "Review the source record, corroborate with a second source, and validate against inventory before acting.",
}

GEO_POOL = [
    {"country": "Germany", "code": "DE", "lat": 52.52, "lon": 13.405},
    {"country": "Netherlands", "code": "NL", "lat": 52.3676, "lon": 4.9041},
    {"country": "United States", "code": "US", "lat": 39.0438, "lon": -77.4874},
    {"country": "Singapore", "code": "SG", "lat": 1.3521, "lon": 103.8198},
    {"country": "Brazil", "code": "BR", "lat": -23.5505, "lon": -46.6333},
    {"country": "India", "code": "IN", "lat": 19.076, "lon": 72.8777},
    {"country": "Russia", "code": "RU", "lat": 55.7558, "lon": 37.6173},
    {"country": "China", "code": "CN", "lat": 39.9042, "lon": 116.4074},
]

IP_POOL = [
    "185.220.101.44", "45.155.205.233", "91.240.118.172", "103.253.145.61",
    "194.26.29.101", "62.204.41.77", "141.98.10.55", "80.66.76.30",
    "179.43.167.12", "5.188.206.18", "193.106.191.84", "146.70.92.11",
]
DOMAIN_POOL = [
    "update-securehub.top", "cdn-lockgrid.top", "auth-check-portal.info",
    "payroll-verify.xyz", "cdn-metrics-analytics.com", "vpn-update-center.net",
    "invoice-share.top", "telemetry-sync.io", "cloud-backup-alert.xyz",
]
HASH_POOL = [
    "9f2c41d7b3e8a5c6914f0d2b7a8e3c5d6f1a9b4c8d7e2f3a6b5c1d9e0f8a7b6c",
    "3c7a1f9e5b2d8c4a6f0e1b3d7a9c5e4f2b8d6a1c9f0e3b7d5a2c4e6f8b1d3a9c",
    "d4e8a2c6f0b4d8e2a6c0f4b8d2e6a0c4f8b2d6e0a4c8f2b6d0e4a8c2f6b0d4e8",
]
URL_POOL = [
    "http://auth-check-portal.info/login", "https://update-securehub.top/pkg/install",
    "http://payroll-verify.xyz/secure", "https://cdn-lockgrid.top/payload.bin",
]
MITRE_POOL = ["T1486", "T1566.001", "T1190", "T1498", "T1078", "T1071.001", "T1059.001", "T1552.001"]


def _indicator(kind: str | None = None) -> dict:
    kind = kind or RNG.choice(["ip", "domain", "sha256", "url", "mitre"])
    if kind == "ip":
        data = {"type": "ip", "value": RNG.choice(IP_POOL)}
        if RNG.random() < 0.65:
            data["geo"] = RNG.choice(GEO_POOL)
    elif kind == "domain":
        data = {"type": "domain", "value": RNG.choice(DOMAIN_POOL)}
    elif kind == "sha256":
        data = {"type": "sha256", "value": RNG.choice(HASH_POOL)}
    elif kind == "mitre":
        data = {"type": "mitre", "value": RNG.choice(MITRE_POOL)}
    else:
        data = {"type": "url", "value": RNG.choice(URL_POOL)}
    return data


def _pick(pool, weights):
    return RNG.choices(pool, weights=weights, k=1)[0]


ORGS = [
    ("Northstar Health Network", "Healthcare", "India"),
    ("Meridian Trust Bank", "Financial services", "India"),
    ("Vaultwave Commerce", "E-commerce", "Singapore"),
    ("Helios Grid Energy", "Energy", "India"),
    ("CivicBridge Services", "Public services", "India"),
]

USERS = [
    ("admin@aegissentinel.ai", "Aarav Mehta", "admin", "AegisAdmin#2026", 0),
    ("analyst@aegissentinel.ai", "Priya Nair", "analyst", "AegisAnalyst#2026", 0),
    ("viewer@aegissentinel.ai", "Daniel Roy", "viewer", "AegisViewer#2026", 0),
    ("maya.iyer@aegissentinel.ai", "Maya Iyer", "analyst", "AegisAnalyst#2026", 0),
    ("jonas.weber@aegissentinel.ai", "Jonas Weber", "analyst", "AegisAnalyst#2026", 1),
    ("elena.costa@aegissentinel.ai", "Elena Costa", "viewer", "AegisViewer#2026", 2),
]

ASSETS = [
    ("Northstar Patient Portal Gateway", "Network Infrastructure", 0, "10.20.4.11", "Apache HTTP Server", "2.4.53", "Ubuntu 22.04", "internet-facing", 5, "mission-critical", "S. Rao"),
    ("Northstar EHR Application Server", "Server", 0, "10.20.8.24", "OpenSSL", "3.0.7", "RHEL 9", "internal", 5, "mission-critical", "M. Ghosh"),
    ("Northstar Patient Records DB", "Database", 0, "10.20.9.5", "PostgreSQL", "15.4", "RHEL 9", "internal", 5, "mission-critical", "K. Shah"),
    ("Northstar Domain Controller", "Server", 0, "10.20.1.10", "Windows Server", "2019", "Windows Server 2019", "internal", 5, "mission-critical", "IT Ops"),
    ("Northstar Cache Cluster", "Database", 0, "10.20.9.31", "Redis", "7.2.4", "Debian 12", "internal", 3, "standard", "Platform Team"),
    ("Northstar Remote Access VPN", "Network Infrastructure", 0, "203.0.113.24", "Citrix NetScaler", "14.1.25", "NetScaler 14.1", "internet-facing", 5, "mission-critical", "Network Ops"),
    ("Northstar Radiology Workstation", "Workstation", 0, "10.20.30.14", "Google Chrome", "128.0.60", "Windows 11", "internal", 3, "standard", "Clinical IT"),
    ("Northstar Telemetry IoT Hub", "IoT Device", 0, "10.20.44.9", "Linux Kernel", "6.1.72", "Yocto Linux", "internal", 3, "standard", "Biomedical Eng."),
    ("Northstar Partner Portal", "Network Infrastructure", 0, "203.0.113.61", "Ivanti Connect Secure", "22.7", "Ivanti 22.7", "internet-facing", 4, "important", "Network Ops"),
    ("Meridian Internet Banking API", "Enterprise Application", 1, "10.50.6.12", "nginx", "1.24.0", "Ubuntu 22.04", "internet-facing", 5, "mission-critical", "Digital Banking"),
    ("Meridian Core Banking DB", "Database", 1, "10.50.9.6", "MySQL", "8.0.35", "RHEL 8", "internal", 5, "mission-critical", "DBA Team"),
    ("Meridian Fraud Analytics", "Server", 1, "10.50.7.21", "Elasticsearch", "8.12.1", "RHEL 8", "internal", 4, "important", "Fraud Analytics"),
    ("Meridian Corporate Mail", "Enterprise Application", 1, "10.50.8.30", "Microsoft Exchange", "15.2.1258", "Windows Server 2019", "internet-facing", 5, "mission-critical", "M365 Team"),
    ("Meridian Trading API Gateway", "Network Infrastructure", 1, "10.50.6.2", "Apache HTTP Server", "2.4.58", "Ubuntu 22.04", "internet-facing", 5, "mission-critical", "Trading Tech"),
    ("Meridian HR Portal", "Enterprise Application", 1, "10.50.12.33", "WordPress", "6.4.2", "Ubuntu 22.04", "internal", 3, "standard", "HR Systems"),
    ("Meridian Treasury Server", "Server", 1, "10.50.7.9", "OpenSSL", "3.1.4", "RHEL 8", "internal", 4, "important", "Treasury IT"),
    ("Meridian ERP Platform", "Enterprise Application", 1, "10.50.14.4", "SAP NetWeaver", "7.5", "SUSE Linux", "internal", 5, "mission-critical", "ERP Team"),
    ("Meridian Secure VPN", "Network Infrastructure", 1, "203.0.113.102", "Fortinet FortiOS", "7.4.2", "FortiOS 7.4", "internet-facing", 5, "mission-critical", "Network Security"),
    ("Meridian App Delivery", "Cloud Infrastructure", 1, "10.50.2.12", "Docker", "25.0.5", "Ubuntu 22.04", "internal", 3, "standard", "Platform Team"),
    ("Meridian Mobile Workforce", "IoT Device", 1, "10.50.30.0/24", "Android", "14", "Android 14", "internal", 2, "standard", "Mobile Ops"),
    ("Vaultwave Storefront", "Enterprise Application", 2, "10.80.5.18", "nginx", "1.24.0", "Ubuntu 22.04", "internet-facing", 4, "important", "Storefront Eng."),
    ("Vaultwave Payment API", "Server", 2, "10.80.6.22", "Kubernetes", "1.29.2", "Container Linux", "internet-facing", 5, "mission-critical", "Payments Eng."),
    ("Vaultwave Order DB", "Database", 2, "10.80.9.7", "PostgreSQL", "15.4", "RHEL 9", "internal", 4, "important", "DBA Team"),
    ("Vaultwave Warehouse Scanners", "IoT Device", 2, "10.80.40.0/24", "Android", "14", "Android 14", "internal", 2, "standard", "Logistics IT"),
    ("Vaultwave CDN Edge", "Network Infrastructure", 2, "10.80.2.8", "Apache HTTP Server", "2.4.53", "Debian 12", "internet-facing", 4, "important", "Edge Ops"),
    ("Vaultwave CI Runner", "Cloud Infrastructure", 2, "10.80.20.16", "Jenkins", "2.440", "Ubuntu 22.04", "internal", 3, "standard", "DevOps"),
    ("Vaultwave Product Wiki", "Enterprise Application", 2, "10.80.11.12", "Atlassian Confluence", "8.5.4", "Linux", "internal", 3, "standard", "Product Ops"),
    ("Vaultwave Virtualization Cluster", "Cloud Infrastructure", 2, "10.80.2.20", "VMware ESXi", "8.0.1", "ESXi 8.0", "internal", 4, "important", "Infrastructure"),
    ("Vaultwave Export Service", "Server", 2, "10.80.6.30", "Apache Tomcat", "10.1.16", "Ubuntu 22.04", "internal", 3, "standard", "Export Eng."),
    ("Helios SCADA Gateway", "Network Infrastructure", 3, "10.90.1.5", "Cisco IOS XE", "17.9.4", "IOS XE", "internet-facing", 5, "mission-critical", "OT Security"),
    ("Helios Substation Controller", "IoT Device", 3, "10.90.4.11", "Linux Kernel", "6.1.72", "Yocto Linux", "air-gapped", 5, "mission-critical", "OT Engineering"),
    ("Helios Perimeter Firewall", "Network Infrastructure", 3, "10.90.1.1", "Palo Alto PAN-OS", "11.1.2", "PAN-OS 11.1", "internet-facing", 5, "mission-critical", "Network Security"),
    ("Helios Field VPN", "Network Infrastructure", 3, "10.90.1.20", "SonicWall", "7.1.1", "SonicOS 7.1", "internet-facing", 5, "mission-critical", "Network Security"),
    ("Helios Customer Billing", "Enterprise Application", 3, "10.90.8.6", "GitLab", "16.9.1", "Ubuntu 22.04", "internet-facing", 4, "important", "Billing Eng."),
    ("Helios Build Server", "Server", 3, "10.90.12.7", "TeamCity", "2023.11.3", "Windows Server 2019", "internal", 4, "important", "DevOps"),
    ("Helios Meter Database", "Database", 3, "10.90.9.3", "MySQL", "8.0.35", "RHEL 8", "internal", 4, "important", "DBA Team"),
    ("Helios Historian", "Database", 3, "10.90.9.8", "PostgreSQL", "15.4", "RHEL 8", "internal", 5, "mission-critical", "OT Data"),
    ("CivicBridge Citizen Portal", "Enterprise Application", 4, "10.70.5.10", "Drupal", "10.2.1", "Ubuntu 22.04", "internet-facing", 3, "important", "Citizen Services"),
    ("CivicBridge File Exchange", "Enterprise Application", 4, "10.70.6.14", "MOVEit Transfer", "2023.1.0", "Windows Server 2019", "internet-facing", 4, "important", "File Services"),
    ("CivicBridge Collaboration", "Enterprise Application", 4, "10.70.11.22", "SharePoint", "2019", "Windows Server 2019", "internal", 3, "standard", "Collaboration"),
    ("CivicBridge Mail Relay", "Server", 4, "10.70.8.8", "Zimbra", "10.0.6", "Ubuntu 22.04", "internet-facing", 3, "important", "Mail Ops"),
    ("CivicBridge GIS Workstation", "Workstation", 4, "10.70.30.2", "Mozilla Firefox", "130.0", "Windows 11", "internal", 2, "standard", "GIS Team"),
    ("CivicBridge Document Review", "Workstation", 4, "10.70.30.9", "Adobe Acrobat", "24.002", "Windows 11", "internal", 2, "standard", "Legal Ops"),
    ("CivicBridge Remote Access", "Network Infrastructure", 4, "203.0.113.140", "Citrix NetScaler", "14.1.25", "NetScaler 14.1", "internet-facing", 4, "important", "Network Ops"),
    ("CivicBridge Analytics Portal", "Enterprise Application", 4, "10.70.6.22", "Apache Tomcat", "10.1.16", "Ubuntu 22.04", "internal", 3, "standard", "Analytics"),
    ("Northstar Imaging Archive", "Server", 0, "10.20.9.40", "Elasticsearch", "8.12.1", "RHEL 9", "internal", 4, "important", "Imaging IT"),
    ("Meridian Load Balancer", "Network Infrastructure", 1, "10.50.6.5", "Fortinet FortiOS", "7.4.2", "FortiOS 7.4", "internet-facing", 4, "important", "Network Ops"),
]

# (cve, title, description, cvss, epss, kev, age_hours, vendor, product, start, end | None, all_versions, category, remediation, ransomware)
VULNS = [
    ("CVE-2026-48211", "Apache HTTP Server mod_proxy request smuggling flaw",
     "A vulnerability in Apache HTTP Server versions 2.4.49 through 2.4.55 allows an unauthenticated attacker to smuggle crafted requests through mod_proxy, leading to remote code execution in some configurations. Exploit code has been observed in the wild against internet-facing gateways.",
     9.8, 0.72, True, 10, "Apache", "Apache HTTP Server", "2.4.49", "2.4.55", False, "Remote Code Execution",
     "Upgrade to a fixed Apache HTTP Server release, restrict proxy endpoints, and review access logs for exploitation attempts.", False),
    ("CVE-2026-39117", "OpenSSL memory disclosure in TLS handshake",
     "A software vulnerability in OpenSSL 3.0.x can disclose portions of process memory during a crafted TLS handshake. Sensitive information exposure may affect applications using the affected library.",
     8.8, 0.31, False, 216, "OpenSSL", "OpenSSL", "3.0.0", "3.0.11", False, "Software Vulnerability",
     "Upgrade OpenSSL to a fixed 3.0.x release and restart dependent services.", False),
    ("CVE-2026-44902", "Fortinet FortiOS SSL VPN remote code execution",
     "Fortinet FortiOS 7.4.0 through 7.4.5 contains a remote code execution vulnerability in the SSL VPN component. Unauthenticated attackers can execute arbitrary code on internet-facing appliances. Known exploitation has been reported.",
     9.6, 0.58, True, 120, "Fortinet", "Fortinet FortiOS", "7.4.0", "7.4.5", False, "Remote Code Execution",
     "Apply the vendor firmware update, disable exposed SSL VPN management where possible, and review VPN logs for indicators of exploitation.", True),
    ("CVE-2026-31208", "Cisco IOS XE web UI command injection",
     "A command injection vulnerability in the Cisco IOS XE web UI allows an authenticated remote attacker to execute commands with elevated privileges. Affected releases include 17.9.1 through 17.9.4.",
     8.6, 0.41, False, 288, "Cisco", "Cisco IOS XE", "17.9.1", "17.9.4", False, "Remote Code Execution",
     "Disable the HTTP server if unused and upgrade to a fixed IOS XE release.", False),
    ("CVE-2026-27551", "VMware ESXi VM escape and code execution flaw",
     "VMware ESXi 8.0.0 through 8.0.2 is affected by a code execution vulnerability in a virtual device. An actor with access to a guest VM could potentially escape isolation. The vulnerability is listed in known-exploited evidence.",
     9.3, 0.63, True, 432, "VMware", "VMware ESXi", "8.0.0", "8.0.2", False, "Remote Code Execution",
     "Apply the ESXi patch, isolate affected hosts, and review VM administrative activity.", True),
    ("CVE-2026-41876", "Ivanti Connect Secure authentication bypass",
     "An authentication bypass vulnerability in Ivanti Connect Secure 22.6 through 22.8 allows a remote attacker to access protected resources without valid credentials. Stolen session tokens have been observed in related intrusions.",
     9.1, 0.55, True, 168, "Ivanti", "Ivanti Connect Secure", "22.6", "22.8", False, "Credential Compromise",
     "Apply the vendor mitigation, rotate credentials, and review authentication logs for anomalous sessions.", True),
    ("CVE-2026-35492", "Kubernetes kubelet privilege escalation",
     "A privilege escalation vulnerability in Kubernetes 1.29.0 through 1.29.3 permits a compromised pod to access node-level credentials under specific configurations.",
     7.8, 0.22, False, 504, "CNCF", "Kubernetes", "1.29.0", "1.29.3", False, "Software Vulnerability",
     "Upgrade the control plane and nodes to a fixed Kubernetes release and restrict pod service account permissions.", False),
    ("CVE-2026-22904", "MySQL Server information disclosure",
     "MySQL Server 8.0.0 through 8.0.36 contains an information disclosure flaw that could allow a high-privileged attacker to access sensitive data through crafted SQL.",
     7.5, 0.18, False, 600, "Oracle", "MySQL", "8.0.0", "8.0.36", False, "Data Breach",
     "Upgrade MySQL to a fixed release and review database account privileges.", False),
    ("CVE-2026-40113", "Redis denial of service via crafted command",
     "Redis 7.2.0 through 7.2.4 can be crashed by an authenticated client sending a crafted command sequence, leading to denial of service.",
     6.5, 0.12, False, 792, "Redis", "Redis", "7.2.0", "7.2.4", False, "Denial of Service",
     "Upgrade Redis, enforce authentication, and restrict network access to trusted clients.", False),
    ("CVE-2026-17382", "WordPress plugin remote code execution",
     "A vulnerable WordPress component in versions 6.4.0 through 6.4.3 allows an authenticated editor to achieve remote code execution through unsafe file handling.",
     8.2, 0.29, False, 384, "WordPress", "WordPress", "6.4.0", "6.4.3", False, "Remote Code Execution",
     "Update WordPress and the affected component, and review file permissions.", False),
    ("CVE-2026-28643", "Atlassian Confluence template injection",
     "Atlassian Confluence 8.5.0 through 8.5.3 is affected by a template injection vulnerability enabling remote code execution for authenticated users. Exploitation has been observed in known incidents.",
     9.0, 0.48, True, 672, "Atlassian", "Atlassian Confluence", "8.5.0", "8.5.3", False, "Remote Code Execution",
     "Upgrade Confluence, restrict public access, and review administrative audit logs.", True),
    ("CVE-2026-33019", "Google Chrome V8 type confusion",
     "Google Chrome 128.0.0 through 128.0.67 contains a type confusion vulnerability in the V8 engine that can lead to remote code execution when a user visits a crafted page.",
     7.2, 0.16, False, 264, "Google", "Google Chrome", "128.0.0", "128.0.67", False, "Remote Code Execution",
     "Update Chrome to a fixed build and enforce browser update policies.", False),
    ("CVE-2026-45871", "Microsoft Exchange Server deserialization RCE",
     "Microsoft Exchange Server builds 15.2.0 through 15.2.1500 are affected by unsafe deserialization that permits unauthenticated remote code execution against exposed services. The flaw is known to be exploited.",
     9.8, 0.66, True, 30, "Microsoft", "Microsoft Exchange", "15.2.0", "15.2.1500", False, "Remote Code Execution",
     "Apply the emergency Exchange update, restrict OWA exposure, and review IIS logs for suspicious requests.", True),
    ("CVE-2026-21334", "Apache Tomcat deserialization flaw",
     "Apache Tomcat 10.1.0 through 10.1.17 is affected by a deserialization flaw in the session persistence component, enabling remote code execution in some configurations.",
     7.3, 0.14, False, 912, "Apache", "Apache Tomcat", "10.1.0", "10.1.17", False, "Remote Code Execution",
     "Upgrade Tomcat and review exposed management endpoints.", False),
    ("CVE-2026-36721", "nginx HTTP/2 denial of service",
     "nginx 1.24.0 through 1.24.1 can be forced to consume excessive memory via crafted HTTP/2 frames, causing denial of service for internet-facing services.",
     6.1, 0.09, False, 1056, "nginx", "nginx", "1.24.0", "1.24.1", False, "Denial of Service",
     "Upgrade nginx and apply connection limits at the edge.", False),
    ("CVE-2025-64428", "GitLab CI token exposure",
     "GitLab 16.9.0 through 16.9.2 exposed CI job tokens to unauthorised project members under specific pipeline conditions, enabling credential compromise.",
     8.4, 0.25, False, 1464, "GitLab", "GitLab", "16.9.0", "16.9.2", False, "Credential Compromise",
     "Upgrade GitLab, rotate exposed CI tokens, and review pipeline activity.", False),
    ("CVE-2026-19443", "Oracle WebLogic Server RCE",
     "Oracle WebLogic Server 14.1.1.0 through 14.1.1.2 is affected by a remote code execution vulnerability in an exposed management component.",
     8.9, 0.33, False, 696, "Oracle", "Oracle WebLogic", "14.1.1.0", "14.1.1.2", False, "Remote Code Execution",
     "Apply the Oracle critical patch update and restrict T3/IIOP access.", False),
    ("CVE-2026-40286", "Citrix NetScaler session token theft",
     "A vulnerability in Citrix NetScaler 14.1.0 through 14.1.25 allows session token theft and authentication bypass on exposed management interfaces. Known exploitation affects remote-access deployments.",
     9.4, 0.57, True, 336, "Citrix", "Citrix NetScaler", "14.1.0", "14.1.25", False, "Credential Compromise",
     "Apply the vendor patch, rotate all sessions and credentials, and review VPN access logs.", True),
    ("CVE-2026-24862", "Palo Alto PAN-OS command injection",
     "PAN-OS 11.1.0 through 11.1.3 contains a command injection vulnerability in the management interface that can lead to remote code execution by an authenticated administrator.",
     8.7, 0.31, False, 552, "Palo Alto Networks", "Palo Alto PAN-OS", "11.1.0", "11.1.3", False, "Remote Code Execution",
     "Upgrade PAN-OS and restrict management access to trusted networks.", False),
    ("CVE-2026-32177", "SonicWall firewall RCE",
     "SonicWall SonicOS 7.1.0 through 7.1.2 is affected by a remote code execution vulnerability in the SSL VPN interface.",
     8.1, 0.27, False, 840, "SonicWall", "SonicWall", "7.1.0", "7.1.2", False, "Remote Code Execution",
     "Update SonicOS firmware and review VPN connection logs.", False),
    ("CVE-2025-70611", "Zimbra cross-site scripting",
     "Zimbra Collaboration 10.0.0 through 10.0.8 contains a cross-site scripting vulnerability in the web client that could permit session hijacking.",
     7.9, 0.21, False, 1800, "Synacor", "Zimbra", "10.0.0", "10.0.8", False, "Software Vulnerability",
     "Upgrade Zimbra and review mail filter rules for suspicious changes.", False),
    ("CVE-2026-27774", "Jenkins remote code execution",
     "Jenkins 2.440 through 2.442 allows remote code execution through unsafe script console access under specific authorisation configurations. Known exploitation targets exposed CI controllers.",
     9.2, 0.44, True, 456, "Jenkins", "Jenkins", "2.440", "2.442", False, "Remote Code Execution",
     "Update Jenkins, remove anonymous read access, and rotate CI credentials.", True),
    ("CVE-2026-49901", "JetBrains TeamCity authentication bypass RCE",
     "TeamCity 2023.11.0 through 2023.11.4 is affected by an authentication bypass that allows unauthenticated remote code execution. Exploitation is observed against internet-exposed build servers.",
     9.8, 0.61, True, 50, "JetBrains", "TeamCity", "2023.11.0", "2023.11.4", False, "Remote Code Execution",
     "Apply the TeamCity security patch immediately, restrict access, and rotate build credentials.", True),
    ("CVE-2025-61207", "MOVEit Transfer SQL injection",
     "MOVEit Transfer 2023.1.0 through 2023.1.2 contains a SQL injection vulnerability in a web application endpoint that could permit unauthorised data access.",
     8.8, 0.36, False, 1992, "Progress", "MOVEit Transfer", "2023.1.0", "2023.1.2", False, "Data Breach",
     "Apply the vendor patch, review transfer logs, and audit exposed files.", False),
    ("CVE-2026-43328", "Docker Engine privilege escalation",
     "Docker Engine 25.0.0 through 25.0.6 is affected by a privilege escalation flaw when containers mount crafted volumes.",
     7.0, 0.11, False, 984, "Docker", "Docker", "25.0.0", "25.0.6", False, "Software Vulnerability",
     "Upgrade Docker Engine and review container volume permissions.", False),
    ("CVE-2026-31755", "Elasticsearch information disclosure",
     "Elasticsearch 8.12.0 through 8.12.2 can expose index metadata to an unauthorised user under misconfigured role mappings.",
     7.6, 0.19, False, 1128, "Elastic", "Elasticsearch", "8.12.0", "8.12.2", False, "Data Breach",
     "Upgrade Elasticsearch and review cluster role mappings.", False),
    ("CVE-2026-18607", "Drupal access bypass",
     "Drupal 10.2.0 through 10.2.2 contains an access bypass vulnerability that may allow viewing restricted content.",
     8.3, 0.26, False, 768, "Drupal", "Drupal", "10.2.0", "10.2.2", False, "Software Vulnerability",
     "Upgrade Drupal core and review content access policies.", False),
    ("CVE-2026-33082", "Apache HTTP Server mod_http2 denial of service",
     "Apache HTTP Server 2.4.56 through 2.4.58 is vulnerable to a denial of service condition through excessive HTTP/2 stream resets.",
     7.5, 0.15, False, 360, "Apache", "Apache HTTP Server", "2.4.56", "2.4.58", False, "Denial of Service",
     "Upgrade Apache HTTP Server and tune HTTP/2 limits.", False),
    ("CVE-2026-46712", "OpenSSL denial of service in certificate parsing",
     "OpenSSL 3.1.0 through 3.1.5 can consume excessive CPU when parsing crafted certificates, causing denial of service.",
     6.8, 0.10, False, 624, "OpenSSL", "OpenSSL", "3.1.0", "3.1.5", False, "Denial of Service",
     "Upgrade OpenSSL to a fixed release and restrict untrusted certificate processing.", False),
    ("CVE-2026-24092", "VMware ESXi information disclosure",
     "VMware ESXi 8.0.0 through 8.0.3 may disclose host memory contents to an authenticated attacker.",
     8.1, 0.24, False, 1392, "VMware", "VMware ESXi", "8.0.0", "8.0.3", False, "Data Breach",
     "Apply the ESXi patch and restrict host management access.", False),
    ("CVE-2026-38517", "Progress Sitefinity unsafe file upload",
     "Progress Sitefinity 14.0 through 14.3 allows an authenticated user to upload executable content through unsafe file validation.",
     8.5, 0.30, False, 240, "Progress", "Progress Sitefinity", "14.0", "14.3", False, "Remote Code Execution",
     "Apply the vendor update and validate upload directories.", False),
    ("CVE-2026-42108", "Linux kernel use-after-free",
     "Linux kernel 6.1.0 through 6.1.75 contains a use-after-free vulnerability in a network subsystem that may lead to privilege escalation.",
     7.4, 0.17, False, 528, "Linux", "Linux Kernel", "6.1.0", "6.1.75", False, "Software Vulnerability",
     "Apply the distribution kernel update and reboot affected systems.", False),
    ("CVE-2026-44003", "macOS privilege escalation",
     "macOS 14.0 through 14.4 contains a privilege escalation flaw in a system service. An update is available.",
     7.8, 0.13, False, 216, "Apple", "macOS", "14.0", "14.4", False, "Software Vulnerability",
     "Apply the macOS security update.", False),
    ("CVE-2026-45117", "Android sensitive data exposure",
     "Android 13 through 14 can expose sensitive clipboard data to background applications under specific conditions.",
     6.4, 0.08, False, 432, "Google", "Android", "13", "14", False, "Data Breach",
     "Apply the Android security bulletin and restrict background app permissions.", False),
    ("CVE-2026-20665", "PostgreSQL SQL injection in extension",
     "PostgreSQL 15.0 through 15.5 is affected by SQL injection in an optional extension when processing untrusted input.",
     8.0, 0.20, False, 408, "PostgreSQL", "PostgreSQL", "15.0", "15.5", False, "Data Breach",
     "Upgrade PostgreSQL and validate extension usage.", False),
    ("CVE-2026-36990", "Zoom client denial of service",
     "Zoom 5.16.0 through 5.17.2 can be crashed by a malformed meeting request, causing denial of service for the user session.",
     6.2, 0.08, False, 1320, "Zoom", "Zoom", "5.16.0", "5.17.2", False, "Denial of Service",
     "Update the Zoom client and restrict meeting join links.", False),
    ("CVE-2025-58442", "Adobe Acrobat arbitrary code execution",
     "Adobe Acrobat 23.0 through 24.002 contains a use-after-free vulnerability that can lead to arbitrary code execution when a crafted PDF is opened.",
     7.1, 0.12, False, 2160, "Adobe", "Adobe Acrobat", "23.0", "24.002", False, "Remote Code Execution",
     "Update Adobe Acrobat and restrict untrusted PDF sources.", False),
    ("CVE-2026-31119", "Firefox address bar spoofing",
     "Mozilla Firefox 129.0 through 130.0 contains an address bar spoofing vulnerability that may facilitate phishing.",
     6.9, 0.09, False, 192, "Mozilla", "Mozilla Firefox", "129.0", "130.0", False, "Phishing",
     "Update Firefox and enable browser phishing protections.", False),
    ("CVE-2026-39271", "SharePoint remote code execution",
     "Microsoft SharePoint Server 2019 contains a deserialization vulnerability enabling remote code execution by an authenticated attacker.",
     8.6, 0.28, False, 288, "Microsoft", "SharePoint", "2019", "2019", False, "Remote Code Execution",
     "Apply the SharePoint security update and review server-side activity.", False),
    ("CVE-2026-28834", "Atlassian Jira template injection",
     "Atlassian Jira 9.0 through 9.15 is affected by a template injection vulnerability in issue views.",
     7.1, 0.10, False, 1176, "Atlassian", "Atlassian Jira", "9.0", "9.15", False, "Remote Code Execution",
     "Upgrade Jira and restrict public project permissions.", False),
    ("CVE-2026-47615", "Fortinet FortiOS heap overflow",
     "Fortinet FortiOS 7.4.0 through 7.4.4 contains a heap overflow in the SSL VPN component that may permit remote code execution.",
     8.4, 0.30, False, 648, "Fortinet", "Fortinet FortiOS", "7.4.0", "7.4.4", False, "Remote Code Execution",
     "Apply the latest FortiOS firmware and review VPN logs.", False),
    ("CVE-2026-13741", "Apache Tomcat request smuggling",
     "Apache Tomcat 10.1.0 through 10.1.15 is affected by request smuggling when behind a reverse proxy.",
     8.8, 0.23, False, 1512, "Apache", "Apache Tomcat", "10.1.0", "10.1.15", False, "Software Vulnerability",
     "Upgrade Tomcat and align proxy request handling.", False),
    ("CVE-2026-21299", "IBM WebSphere deserialization",
     "IBM WebSphere Application Server 9.0 through 9.0.5 is vulnerable to unsafe deserialization through an exposed connector.",
     7.7, 0.15, False, 936, "IBM", "IBM WebSphere", "9.0", "9.0.5", False, "Remote Code Execution",
     "Apply the IBM fix pack and restrict connector exposure.", False),
    ("CVE-2026-33541", "Google Chrome heap buffer overflow",
     "Google Chrome 127.0.0 through 127.0.65 contains a heap buffer overflow in a graphics component that could lead to remote code execution.",
     7.5, 0.18, False, 1104, "Google", "Google Chrome", "127.0.0", "127.0.65", False, "Remote Code Execution",
     "Update Chrome to a fixed build.", False),
    ("CVE-2026-45920", "Cisco ASA remote code execution",
     "Cisco ASA 9.18.0 through 9.18.3 is affected by a remote code execution vulnerability in the web services interface.",
     8.9, 0.33, False, 720, "Cisco", "Cisco ASA", "9.18.0", "9.18.3", False, "Remote Code Execution",
     "Apply the Cisco update and restrict web services exposure.", False),
]

NON_CVE_TEMPLATES = [
    ("Ransomware", "LockGrid ransomware operation encrypts VMware datastores",
     "A ransomware operation tracked as LockGrid is encrypting VMware ESXi datastores at multiple organisations, leaving ransom notes and threatening to leak stolen records. The group uses valid VPN credentials and data exfiltration before encryption."),
    ("Ransomware", "Double extortion campaign targets healthcare file servers",
     "A double extortion operation encrypted hospital file servers after exfiltrating patient documents. Analysts observed Cobalt Strike beacons deployed before encryption."),
    ("Phishing", "Credential harvesting campaign impersonates HR payroll portal",
     "A phishing campaign is delivering emails that impersonate the HR payroll portal and link to a fake login page to harvest credentials. The lure uses a spoofed sender domain and urgent password-expiry language."),
    ("Phishing", "Smishing wave targets banking customers with fake MFA prompts",
     "A smishing campaign targets banking customers with fake multi-factor prompts and credential harvesting pages. The messages spoof the bank's short code and ask users to verify a transaction."),
    ("Malware", "Info-stealer distributed via malvertising and fake installers",
     "A malware loader is distributing an info-stealer through malicious advertising and fake software installers. The payload steals browser credentials and session tokens, then establishes a backdoor."),
    ("Malware", "QakBot variant delivers AsyncRAT backdoor",
     "A QakBot variant is delivering an AsyncRAT backdoor through reply-chain emails and malicious attachments. The malware establishes command and control beaconing to a suspicious domain."),
    ("Data Breach", "Customer records offered on criminal forum after exfiltration",
     "A data breach claim on a criminal forum advertises customer records allegedly exfiltrated from an e-commerce platform. The dataset includes names, email addresses and partial payment metadata."),
    ("Supply Chain Compromise", "Malicious npm package targets CI build pipelines",
     "A malicious npm package was published as part of a supply chain attack, using dependency confusion to execute a post-install script in build pipelines. The package exfiltrates environment variables."),
    ("Credential Compromise", "Session token theft enables account takeover",
     "Stolen session tokens obtained through an adversary-in-the-middle phishing kit enabled account takeover across a SaaS tenant. Auditors observed unusual MFA registration activity."),
    ("Suspicious Network Activity", "Beaconing and lateral movement observed in internal telemetry",
     "Internal sensors recorded beaconing to command and control infrastructure followed by lateral movement using service account credentials. The activity includes DNS tunneling and suspicious remote service creation."),
    ("Remote Code Execution", "Critical unauthenticated RCE exploited on edge appliances",
     "Attackers are exploiting a critical unauthenticated remote code execution flaw in internet-facing edge appliances. Exploitation attempts include command injection probes and post-exploitation tooling."),
    ("Denial of Service", "DDoS extortion campaign targets public APIs",
     "A DDoS extortion campaign is targeting public APIs with packet flood attacks and resource exhaustion, causing service disruption. The actors threaten larger attacks unless contacted."),
    ("Software Vulnerability", "Vendor advisory describes privilege escalation in agent service",
     "A vendor advisory describes a privilege escalation vulnerability in an endpoint agent service. Local attackers could execute arbitrary code with system privileges after successful authentication."),
    ("Other", "Suspicious domain registrations mimic security vendors",
     "Researchers observed a cluster of suspicious domain registrations and typosquatted security vendor domains used for credential harvesting. The lures impersonate update notifications."),
    ("Ransomware", "LockGrid affiliate reuses Cobalt Strike and Rclone for exfiltration",
     "Affiliates of the LockGrid ransomware operation reuse Cobalt Strike beacons and Rclone for data exfiltration before deployment. The leak site lists new victims across finance and logistics sectors."),
    ("Phishing", "Business email compromise invoice fraud",
     "A business email compromise campaign is spoofing supplier invoices to redirect payments. The email lure uses a compromised mailbox and a malicious attachment containing a credential harvesting page."),
    ("Supply Chain Compromise", "Compromised build pipeline pushes signed malicious update",
     "A compromised update pipeline pushed a signed installer containing a backdoor to downstream customers in a supply chain compromise. The attacker used stolen build credentials."),
    ("Malware", "Mirai botnet variant exploits IoT devices",
     "A Mirai botnet variant is recruiting IoT devices through brute force attacks on exposed telnet services. Infected devices participate in packet flood attacks."),
    ("Data Breach", "Misconfigured object storage exposed sensitive records",
     "A misconfigured cloud object store exposed sensitive records including regulated identifiers and case notes. Access logs show unauthorised data access over several days."),
    ("Other", "Security researchers observe new loader infrastructure",
     "Researchers observed new loader infrastructure associated with multiple malware families, using fast-flux domains and rotating IP addresses. No confirmed exploitation of a specific vulnerability was reported."),
]

NON_CVE_BURST = [
    ("Ransomware", "LockGrid ransomware victim claims surge across VMware environments",
     "Multiple new LockGrid ransomware victim claims reference VMware ESXi environments. Shared infrastructure includes cdn-lockgrid.top and 45.155.205.233, with reports across three sources in the last 72 hours. This is an observed reporting cluster, not proof of a future attack."),
    ("Ransomware", "LockGrid affiliate activity reported by multiple intelligence feeds",
     "Independent feeds report LockGrid affiliate activity targeting virtualisation infrastructure. Shared indicators include cdn-lockgrid.top and the IP 45.155.205.233. Analysts recommend validating exposure of backup and hypervisor management planes."),
    ("Ransomware", "New LockGrid ransom notes observed in incident response cases",
     "Incident responders report new LockGrid ransom notes and data leak pages. Command and control beaconing to cdn-lockgrid.top preceded encryption in the observed cases."),
    ("Ransomware", "LockGrid infrastructure reuses known loader",
     "LockGrid intrusions observed this week reuse a known loader and Cobalt Strike beacon. The operation continues to target internet-facing VMware ESXi hosts."),
]


def _make_indicators(count: int) -> list[dict]:
    values = []
    seen = set()
    attempts = 0
    while len(values) < count and attempts < count * 6:
        attempts += 1
        indicator = _indicator()
        if indicator["value"] in seen:
            continue
        seen.add(indicator["value"])
        values.append(indicator)
    return values


def _build_threat(db: Session, *, name: str, description: str, category_hint: str, source: str,
                  published_at, cve: str | None = None, cvss: float | None = None,
                  epss: float | None = None, known_exploited: bool = False,
                  technology: str | None = None, versions: str | None = None,
                  indicators: list[dict] | None = None, user_ids: list[int] | None = None,
                  status: str | None = None) -> Threat:
    # category_hint is the authored label of this corpus record, so it must not be
    # handed to the classifier as a hint: the stored category stays the authored label
    # and ai_category records what the lexicon independently predicted.
    classification = classifier.classify(description)
    category = category_hint or classifier.OTHER
    severity = severity_from_cvss(cvss) if cvss is not None else _pick(
        ["critical", "high", "medium", "low", "informational"], [8, 27, 40, 22, 3]
    )
    reliability = SOURCE_RELIABILITY.get(source, 70)
    indicators = indicators or []
    recommended = ACTION_BY_CATEGORY.get(category, ACTION_BY_CATEGORY["Other"])
    desc = description
    if technology and technology.lower() not in desc.lower():
        desc += f" Affected technology: {technology} {versions or ''}.".strip()
    summary = classifier.summarise(name, desc, source, technology, indicators, cvss)
    entities = classifier.extract_entities(f"{name}. {desc}", [technology] if technology else None)
    explanation = classifier.explain(
        name, classification, entities, indicators, cvss, epss, known_exploited,
        technology, reliability, recommended,
    )
    status_value = status or _pick(["new", "new", "new", "investigating", "resolved", "resolved", "dismissed"], [1] * 7)
    assigned = RNG.choice(user_ids) if status_value == "investigating" and user_ids else None
    ref = f"THR-{published_at.year}-{db.query(Threat).count() + 1:04d}"
    threat = Threat(
        ref=ref,
        name=name[:238],
        category=category,
        description=desc,
        source=source,
        source_url="",
        published_at=published_at,
        updated_at=published_at + timedelta(hours=RNG.randint(1, 20)),
        cve_id=cve,
        cvss_score=cvss,
        cvss_severity=severity,
        epss_score=epss,
        known_exploited=known_exploited,
        affected_technology=technology,
        affected_versions=versions,
        indicators=indicators,
        source_reliability=reliability,
        evidence_refs=[{
            "label": f"{source} · stored {ref}",
        }],
        ai_summary=summary,
        ai_category=classification["category"],
        ai_confidence=round(classification["confidence"] * 100, 1),
        ai_keywords=classifier.extract_keywords(desc, 10),
        ai_entities=entities,
        ai_explanation=explanation,
        ai_method=classifier.METHOD,
        confidence=0,
        severity=severity,
        status=status_value,
        assigned_to=assigned,
        is_saved=RNG.random() < 0.12,
        is_simulated=True,
        retrieval_timestamp=published_at + timedelta(minutes=RNG.randint(2, 90)),
        created_at=published_at + timedelta(minutes=5),
        recommended_action=recommended,
    )
    db.add(threat)
    db.flush()
    risk.apply_to_threat(threat, db)
    return threat


def _build_alert(db: Session, threat: Threat | None, *, severity: str, title: str, trigger: str,
                 action: str, status: str, detected_at, assignee: int | None, asset_ids: list[int] | None = None,
                 vulnerability: Vulnerability | None = None) -> Alert:
    ref = f"AL-{NOW.year}-{db.query(Alert).count() + 1:04d}"
    resolved_at = detected_at + timedelta(hours=RNG.randint(3, 40)) if status == "resolved" else None
    if resolved_at and resolved_at > NOW:
        resolved_at = NOW - timedelta(minutes=RNG.randint(5, 120))
    acknowledged_at = detected_at + timedelta(minutes=RNG.randint(15, 240)) if status in {"acknowledged", "investigating", "resolved"} else None
    if acknowledged_at and acknowledged_at > NOW:
        acknowledged_at = NOW - timedelta(minutes=RNG.randint(1, 210))
    alert = Alert(
        ref=ref,
        title=title[:258],
        severity=severity,
        category=(threat.ai_category if threat else "Software Vulnerability"),
        detected_at=detected_at,
        threat_id=threat.id if threat else None,
        vulnerability_id=vulnerability.id if vulnerability else None,
        asset_ids=asset_ids or [],
        source=threat.source if threat else "Correlation Engine",
        risk_score=threat.risk_score if threat else {"critical": 88, "high": 68, "medium": 45, "low": 20, "informational": 5}[severity],
        confidence=threat.confidence if threat else 70,
        trigger_reason=trigger,
        evidence=[
            {"label": "Threat record", "value": threat.ref if threat else "Correlated platform telemetry"},
            {"label": "Detection rule", "value": "Rule captured with the alert"},
            {"label": "Data provenance", "value": "Stored platform record"},
        ],
        recommended_action=action,
        status=status,
        assignee_id=assignee,
        acknowledged_at=acknowledged_at,
        resolved_at=resolved_at,
        rule_key="historical",
        is_simulated=True,
        created_at=detected_at,
    )
    db.add(alert)
    db.flush()
    return alert


def seed_if_empty(db: Session) -> bool:
    if db.query(User).count() > 0:
        return False

    orgs = []
    for name, sector, country in ORGS:
        org = Organisation(name=name, sector=sector, country=country, created_at=NOW - timedelta(days=240))
        db.add(org)
        orgs.append(org)
    db.flush()

    users = []
    for email, full_name, role, password, org_index in USERS:
        user = User(
            email=email,
            full_name=full_name,
            role=role,
            password_hash=hash_password(password),
            organisation_id=orgs[org_index].id,
            is_active=True,
            notification_email=True,
            created_at=NOW - timedelta(days=210),
            last_login_at=NOW - timedelta(hours=RNG.randint(1, 48)),
        )
        db.add(user)
        users.append(user)
    db.flush()
    admin = users[0]
    analysts = [u for u in users if u.role in {"admin", "analyst"}]
    analyst_ids = [u.id for u in analysts]

    source_defs = [
        ("nvd", "NVD — National Vulnerability Database", "Official CVE and CVSS records from the NIST National Vulnerability Database.",
         "https://nvd.nist.gov/", "vulnerability", False, True, "operational", 94, 132, settings.nvd_api_key != "", NOW - timedelta(hours=2)),
        ("cisa_kev", "CISA KEV Catalog", "Authoritative catalogue of vulnerabilities known to be exploited in the wild.",
         "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "exploitation", False, True, "operational", 97, 46, False, NOW - timedelta(hours=3)),
        ("epss", "FIRST EPSS", "Exploitation probability estimates from the Exploit Prediction Scoring System.",
         "https://www.first.org/epss/", "probability", False, True, "operational", 90, 132, False, NOW - timedelta(hours=4)),
        ("mitre_attack", "MITRE ATT&CK", "Adversary tactics and techniques reference base. No automatic mappings are fabricated.",
         "https://attack.mitre.org/", "knowledge-base", False, True, "reference", 90, 0, False, NOW - timedelta(days=1)),
        ("csirt", "CSIRT Advisories", "Coordinated advisories from national and sector CSIRTs distributed through FIRST. Manual/authorised import only.",
         "https://www.first.org/", "advisory", False, True, "manual-import", 91, 18, False, NOW - timedelta(days=1, hours=5)),
        ("otx", "AlienVault OTX", "Pulse-based threat intelligence with malicious IPs, domains and hashes.",
         "https://otx.alienvault.com/", "indicators", True, bool(settings.otx_api_key), "operational" if settings.otx_api_key else "awaiting_key", 78, 0, bool(settings.otx_api_key), NOW - timedelta(hours=6) if settings.otx_api_key else None),
        ("virustotal", "VirusTotal", "Optional reputation enrichment for indicators. Requires an authorised API key.",
         "https://www.virustotal.com/", "enrichment", True, bool(settings.virustotal_api_key), "operational" if settings.virustotal_api_key else "awaiting_key", 88, 0, bool(settings.virustotal_api_key), None),
        ("abuseipdb", "AbuseIPDB", "IP reputation and abuse reports. Requires an API key.",
         "https://www.abuseipdb.com/", "reputation", True, bool(settings.abuseipdb_api_key), "operational" if settings.abuseipdb_api_key else "awaiting_key", 80, 0, bool(settings.abuseipdb_api_key), None),
        ("greynoise", "GreyNoise", "Internet scanner context for IP indicators. Requires an API key.",
         "https://www.greynoise.io/", "reputation", True, bool(settings.greynoise_api_key), "operational" if settings.greynoise_api_key else "awaiting_key", 82, 0, bool(settings.greynoise_api_key), None),
    ]
    for key, name, desc, url, category, requires_key, enabled, status, reliability, items, configured, last_sync in source_defs:
        db.add(ThreatSource(
            key=key, name=name, description=desc, url=url, category=category,
            requires_key=requires_key, key_configured=configured, enabled=enabled, status=status,
            reliability=reliability, last_sync_at=last_sync,
            last_success_at=last_sync if status in {"operational", "reference", "manual-import"} else None,
            items_ingested=items, latency_ms=RNG.randint(80, 900) if last_sync else None,
            last_message=(
                "Configured; awaiting first synchronisation." if status == "operational" and key == "nvd"
                else "Reference-only connector; no automated ingestion." if status == "reference"
                else "Advisories are imported manually after review." if status == "manual-import"
                else "API key not configured; connector disabled for live calls." if status == "awaiting_key"
                else "Corpus import completed; records carry their source and retrieval timestamp."
            ),
        ))
    db.add(Setting(key="risk_weights", value={"weights": risk.DEFAULT_WEIGHTS, "thresholds": risk.DEFAULT_THRESHOLDS}, updated_at=NOW))
    db.flush()

    assets = []
    for i, (name, category, org_index, identifier, software, version, os_name, exposure_status, criticality,
            importance, owner) in enumerate(ASSETS, start=1):
        asset = Asset(
            ref=f"AST-{NOW.year}-{i:04d}",
            name=name,
            category=category,
            organisation_id=orgs[org_index].id,
            identifier=identifier,
            software=software,
            software_version=version,
            os=os_name,
            exposure=exposure_status,
            internet_facing=exposure_status == "internet-facing",
            criticality=criticality,
            business_importance=importance,
            owner=owner,
            last_assessed_at=NOW - timedelta(days=RNG.randint(1, 14)),
            notes="Registered during inventory baseline import." if i % 2 == 0 else "",
            is_simulated=True,
            created_at=NOW - timedelta(days=180),
        )
        db.add(asset)
        assets.append(asset)
    db.flush()

    vulnerabilities = []
    for cve, title, desc, cvss, epss, kev, age_hours, vendor, product, start, end, all_versions, category, remediation, ransomware in VULNS:
        published = NOW - timedelta(hours=age_hours)
        versions = {"all_versions": True} if all_versions else {"start": start, "end": end}
        vuln = Vulnerability(
            cve_id=cve,
            title=title,
            description=desc,
            cvss_score=cvss,
            cvss_severity=severity_from_cvss(cvss),
            epss_score=epss,
            epss_percentile=round(min(0.999, epss * 1.15), 3),
            known_exploited=kev,
            kev_due_date=published + timedelta(days=21) if kev else None,
            ransomware_use=ransomware,
            published_at=published,
            modified_at=published + timedelta(hours=RNG.randint(2, 72)),
            affected_products=[{
                "vendor": vendor,
                "product": product,
                "versions": versions,
                "notes": f"Affects {product} {start}–{end}." if start else f"Affects {product}.",
            }],
            references=[],
            source="NVD",
            source_url="",
            remediation=remediation,
            is_simulated=True,
            created_at=published,
        )
        db.add(vuln)
        vulnerabilities.append((vuln, category))
    db.flush()

    source_cycle = ["NVD", "CISA KEV", "CSIRT Advisory", "AlienVault OTX", "Vendor Advisory", "Internal Sensor", "MITRE ATT&CK"]
    threats: list[Threat] = []
    for vuln, category in vulnerabilities:
        product = vuln.affected_products[0]["product"]
        start = vuln.affected_products[0]["versions"].get("start", "")
        end = vuln.affected_products[0]["versions"].get("end", "")
        issue = {
            "Remote Code Execution": "remote code execution",
            "Credential Compromise": "authentication bypass",
            "Data Breach": "sensitive data exposure",
            "Denial of Service": "denial of service",
            "Software Vulnerability": "security flaw",
            "Phishing": "spoofing flaw",
        }.get(category, "security issue")
        reports = 1 if vuln.cvss_score < 7 else RNG.randint(2, 3)
        for r in range(reports):
            source = "CISA KEV" if (vuln.known_exploited and r == 0) else source_cycle[(vuln.id + r) % len(source_cycle)]
            lag = timedelta(hours=RNG.randint(0, 8) if r == 0 else RNG.randint(2, 30))
            base_age = max(1, int((NOW - vuln.published_at).total_seconds() // 3600))
            published = NOW - timedelta(hours=min(base_age, RNG.randint(1, base_age))) if base_age > 1 else NOW - timedelta(minutes=30)
            if vuln.cve_id == "CVE-2026-48211":
                published = NOW - timedelta(hours=[9, 6, 2][r % 3])
            if vuln.cve_id == "CVE-2026-45871":
                published = NOW - timedelta(hours=[22, 14, 4][r % 3])
            if vuln.cve_id == "CVE-2026-49901":
                published = NOW - timedelta(hours=[40, 26, 11][r % 3])
            name = f"{product} {issue} — {vuln.cve_id}" if r == 0 else f"Follow-up reporting: {vuln.cve_id} impacts {product}"
            desc = vuln.description
            fingerprint_indicators = _make_indicators(RNG.randint(0, 2))
            threat = _build_threat(
                db, name=name, description=desc, category_hint=category, source=source,
                published_at=published, cve=vuln.cve_id, cvss=vuln.cvss_score, epss=vuln.epss_score,
                known_exploited=vuln.known_exploited, technology=product, versions=f"{start}–{end}".strip("–"),
                indicators=fingerprint_indicators, user_ids=analyst_ids,
            )
            threats.append(threat)

    for idx, (category, name, description) in enumerate(NON_CVE_TEMPLATES):
        days_ago = RNG.randint(1, 100)
        published = NOW - timedelta(days=days_ago, hours=RNG.randint(0, 20))
        source = source_cycle[idx % len(source_cycle)]
        tech = _pick(
            ["Fortinet FortiOS", "VMware ESXi", "Microsoft Exchange", "Apache HTTP Server", "Kubernetes", "Linux Kernel", None],
            [2, 2, 2, 2, 1, 1, 2],
        )
        threat = _build_threat(
            db, name=name, description=description, category_hint=category, source=source,
            published_at=published, technology=tech,
            versions=RNG.choice(["7.4.x", "8.0.x", "15.2.x", "2.4.x", "1.29.x", None]) if tech else None,
            indicators=_make_indicators(RNG.randint(1, 3)), user_ids=analyst_ids,
        )
        threats.append(threat)

    for idx, (category, name, description) in enumerate(NON_CVE_BURST):
        published = NOW - timedelta(hours=[60, 44, 26, 12][idx])
        indicators = [
            {"type": "domain", "value": "cdn-lockgrid.top"},
            {"type": "ip", "value": "45.155.205.233", "geo": {"country": "Netherlands", "code": "NL", "lat": 52.3676, "lon": 4.9041}},
            {"type": "sha256", "value": HASH_POOL[0]},
        ]
        threat = _build_threat(
            db, name=name, description=description, category_hint=category,
            source=["OSINT Digest", "AlienVault OTX", "CSIRT Advisory", "Internal Sensor"][idx],
            published_at=published, technology="VMware ESXi", versions="8.0.x",
            indicators=indicators, user_ids=analyst_ids,
        )
        threats.append(threat)

    db.commit()

    # Exposure matching, correlation, and risk assessments over real seeded records.
    exposure.run_scan(db, user_id=admin.id, create_recommendations=True)
    correlation.build(db, days=200, limit=220)

    validated = (
        db.query(AssetVulnerability)
        .filter(AssetVulnerability.status == "potentially_exposed")
        .order_by(AssetVulnerability.match_confidence.desc())
        .limit(32)
        .all()
    )
    for link in validated:
        vuln = db.get(Vulnerability, link.vulnerability_id)
        asset = db.get(Asset, link.asset_id)
        threat = db.query(Threat).filter(Threat.cve_id == vuln.cve_id).order_by(Threat.risk_score.desc()).first() if vuln else None
        if threat and asset:
            risk.persist_assessment(db, threat, asset, link.match_confidence, admin, vulnerability_id=vuln.id)
    db.commit()

    # Historical alerts with mixed severities and lifecycle states.
    ranked = sorted(threats, key=lambda t: t.risk_score or 0, reverse=True)
    status_cycle = ["resolved", "investigating", "acknowledged", "new", "resolved", "new", "acknowledged",
                    "investigating", "resolved", "new", "resolved", "dismissed", "acknowledged", "new",
                    "investigating", "resolved", "new", "acknowledged", "investigating", "resolved",
                    "new", "resolved", "dismissed", "acknowledged", "new", "new"]
    severities = ["critical"] * 4 + ["high"] * 7 + ["medium"] * 8 + ["low"] * 4 + ["informational"] * 2
    alerts: list[Alert] = []
    for idx, severity in enumerate(severities):
        threat = ranked[idx % len(ranked)]
        status = status_cycle[idx]
        if severity == "informational":
            title = f"Context update: {threat.source} publishes additional detail for {threat.affected_technology or 'tracked activity'}"
            trigger = "A new contextual report was added to an existing investigation. No new exploitation evidence was supplied."
        elif severity == "low":
            title = f"Low-priority monitoring: {threat.name}"
            trigger = "A record was observed with limited evidence and no validated inventory exposure."
        elif severity == "medium":
            title = f"Elevated activity: {threat.name}"
            trigger = "Correlated reporting crossed the configured medium-priority threshold. Evidence confidence is moderate."
        elif severity == "high":
            title = f"High-priority early warning: {threat.name}"
            trigger = "The rule engine detected elevated risk combined with corroborating reports. Validate exposure before acting."
        else:
            title = f"Critical early warning: {threat.name}"
            trigger = "Critical risk and known-exploitation evidence intersect with registered asset exposure. Immediate validation is recommended."
        matched_assets = [
            link.asset_id for link in db.query(AssetVulnerability)
            .filter(
                AssetVulnerability.vulnerability_id.in_(
                    [v.id for v, _ in vulnerabilities if v.cve_id == threat.cve_id]
                ),
                AssetVulnerability.status == "potentially_exposed",
            ).all()
        ] if threat.cve_id else []
        alert = _build_alert(
            db, threat, severity=severity, title=title, trigger=trigger,
            action=threat.recommended_action or ACTION_BY_CATEGORY["Other"],
            status=status, detected_at=NOW - timedelta(days=RNG.randint(0, 26), hours=RNG.randint(0, 23)),
            assignee=RNG.choice(analyst_ids) if status in {"acknowledged", "investigating", "resolved"} else None,
            asset_ids=matched_assets[:4],
            vulnerability=next((v for v, _ in vulnerabilities if v.cve_id == threat.cve_id), None),
        )
        alerts.append(alert)
    db.flush()

    for idx, alert in enumerate(alerts[:14]):
        db.add(AnalystNote(
            user_id=RNG.choice(analyst_ids),
            alert_id=alert.id,
            body=[
                "Correlated with additional reporting; validating asset exposure through the inventory module.",
                "Vendor mitigation identified. Awaiting change-window approval before patching.",
                "No evidence of exploitation in our telemetry at this time. Monitoring continues.",
                "Asset owner notified. Verification task opened with the platform team.",
            ][idx % 4],
            created_at=alert.detected_at + timedelta(hours=RNG.randint(1, 12)),
        ))

    # Additional remediation items beyond those generated by exposure matching.
    remediation_templates = [
        ("Patch internet-facing edge appliances", "Known-exploited vulnerabilities affect externally exposed infrastructure.", "critical", "Apply approved firmware updates and verify compensating controls until reboot windows complete."),
        ("Verify backup isolation and restore testing", "Ransomware reporting highlights virtualisation and backup targets.", "high", "Confirm immutable backups and perform a restore validation for critical systems."),
        ("Review VPN authentication logs", "Recent credential-compromise reporting targets remote access.", "high", "Inspect authentication logs for anomalous sessions and rotate affected credentials."),
        ("Enforce phishing-resistant MFA", "Credential theft campaigns continue to target privileged users.", "medium", "Roll out phishing-resistant authentication for administrative accounts."),
        ("Complete inventory software verification", "Several assets lack verified software versions.", "medium", "Reconcile agent inventory with CMDB records and update version data."),
        ("Restrict management interface exposure", "Management interfaces should not be internet-reachable.", "high", "Move administrative interfaces behind the VPN and apply allow-lists."),
        ("Validate open-source dependency integrity", "Supply-chain reporting highlights build pipeline risk.", "medium", "Enable dependency pinning and verify signed artefacts."),
        ("Tune detection coverage for beaconing", "Suspicious network activity reports include C2 beaconing.", "low", "Review detection rules for DNS tunneling and periodic beacon behaviour."),
    ]
    for idx, (title, reason, priority, action) in enumerate(remediation_templates):
        threat = ranked[idx * 3 % len(ranked)]
        db.add(Recommendation(
            ref=next_ref(db, Recommendation, "REC"),
            title=title,
            reason=reason,
            priority=priority,
            threat_id=threat.id,
            vulnerability_id=None,
            asset_id=RNG.choice(assets).id,
            action=action,
            evidence=[{"label": "Basis", "value": "Correlated reporting and asset context"}],
            status=["open", "in_progress", "open", "done", "open", "in_progress", "open", "done"][idx],
            owner_id=RNG.choice(analyst_ids),
            due_at=NOW + timedelta(days=RNG.randint(-3, 14)),
            source_url="",
            created_at=NOW - timedelta(days=RNG.randint(1, 25)),
        ))

    for idx in range(16):
        source = source_defs[idx % len(source_defs)][0]
        started = NOW - timedelta(days=idx // 3, hours=RNG.randint(1, 20))
        mode = "recorded"
        status = "success" if idx % 7 else "degraded"
        db.add(IngestionLog(
            source_key=source,
            started_at=started,
            finished_at=started + timedelta(seconds=RNG.randint(2, 40)),
            status=status,
            mode=mode,
            items_found=RNG.randint(12, 48),
            items_new=RNG.randint(0, 12),
            message="Corpus import completed." if status == "success" else "Upstream response slow; cached records retained.",
            duration_ms=RNG.randint(240, 4200),
        ))

    for idx, (action, entity, detail) in enumerate([
        ("intelligence.corpus.seeded", "system", f"Corpus created with {len(threats)} threat records, {len(vulnerabilities)} vulnerabilities and {len(assets)} assets."),
        ("risk.model.initialised", "settings", "Risk model aegis-risk-v1 initialised with default weights."),
        ("exposure.scan.completed", "assets", "Initial inventory exposure scan completed after dataset import."),
        ("correlation.build.completed", "threats", "Correlation pairs generated from shared entities and lexical similarity."),
        ("source.configured", "threat_sources", "Public connectors registered; optional enrichments await API keys."),
    ]):
        db.add(AuditLog(
            user_id=admin.id,
            user_email="system@aegissentinel.ai",
            action=action,
            entity_type=entity,
            entity_id="-",
            detail=detail,
            ip_address="127.0.0.1",
            created_at=NOW - timedelta(hours=4 - idx),
        ))

    evaluation = classifier.evaluate()
    db.add(ModelEvaluation(
        model_name=evaluation["model_name"],
        dataset_name=evaluation["dataset_name"],
        samples=evaluation["samples"],
        precision=evaluation["precision"],
        recall=evaluation["recall"],
        f1=evaluation["f1"],
        macro_f1=evaluation["macro_f1"],
        confusion=evaluation["confusion"],
        notes=evaluation["notes"],
        evaluated_at=NOW - timedelta(hours=2),
    ))

    db.commit()
    return True
