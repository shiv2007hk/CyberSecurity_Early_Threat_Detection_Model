/* Public MITRE ATT&CK reference mapping. Presentation reference only: counts in the
   interface come from stored indicator records, never from this table. */

export type AttackTechnique = {
  name: string;
  tactic: string;
  note: string;
};

export const ATTACK_TACTICS = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

export const ATTACK_TECHNIQUES: Record<string, AttackTechnique> = {
  T1595: { name: "Active Scanning", tactic: "Reconnaissance", note: "Probing address ranges and services for reachable targets." },
  T1598: { name: "Phishing for Information", tactic: "Reconnaissance", note: "Deceptive messages used to collect information rather than deliver a payload." },
  T1566: { name: "Phishing", tactic: "Initial Access", note: "Deceptive messaging that attempts to obtain access or deliver a payload." },
  "T1566.001": { name: "Spearphishing Attachment", tactic: "Initial Access", note: "A malicious attachment delivered to a targeted recipient." },
  T1190: { name: "Exploit Public-Facing Application", tactic: "Initial Access", note: "Exploitation of an internet-reachable service." },
  T1078: { name: "Valid Accounts", tactic: "Initial Access", note: "Use of legitimate credentials; also seen in persistence and privilege escalation." },
  T1059: { name: "Command and Scripting Interpreter", tactic: "Execution", note: "Abuse of a native interpreter to run attacker-controlled commands." },
  "T1059.001": { name: "PowerShell", tactic: "Execution", note: "Command execution through PowerShell." },
  T1203: { name: "Exploitation for Client Execution", tactic: "Execution", note: "Exploitation of a client application to run code." },
  T1547: { name: "Boot or Logon Autostart Execution", tactic: "Persistence", note: "Configuration changes that restart attacker code on boot or logon." },
  "T1505.003": { name: "Web Shell", tactic: "Persistence", note: "A script placed on a server to retain remote access." },
  T1055: { name: "Process Injection", tactic: "Defense Evasion", note: "Running code inside another process to avoid scrutiny." },
  "T1552.001": { name: "Credentials In Files", tactic: "Credential Access", note: "Credentials recovered from files or configuration stores." },
  T1110: { name: "Brute Force", tactic: "Credential Access", note: "Repeated authentication attempts against known accounts or services." },
  T1046: { name: "Network Service Discovery", tactic: "Discovery", note: "Enumerating services reachable from a compromised host." },
  "T1021.001": { name: "Remote Desktop Protocol", tactic: "Lateral Movement", note: "Use of RDP to move between systems." },
  T1005: { name: "Data from Local System", tactic: "Collection", note: "Collection of files from the local host before exfiltration." },
  "T1071.001": { name: "Web Protocols", tactic: "Command and Control", note: "Application-layer web protocols used for command and control." },
  T1105: { name: "Ingress Tool Transfer", tactic: "Command and Control", note: "Transfer of tools or payloads into the compromised environment." },
  T1041: { name: "Exfiltration Over C2 Channel", tactic: "Exfiltration", note: "Data removed over the existing command and control channel." },
  T1567: { name: "Exfiltration Over Web Service", tactic: "Exfiltration", note: "Data removed through a public web service." },
  T1486: { name: "Data Encrypted for Impact", tactic: "Impact", note: "Encryption of data to disrupt operations." },
  T1490: { name: "Inhibit System Recovery", tactic: "Impact", note: "Removal of backups or recovery points to obstruct restoration." },
  T1498: { name: "Network Denial of Service", tactic: "Impact", note: "Exhaustion of network capacity or service state." },
  T1499: { name: "Endpoint Denial of Service", tactic: "Impact", note: "Exhaustion of host resources so a service can no longer respond." },
};

export const ATTACK_CLASS_NOTES: Record<string, string> = {
  "Remote Code Execution": "Execution of attacker-controlled code through a vulnerable service or library.",
  "Software Vulnerability": "A published weakness with severity and exploitation evidence attached.",
  "Data Breach": "Unauthorised access to or disclosure of protected data.",
  "Credential Compromise": "Credential theft, reuse or exposure that enables account access.",
  "Denial of Service": "Disruption of availability through traffic exhaustion or resource abuse.",
  Phishing: "Deceptive messaging that attempts to obtain access or deliver a payload.",
  Ransomware: "Encryption or extortion activity affecting operational data.",
  Malware: "Malicious code or tooling observed in reporting.",
  "Supply Chain Compromise": "Compromise introduced through a supplier, dependency or update channel.",
  "Suspicious Network Activity": "Network behaviour recorded as anomalous or indicative of intrusion.",
};
