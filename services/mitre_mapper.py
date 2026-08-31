"""
MITRE ATT&CK Heuristic Technique Mapping Engine for IntelAssist AI.
Correlates observed log events, extracted indicators, and threat intelligence context
to MITRE ATT&CK Enterprise Matrix tactics and techniques with evidence attribution.
"""

from typing import List, Dict, Any, Optional

TECHNIQUES_DATABASE = {
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt authentication into accounts with password guessing.",
        "mitigation": "Enforce account lockouts, multi-factor authentication (MFA), rate limiting, and fail2ban rules."
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts to gain initial access or maintain persistence.",
        "mitigation": "Audit privileged accounts, implement just-in-time access, and monitor anomalous login geolocations/times."
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters (e.g., PowerShell, Bash, cmd, Python) to execute commands.",
        "mitigation": "Enable PowerShell Constrained Language Mode, script block logging, and restrict execution policies."
    },
    "T1548": {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may circumvent mechanisms designed to control elevation of privileges to gain higher permissions.",
        "mitigation": "Restrict sudoers permissions, enforce UAC, and restrict binary execution with setuid bits."
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts to identify vulnerable entrypoints.",
        "mitigation": "Configure perimeter firewalls to drop unsolicited incoming port probes and deploy network IDS/IPS."
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit vulnerabilities in internet-facing software such as web servers or VPN gateways.",
        "mitigation": "Patch public software against known CVEs, deploy Web Application Firewalls (WAF), and sanitize inputs."
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol (C2)",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols (HTTP/HTTPS/DNS) to avoid detection by firewalls.",
        "mitigation": "Inspect SSL/TLS egress traffic, monitor outbound beacon intervals, and sinkhole known malicious C2 domains."
    },
    "T1003": {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may dump credentials from the operating system memory, security databases (e.g., LSASS, SAM).",
        "mitigation": "Enable Windows Credential Guard, LSA protection, and monitor for unauthorized memory access to lsass.exe."
    },
    "T1566": {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages with malicious attachments or links to gain execution on victim endpoints.",
        "mitigation": "Deploy email filtering gateways (SPF/DKIM/DMARC), sandbox email attachments, and conduct user awareness training."
    },
    "T1486": {
        "id": "T1486",
        "name": "Data Encrypted for Impact (Ransomware)",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems or files to interrupt availability and extort victims.",
        "mitigation": "Maintain immutable offsite backups, restrict write permissions on shared drives, and monitor mass file renames."
    }
}

class MITREMapper:
    """Heuristic mapping of evidence and indicators to MITRE ATT&CK framework."""

    @classmethod
    def map_evidence(
        cls,
        extracted_iocs: List[Dict[str, Any]],
        log_alerts: List[Dict[str, Any]],
        document_text: str = ""
    ) -> List[Dict[str, Any]]:
        """
        Analyze indicators, log alerts, and text to map possible MITRE ATT&CK techniques.
        """
        mappings: Dict[str, Dict[str, Any]] = {}
        text_lower = document_text.lower()

        # Helper to add mapping
        def add_mapping(tech_id: str, evidence: str, confidence: str = "Medium"):
            meta = TECHNIQUES_DATABASE.get(tech_id)
            if not meta:
                return
            if tech_id not in mappings:
                mappings[tech_id] = {
                    "technique_id": meta["id"],
                    "technique_name": meta["name"],
                    "tactic": meta["tactic"],
                    "description": meta["description"],
                    "mitigation": meta["mitigation"],
                    "evidences": [evidence],
                    "confidence": confidence,
                    "label": "Possible MITRE ATT&CK Mapping (Heuristic Correlation)"
                }
            else:
                if evidence not in mappings[tech_id]["evidences"]:
                    mappings[tech_id]["evidences"].append(evidence)

        # 1. Map from Log Alerts
        for a in log_alerts:
            title = a.get("title", "").lower()
            reason = a.get("reason", "")
            if "brute force" in title:
                add_mapping("T1110", f"Log Alert: {reason}", "High")
            if "privilege escalation" in title:
                add_mapping("T1548", f"Log Alert: {reason}", "High")
            if "port scanning" in title:
                add_mapping("T1046", f"Log Alert: {reason}", "High")
            if "web application" in title or "sql" in title:
                add_mapping("T1190", f"Log Alert: {reason}", "High")

        # 2. Map from Extracted IOCs & Context
        for ioc in extracted_iocs:
            ind = ioc.get("indicator", "")
            ctx = (ioc.get("context", "") + " " + ioc.get("context_snippet", "")).lower()

            if "c2" in ctx or "beacon" in ctx or "command and control" in ctx:
                add_mapping("T1071", f"C2 communication context observed with indicator '{ind}'", "High")
            if "phishing" in ctx:
                add_mapping("T1566", f"Phishing context linked to '{ind}'", "Medium")
            if "mimikatz" in ctx or "credential" in ctx:
                add_mapping("T1003", f"Credential dumping / Mimikatz context with indicator '{ind}'", "High")
            if "ransomware" in ctx or "encrypt" in ctx:
                add_mapping("T1486", f"Ransomware encryption context associated with '{ind}'", "High")
            if ioc.get("type") == "CVE":
                add_mapping("T1190", f"Exploitation of vulnerability '{ind}'", "High")

        # 3. Map from Document Text keywords
        if "spear-phishing" in text_lower or "phishing email" in text_lower:
            add_mapping("T1566", "Text mentions spear-phishing / email lure delivery mechanism", "Medium")
        if "powershell" in text_lower or "cmd.exe" in text_lower or "bash script" in text_lower:
            add_mapping("T1059", "Document references command-line interpreter scripting execution", "Medium")

        return list(mappings.values())
