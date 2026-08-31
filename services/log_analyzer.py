"""
Log Analysis & Security Event Forensic Engine for IntelAssist AI.
Parses auth.log, firewall, web access, system logs, and CSV security events.
Detects explainable brute-force attacks, port scanning, privilege escalation, web injection,
and generates structured forensic timelines with actionable SOC mitigation recommendations.
"""

import re
import csv
import io
import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Set

# Regex Matchers for Common Log Formats
AUTH_FAILED_PASSWORD = re.compile(
    r'(?:Failed password for(?: invalid user)? (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)|authentication failure;.*rhost=(\d+\.\d+\.\d+\.\d+))',
    re.IGNORECASE
)

AUTH_ACCEPTED_PASSWORD = re.compile(
    r'Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)',
    re.IGNORECASE
)

AUTH_SUDO_EXEC = re.compile(
    r'sudo:\s+(\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.+)',
    re.IGNORECASE
)

AUTH_INVALID_USER = re.compile(
    r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)',
    re.IGNORECASE
)

FIREWALL_DROP = re.compile(
    r'(?:DROP|BLOCK|DENY).*SRC=(\d+\.\d+\.\d+\.\d+).*DST=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+)',
    re.IGNORECASE
)

WEB_ACCESS_LOG = re.compile(
    r'^(\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(.*?)\]\s+"([A-Z]+)\s+([^"\s]+)\s+HTTP/[0-9.]+"\s+(\d{3})\s+(\d+|-)',
    re.IGNORECASE
)

# Web Attack Signatures (Explainable Heuristics)
SQLI_PATTERNS = [
    r"union\s+select", r"select\s+.*\s+from", r"'\s*or\s+'1'='1", r"--",
    r"information_schema", r"sleep\(\d+\)", r"benchmark\(\d+"
]
SQLI_COMPILED = [re.compile(p, re.IGNORECASE) for p in SQLI_PATTERNS]

TRAVERSAL_PATTERNS = [
    r"\.\./\.\.", r"/etc/passwd", r"/etc/shadow", r"c:\\windows",
    r"boot\.ini", r"win\.ini"
]
TRAVERSAL_COMPILED = [re.compile(p, re.IGNORECASE) for p in TRAVERSAL_PATTERNS]

WEBSHELL_PATTERNS = [
    r"\.(?:php|jsp|asp|aspx|sh|cgi|pl)(?:\?.*(?:cmd|exec|eval|system|passthru|shell)=)?",
    r"/uploads?/[^/\s]+\.(?:php|jsp|asp|sh)"
]
WEBSHELL_COMPILED = [re.compile(p, re.IGNORECASE) for p in WEBSHELL_PATTERNS]

PRIV_ESC_KEYWORDS = ["sudo su", "chmod 777", "visudo", "adduser", "/bin/sh", "/bin/bash", "net localgroup", "whoami", "mimikatz"]


class LogAnalyzer:
    """Security log parsing, brute-force correlation, and attack detection engine."""

    @classmethod
    def parse_log_text(cls, log_text: str, filename: str = "security.log") -> Dict[str, Any]:
        """
        Parse and analyze unstructured security logs or structured CSV event data.
        Returns comprehensive forensic metrics, detected alerts, unique IPs, and timeline data.
        """
        if not log_text:
            return cls._empty_result(filename)

        lines = log_text.strip().splitlines()
        if not lines:
            return cls._empty_result(filename)

        events: List[Dict[str, Any]] = []
        ip_fail_count: Dict[str, int] = {}
        ip_ports_probed: Dict[str, Set[int]] = {}
        ip_events: Dict[str, List[Dict[str, Any]]] = {}
        unique_ips: Set[str] = set()
        failed_logins = 0
        successful_logins = 0
        priv_esc_events = 0
        web_attack_count = 0

        # Check if CSV format
        first_line = lines[0].strip()
        is_csv = "," in first_line and ("timestamp" in first_line.lower() or "event" in first_line.lower() or "ip" in first_line.lower())

        if is_csv:
            events = cls._parse_csv_logs(lines, filename)
        else:
            for idx, line in enumerate(lines, 1):
                clean_line = line.strip()
                if not clean_line:
                    continue

                event_info = cls._parse_single_line(clean_line, idx, filename)
                if event_info:
                    events.append(event_info)
                    src_ip = event_info.get("source_ip")
                    if src_ip:
                        unique_ips.add(src_ip)
                        if src_ip not in ip_events:
                            ip_events[src_ip] = []
                        ip_events[src_ip].append(event_info)

                    # Aggregations
                    if event_info.get("event_type") in ["Failed Login", "Invalid User"]:
                        failed_logins += 1
                        if src_ip:
                            ip_fail_count[src_ip] = ip_fail_count.get(src_ip, 0) + 1

                    elif event_info.get("event_type") == "Successful Login":
                        successful_logins += 1

                    elif event_info.get("event_type") == "Privilege Escalation":
                        priv_esc_events += 1

                    elif "Web Attack" in event_info.get("event_type", ""):
                        web_attack_count += 1

                    # Port scan tracking
                    port = event_info.get("dest_port")
                    if src_ip and port:
                        if src_ip not in ip_ports_probed:
                            ip_ports_probed[src_ip] = set()
                        try:
                            ip_ports_probed[src_ip].add(int(port))
                        except ValueError:
                            pass

        # Detect High-Level Correlated Alerts
        alerts = cls._correlate_alerts(
            ip_fail_count=ip_fail_count,
            ip_ports_probed=ip_ports_probed,
            events=events,
            filename=filename
        )

        suspicious_count = sum(1 for e in events if e.get("severity") in ["Elevated", "High", "Critical"])
        critical_count = sum(1 for a in alerts if a.get("severity") == "Critical")

        # Calculate Overall Log Risk Score (0-100)
        risk_score = min(100, int(
            (len(alerts) * 20) +
            (critical_count * 25) +
            (min(50, failed_logins * 2)) +
            (priv_esc_events * 15) +
            (web_attack_count * 10)
        ))
        if not events and not alerts:
            risk_score = 0

        # Timeline generation
        timeline = cls._generate_timeline(events)

        return {
            "filename": filename,
            "total_events": len(events) if events else len(lines),
            "suspicious_events": suspicious_count,
            "critical_alerts": len([a for a in alerts if a.get("severity") in ["High", "Critical"]]),
            "unique_ips": len(unique_ips),
            "unique_ip_list": sorted(list(unique_ips)),
            "failed_logins": failed_logins,
            "successful_logins": successful_logins,
            "privilege_escalations": priv_esc_events,
            "web_attacks": web_attack_count,
            "risk_score": risk_score,
            "alerts": alerts,
            "events": events[:500],  # Return top 500 events for fast rendering
            "timeline": timeline
        }

    @classmethod
    def _parse_single_line(cls, line: str, line_no: int, filename: str) -> Optional[Dict[str, Any]]:
        """Parse an individual log line using heuristic rules."""
        # Extract Timestamp if present at start of line
        timestamp = "Unknown"
        ts_match = re.match(r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})', line)
        if ts_match:
            timestamp = ts_match.group(1)

        # 1. SSH / Auth Failed Password
        match_fail = AUTH_FAILED_PASSWORD.search(line)
        if match_fail:
            user = match_fail.group(1) or "root"
            ip = match_fail.group(2) or match_fail.group(4) or "Unknown"
            port = match_fail.group(3) if match_fail.group(3) else "22"
            return {
                "line_no": line_no,
                "timestamp": timestamp,
                "event_type": "Failed Login",
                "severity": "Medium",
                "source_ip": ip,
                "user": user,
                "dest_port": port,
                "description": f"Failed SSH login attempt for user '{user}' from {ip}",
                "raw": line
            }

        # 2. Invalid User probe
        match_invalid = AUTH_INVALID_USER.search(line)
        if match_invalid:
            user = match_invalid.group(1)
            ip = match_invalid.group(2)
            return {
                "line_no": line_no,
                "timestamp": timestamp,
                "event_type": "Invalid User",
                "severity": "Elevated",
                "source_ip": ip,
                "user": user,
                "dest_port": "22",
                "description": f"Login attempt for nonexistent user '{user}' from {ip}",
                "raw": line
            }

        # 3. SSH Accepted Password / Key
        match_succ = AUTH_ACCEPTED_PASSWORD.search(line)
        if match_succ:
            user = match_succ.group(1)
            ip = match_succ.group(2)
            port = match_succ.group(3)
            return {
                "line_no": line_no,
                "timestamp": timestamp,
                "event_type": "Successful Login",
                "severity": "Low",
                "source_ip": ip,
                "user": user,
                "dest_port": port,
                "description": f"Successful authentication for user '{user}' from {ip}",
                "raw": line
            }

        # 4. Sudo Command Execution / Priv Esc
        match_sudo = AUTH_SUDO_EXEC.search(line)
        if match_sudo:
            caller = match_sudo.group(1)
            target_user = match_sudo.group(2)
            cmd = match_sudo.group(3).strip()
            
            is_critical = any(kw in cmd.lower() for kw in ["/bin/sh", "/bin/bash", "chmod 777", "visudo", "passwd", "mimikatz"])
            severity = "Critical" if is_critical else "Elevated"

            return {
                "line_no": line_no,
                "timestamp": timestamp,
                "event_type": "Privilege Escalation",
                "severity": severity,
                "source_ip": "127.0.0.1",
                "user": caller,
                "target_user": target_user,
                "description": f"Sudo command execution by '{caller}' as '{target_user}': {cmd}",
                "raw": line
            }

        # 5. Web Server Access Logs (Apache / Nginx)
        match_web = WEB_ACCESS_LOG.match(line)
        if match_web:
            ip = match_web.group(1)
            ts = match_web.group(2)
            method = match_web.group(3)
            uri = match_web.group(4)
            status = match_web.group(5)

            # Check for web attack signatures
            uri_lower = uri.lower()
            if any(p.search(uri_lower) for p in SQLI_COMPILED):
                return {
                    "line_no": line_no,
                    "timestamp": ts,
                    "event_type": "Web Attack: SQL Injection",
                    "severity": "Critical",
                    "source_ip": ip,
                    "dest_port": "80/443",
                    "description": f"SQL Injection attempt detected from {ip} in URI: {uri[:60]}",
                    "raw": line
                }
            elif any(p.search(uri_lower) for p in TRAVERSAL_COMPILED):
                return {
                    "line_no": line_no,
                    "timestamp": ts,
                    "event_type": "Web Attack: Path Traversal",
                    "severity": "High",
                    "source_ip": ip,
                    "dest_port": "80/443",
                    "description": f"Directory traversal attempt detected from {ip} targeting {uri[:60]}",
                    "raw": line
                }
            elif any(p.search(uri_lower) for p in WEBSHELL_COMPILED):
                return {
                    "line_no": line_no,
                    "timestamp": ts,
                    "event_type": "Web Attack: Webshell Access",
                    "severity": "Critical",
                    "source_ip": ip,
                    "dest_port": "80/443",
                    "description": f"Suspicious webshell request from {ip} targeting {uri[:60]}",
                    "raw": line
                }

            return {
                "line_no": line_no,
                "timestamp": ts,
                "event_type": "Web Access",
                "severity": "Low" if status in ["200", "301", "302"] else "Medium",
                "source_ip": ip,
                "dest_port": "80/443",
                "description": f"{method} {uri[:50]} (HTTP {status})",
                "raw": line
            }

        # 6. Firewall Block / Drop
        match_fw = FIREWALL_DROP.search(line)
        if match_fw:
            src = match_fw.group(1)
            dst = match_fw.group(2)
            port = match_fw.group(3)
            return {
                "line_no": line_no,
                "timestamp": timestamp,
                "event_type": "Firewall Drop",
                "severity": "Medium",
                "source_ip": src,
                "dest_ip": dst,
                "dest_port": port,
                "description": f"Firewall dropped packet from {src} to {dst}:{port}",
                "raw": line
            }

        # Generic line fallback
        ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
        src_ip = ip_match.group(0) if ip_match else None
        
        has_error = any(w in line.lower() for w in ["error", "fatal", "failed", "denied", "critical", "attack"])
        return {
            "line_no": line_no,
            "timestamp": timestamp,
            "event_type": "System Event",
            "severity": "Elevated" if has_error else "Low",
            "source_ip": src_ip,
            "description": line[:80],
            "raw": line
        }

    @classmethod
    def _parse_csv_logs(cls, lines: List[str], filename: str) -> List[Dict[str, Any]]:
        """Parse structured CSV security events."""
        events = []
        reader = csv.DictReader(lines)
        for idx, row in enumerate(reader, 1):
            row_keys = {k.lower(): v for k, v in row.items() if k}
            ts = row_keys.get("timestamp") or row_keys.get("date") or row_keys.get("time") or "Unknown"
            src_ip = row_keys.get("source_ip") or row_keys.get("src_ip") or row_keys.get("ip") or row_keys.get("host") or ""
            event_type = row_keys.get("event_type") or row_keys.get("event") or row_keys.get("action") or "Security Event"
            severity = row_keys.get("severity") or row_keys.get("level") or "Medium"
            desc = row_keys.get("description") or row_keys.get("message") or str(row)

            events.append({
                "line_no": idx,
                "timestamp": ts,
                "event_type": event_type,
                "severity": severity.capitalize(),
                "source_ip": src_ip,
                "description": desc,
                "raw": str(row)
            })
        return events

    @classmethod
    def _correlate_alerts(
        cls,
        ip_fail_count: Dict[str, int],
        ip_ports_probed: Dict[str, Set[int]],
        events: List[Dict[str, Any]],
        filename: str
    ) -> List[Dict[str, Any]]:
        """Correlate parsed events into high-confidence explainable security alerts."""
        alerts: List[Dict[str, Any]] = []

        # 1. SSH / Auth Brute Force Detection
        for ip, fail_cnt in ip_fail_count.items():
            if fail_cnt >= 4:
                # Check if IP eventually succeeded
                succeeded = any(e.get("event_type") == "Successful Login" and e.get("source_ip") == ip for e in events)
                sev = "Critical" if succeeded else "High"
                title = "Critical Brute Force & Account Compromise" if succeeded else "SSH Brute Force Attack Detected"
                rec = "Immediately block the attacker IP on perimeter firewalls, rotate user credentials, and audit privileged sessions." if succeeded else "Add source IP to iptables / fail2ban blocklist and enforce multi-factor authentication."

                alerts.append({
                    "title": title,
                    "severity": sev,
                    "source_ip": ip,
                    "failed_attempts": fail_cnt,
                    "target_service": "SSH Authentication",
                    "time_window": "Observed in log stream",
                    "reason": f"Observed {fail_cnt} authentication failures from single IP ({ip}).{' Followed by successful login (Potential Compromise).' if succeeded else ''}",
                    "mitre_technique": "T1110 (Brute Force)",
                    "recommended_action": rec,
                    "status": "Active Alert"
                })

        # 2. Port Scanning Detection
        for ip, ports in ip_ports_probed.items():
            if len(ports) >= 4:
                port_list = ", ".join(str(p) for p in sorted(list(ports))[:6])
                alerts.append({
                    "title": "Network Port Scanning / Reconnaissance",
                    "severity": "Elevated",
                    "source_ip": ip,
                    "failed_attempts": len(ports),
                    "target_service": f"Multiple Ports ({port_list})",
                    "time_window": "Log Duration",
                    "reason": f"Source IP {ip} systematically probed {len(ports)} distinct network ports.",
                    "mitre_technique": "T1046 (Network Service Scanning)",
                    "recommended_action": "Apply rate-limiting rules and block the probing IP at the external router or Cloud WAF.",
                    "status": "Investigating"
                })

        # 3. Privilege Escalation Alerts
        priv_events = [e for e in events if e.get("event_type") == "Privilege Escalation" and e.get("severity") == "Critical"]
        if priv_events:
            alerts.append({
                "title": "Suspicious Privilege Escalation Detected",
                "severity": "Critical",
                "source_ip": "127.0.0.1 (Local Host)",
                "failed_attempts": len(priv_events),
                "target_service": "Linux Root Subsystem / Sudo",
                "time_window": "Active Session",
                "reason": f"Detected {len(priv_events)} high-risk privileged executions (e.g., shell spawns or permissions modification).",
                "mitre_technique": "T1548 (Abuse Elevation Control Mechanism)",
                "recommended_action": "Revoke active interactive sessions for affected accounts, inspect /etc/sudoers, and verify binary integrity.",
                "status": "Critical Review"
            })

        # 4. Web Application Attack Alerts
        web_attacks = [e for e in events if "Web Attack" in e.get("event_type", "")]
        if web_attacks:
            types = set(e.get("event_type", "") for e in web_attacks)
            ips = set(e.get("source_ip") for e in web_attacks if e.get("source_ip"))
            alerts.append({
                "title": f"Web Application Exploitation Attempts ({', '.join(types)})",
                "severity": "High",
                "source_ip": ", ".join(list(ips)[:3]),
                "failed_attempts": len(web_attacks),
                "target_service": "HTTP/HTTPS Web Application",
                "time_window": "Log Stream",
                "reason": f"Detected {len(web_attacks)} web attack payloads targeting application endpoints (SQLi/Traversal/Webshell).",
                "mitre_technique": "T1190 (Exploit Public-Facing Application)",
                "recommended_action": "Deploy WAF rules to block malicious query patterns, sanitize parameter inputs, and restrict file upload directories.",
                "status": "Active Protection"
            })

        return alerts

    @classmethod
    def _generate_timeline(cls, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate chronological event timeline points for visual timeline render."""
        timeline: List[Dict[str, Any]] = []
        for e in events:
            if e.get("severity") in ["Elevated", "High", "Critical"] or e.get("event_type") in ["Successful Login", "Failed Login"]:
                timeline.append({
                    "time": e.get("timestamp", "N/A"),
                    "title": e.get("event_type", "Event"),
                    "severity": e.get("severity", "Medium"),
                    "description": e.get("description", ""),
                    "source_ip": e.get("source_ip", "")
                })
        return timeline[:30]

    @classmethod
    def _empty_result(cls, filename: str) -> Dict[str, Any]:
        """Return fallback empty result structure."""
        return {
            "filename": filename,
            "total_events": 0,
            "suspicious_events": 0,
            "critical_alerts": 0,
            "unique_ips": 0,
            "unique_ip_list": [],
            "failed_logins": 0,
            "successful_logins": 0,
            "privilege_escalations": 0,
            "web_attacks": 0,
            "risk_score": 0,
            "alerts": [],
            "events": [],
            "timeline": []
        }
