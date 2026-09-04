"""
Explainable Risk Scoring Engine for IntelAssist AI.
Calculates transparent 0-100 security risk scores with itemized factor point breakdowns
based on empirical evidence, cross-source corroboration, exploit signatures, and authentication telemetry.
"""

from typing import Dict, Any, List, Optional, Tuple

class RiskEngine:
    """Calculates explainable risk scores and categorized threat levels."""

    @staticmethod
    def get_risk_level(score: int) -> Tuple[str, str, str]:
        """
        Map numerical score to severity level, hex color, and badge class.
        0-20: Low (Teal/Green)
        21-40: Medium (Blue/Sky)
        41-60: Elevated (Amber)
        61-80: High (Orange)
        81-100: Critical (Red)
        """
        if score >= 81:
            return "Critical", "#ef4444", "risk-critical"
        elif score >= 61:
            return "High", "#f97316", "risk-high"
        elif score >= 41:
            return "Elevated", "#f59e0b", "risk-elevated"
        elif score >= 21:
            return "Medium", "#38bdf8", "risk-medium"
        else:
            return "Low", "#10b981", "risk-low"

    @classmethod
    def calculate_indicator_risk(
        cls,
        indicator: str,
        ioc_type: str,
        matched_docs: List[Dict[str, Any]],
        matched_logs: List[Dict[str, Any]],
        contexts: List[str],
        base_confidence: str = "Medium"
    ) -> Dict[str, Any]:
        """
        Compute an explainable 0-100 risk score for a specific indicator.
        """
        score = 0
        breakdown: List[Dict[str, Any]] = []

        # 1. Base Type Scoring
        if ioc_type == "CVE":
            score += 25
            breakdown.append({"points": 25, "factor": "Known CVE Vulnerability Identifier"})
        elif ioc_type in ["SHA256", "MD5", "SHA1"]:
            score += 15
            breakdown.append({"points": 15, "factor": "Cryptographic Binary / File Hash"})
        elif ioc_type == "Suspicious File":
            score += 20
            breakdown.append({"points": 20, "factor": "Known Malicious Tool / Executable Pattern"})
        else:
            score += 10
            breakdown.append({"points": 10, "factor": f"Network Indicator ({ioc_type})"})

        # 2. Cross-Source Corroboration
        source_count = len(matched_docs) + len(matched_logs)
        if source_count >= 3:
            score += 25
            breakdown.append({"points": 25, "factor": f"Corroborated across {source_count} distinct data sources"})
        elif source_count == 2:
            score += 18
            breakdown.append({"points": 18, "factor": "Corroborated in multiple data sources (Report + Log)"})
        elif source_count == 1:
            score += 8
            breakdown.append({"points": 8, "factor": "Observed in 1 indexed source"})

        # 3. Log Telemetry Evidence
        total_log_events = sum(l.get("event_count", 0) for l in matched_logs)
        if total_log_events >= 20:
            score += 25
            breakdown.append({"points": 25, "factor": f"High volume log activity ({total_log_events} events)"})
        elif total_log_events >= 5:
            score += 15
            breakdown.append({"points": 15, "factor": f"Repeated log activity ({total_log_events} events)"})
        elif total_log_events > 0:
            score += 10
            breakdown.append({"points": 10, "factor": "Directly triggered security log events"})

        # 4. Keyword & Context Triggers
        joined_ctx = " ".join(contexts).lower()
        if any(k in joined_ctx for k in ["c2", "command and control", "beacon", "ransomware", "backdoor", "rce", "exploit"]):
            score += 20
            breakdown.append({"points": 20, "factor": "High-severity threat context (C2 / Exploit / Ransomware)"})
        elif any(k in joined_ctx for k in ["brute force", "failed password", "invalid user", "port scan"]):
            score += 15
            breakdown.append({"points": 15, "factor": "Active credential / reconnaissance attack pattern"})
        elif any(k in joined_ctx for k in ["phishing", "suspicious", "unauthorized"]):
            score += 10
            breakdown.append({"points": 10, "factor": "Suspicious activity mentions in threat context"})

        # Ensure total breakdown points strictly equal final score (clamped to 0-100)
        adjusted_breakdown = []
        running_score = 0
        for item in breakdown:
            pts = item["points"]
            if pts <= 0:
                continue
            if running_score + pts > 100:
                pts = 100 - running_score
            if pts > 0:
                adjusted_breakdown.append({"points": pts, "factor": item["factor"]})
                running_score += pts
            if running_score >= 100:
                break

        if running_score == 0 and (indicator or matched_docs or matched_logs):
            running_score = 5
            adjusted_breakdown.append({"points": 5, "factor": "Baseline indicator observation"})

        final_score = running_score
        level, color, badge_class = cls.get_risk_level(final_score)

        return {
            "score": final_score,
            "level": level,
            "color": color,
            "badge_class": badge_class,
            "breakdown": adjusted_breakdown,
            "confidence": base_confidence,
            "disclaimer": "Heuristic threat evaluation for analytical guidance. Does not represent an absolute verdict."
        }

    @classmethod
    def calculate_incident_risk(
        cls,
        extracted_iocs: List[Dict[str, Any]],
        log_alerts: List[Dict[str, Any]],
        total_failed_logins: int = 0
    ) -> Dict[str, Any]:
        """
        Compute an aggregated risk score for an entire security incident or dataset.
        """
        score = 0
        breakdown: List[Dict[str, Any]] = []

        # 1. Critical Log Alerts
        crit_alerts = [a for a in log_alerts if a.get("severity") == "Critical"]
        if crit_alerts:
            pts = min(35, len(crit_alerts) * 20)
            score += pts
            breakdown.append({"points": pts, "factor": f"{len(crit_alerts)} Critical security alert(s) detected"})

        # 2. High Risk Log Alerts
        high_alerts = [a for a in log_alerts if a.get("severity") == "High"]
        if high_alerts:
            pts = min(25, len(high_alerts) * 12)
            score += pts
            breakdown.append({"points": pts, "factor": f"{len(high_alerts)} High-severity alert(s) detected"})

        # 3. Brute Force Volume
        if total_failed_logins >= 50:
            score += 25
            breakdown.append({"points": 25, "factor": f"Massive authentication brute-force ({total_failed_logins} failures)"})
        elif total_failed_logins >= 5:
            score += 15
            breakdown.append({"points": 15, "factor": f"Multiple authentication failures ({total_failed_logins} attempts)"})

        # 4. Critical & High IOCs
        crit_iocs = [i for i in extracted_iocs if i.get("risk_level") in ["Critical", "High"]]
        if crit_iocs:
            pts = min(25, len(crit_iocs) * 5)
            score += pts
            breakdown.append({"points": pts, "factor": f"{len(crit_iocs)} High/Critical indicator(s) identified"})

        # Ensure breakdown points sum strictly equals final score
        adjusted_breakdown = []
        running_score = 0
        for item in breakdown:
            pts = item["points"]
            if pts <= 0:
                continue
            if running_score + pts > 100:
                pts = 100 - running_score
            if pts > 0:
                adjusted_breakdown.append({"points": pts, "factor": item["factor"]})
                running_score += pts
            if running_score >= 100:
                break

        if running_score == 0 and (extracted_iocs or log_alerts or total_failed_logins > 0):
            running_score = 10
            adjusted_breakdown.append({"points": 10, "factor": "Baseline ingested incident telemetry"})

        final_score = running_score
        level, color, badge_class = cls.get_risk_level(final_score)

        return {
            "score": final_score,
            "level": level,
            "color": color,
            "badge_class": badge_class,
            "breakdown": adjusted_breakdown,
            "disclaimer": "Aggregated incident posture score based on ingested telemetry and intelligence."
        }
