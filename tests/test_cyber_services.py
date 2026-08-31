"""
Unit tests for IntelAssist AI Cyber Threat Intelligence services using standard library unittest.
"""

import unittest
import tempfile
from pathlib import Path
from services.ioc_extractor import IOCExtractor
from services.log_analyzer import LogAnalyzer
from services.threat_correlator import ThreatCorrelator
from services.risk_engine import RiskEngine
from services.mitre_mapper import MITREMapper
from services.auth_service import AuthService

class TestCyberServices(unittest.TestCase):

    def test_ioc_extraction_ipv4_and_domains(self):
        text = "Attacker contacted C2 IP 185.220.101.5 and domain login-microsoft-secure.com via HTTP port 80."
        iocs = IOCExtractor.extract_from_text(text, "test_report.pdf")
        indicators = [i["indicator"] for i in iocs]
        self.assertIn("185.220.101.5", indicators)
        self.assertIn("login-microsoft-secure.com", indicators)

    def test_ioc_defanging(self):
        self.assertEqual(IOCExtractor.defang("1.2.3.4"), "1[.]2[.]3[.]4")
        self.assertEqual(IOCExtractor.defang("evil.com"), "evil[.]com")
        self.assertEqual(IOCExtractor.defang("http://evil.com"), "hxxp://evil[.]com")

    def test_log_analyzer_brute_force_detection(self):
        sample_log = """
        Aug 31 10:00:01 server sshd[1001]: Failed password for invalid user admin from 185.220.101.5 port 42100 ssh2
        Aug 31 10:00:02 server sshd[1002]: Failed password for invalid user root from 185.220.101.5 port 42101 ssh2
        Aug 31 10:00:03 server sshd[1003]: Failed password for invalid user oracle from 185.220.101.5 port 42102 ssh2
        Aug 31 10:00:04 server sshd[1004]: Failed password for invalid user deploy from 185.220.101.5 port 42103 ssh2
        Aug 31 10:00:05 server sshd[1005]: Failed password for invalid user test from 185.220.101.5 port 42104 ssh2
        """
        res = LogAnalyzer.parse_log_text(sample_log, "auth.log")
        self.assertEqual(res["failed_logins"], 5)
        self.assertGreater(len(res["alerts"]), 0)
        self.assertTrue(any("Brute Force" in a["title"] for a in res["alerts"]))

    def test_risk_engine_calculation(self):
        risk = RiskEngine.calculate_indicator_risk(
            indicator="185.220.101.5",
            ioc_type="IP Address",
            matched_docs=[{"filename": "threat_advisory.pdf", "snippet": "C2 server 185.220.101.5 observed in Cobalt Strike campaign"}],
            matched_logs=[{"filename": "auth.log", "event_count": 20, "first_event": "SSH Failed login"}],
            contexts=["C2 Command and Control node in Cobalt Strike campaign"]
        )
        self.assertGreaterEqual(risk["score"], 70)
        self.assertIn(risk["level"], ["High", "Critical"])
        self.assertGreater(len(risk["breakdown"]), 0)

    def test_mitre_mapping(self):
        iocs = [{"indicator": "185.220.101.5", "type": "IP Address", "context": "C2 beacon communication"}]
        alerts = [{"title": "SSH Brute Force Attack", "reason": "5 failed logins"}]
        text = "Adversary used spear-phishing emails to deliver payloads."
        
        mappings = MITREMapper.map_evidence(iocs, alerts, text)
        tech_ids = [m["technique_id"] for m in mappings]
        self.assertIn("T1110", tech_ids)  # Brute Force
        self.assertIn("T1071", tech_ids)  # C2
        self.assertIn("T1566", tech_ids)  # Phishing

    def test_auth_service(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_file = Path(tmp_dir) / "test_users.db"
            auth = AuthService(db_path=db_file)
            
            # Test demo user
            demo = auth.get_demo_account()
            self.assertEqual(demo["username"], "analyst")
            
            # Test registration and login
            success, _ = auth.register("soc_lead", "MasterPass@123", "lead@soc.net", "Lead Analyst")
            self.assertTrue(success)
            
            user = auth.authenticate("soc_lead", "MasterPass@123")
            self.assertIsNotNone(user)
            self.assertEqual(user["full_name"], "Lead Analyst")

if __name__ == "__main__":
    unittest.main()
