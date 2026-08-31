"""
Unit tests for DocumentSummarizer and Cross-Document Comparison using standard library unittest.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unittest
from services.summarizer import DocumentSummarizer
from services.llm_service import LLMService

SAMPLE_DOC_TEXT = """
Threat Advisory: APT29 Spear-Phishing Campaign. The adversary leverages CVE-2023-38831 WinRAR execution vulnerability.
Adversaries establish command and control on 185.220.101.5 and deploy custom beacons.
Credential dumping is executed using Mimikatz and privilege escalation occurs via sudo misconfigurations.
"""

SAMPLE_DOC_B_TEXT = """
Incident Response Forensics Report on Ransomware Intrusion.
The intrusion began via unauthorized SSH brute force on port 22.
Lateral movement was facilitated via valid accounts and data exfiltration occurred to secondary nodes.
"""

class TestSummarizer(unittest.TestCase):

    def setUp(self):
        llm = LLMService(provider="Demo Mode (Smart AI)")
        self.summarizer = DocumentSummarizer(llm_service=llm)

    def test_summary_modes(self):
        modes = ["Executive Summary", "Detailed Summary", "Key Findings", "Bullet Points", "Quick Summary"]
        for m in modes:
            res = self.summarizer.summarize(SAMPLE_DOC_TEXT, mode=m, doc_name="APT29_Report.pdf")
            self.assertGreater(len(res["summary"]), 20)
            self.assertEqual(res["mode"], m)
            self.assertGreater(len(res["topics"]), 0)

    def test_entity_and_topic_extraction(self):
        topics = self.summarizer.extract_key_topics(SAMPLE_DOC_TEXT)
        self.assertGreater(len(topics), 0)

        entities = self.summarizer.extract_entities(SAMPLE_DOC_TEXT)
        self.assertIsInstance(entities, dict)

    def test_compare_documents(self):
        comp = self.summarizer.compare_documents(
            doc_a_name="APT29_Report.pdf",
            doc_a_text=SAMPLE_DOC_TEXT,
            doc_b_name="IR_Forensics.docx",
            doc_b_text=SAMPLE_DOC_B_TEXT
        )

        self.assertEqual(comp["doc_a"], "APT29_Report.pdf")
        self.assertEqual(comp["doc_b"], "IR_Forensics.docx")
        self.assertIn("Comparative Dimension", comp["comparison_table"])

if __name__ == "__main__":
    unittest.main()
