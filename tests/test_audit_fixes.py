"""
Unit tests for IntelliAssist AI audit fixes:
- Timeline event-driven reconstruction & chronological sorting
- RiskEngine breakdown point sum equality
- IOCExtractor IP validation & domain lowercasing
- RAGEngine low-confidence protection
"""

import pytest
from services.log_analyzer import LogAnalyzer
from services.risk_engine import RiskEngine
from services.ioc_extractor import IOCExtractor
from services.rag_engine import RAGEngine
from services.vector_store import VectorStore
from services.embeddings import EmbeddingService
from services.llm_service import LLMService

def test_timeline_reconstruction_and_sorting():
    raw_log = """
Aug 31 09:45:10 auth sshd[1022]: Failed password for root from 185.220.101.5 port 22
Aug 31 09:45:12 auth sshd[1025]: Failed password for root from 185.220.101.5 port 22
Aug 31 09:45:15 auth sshd[1030]: Accepted password for root from 185.220.101.5 port 22
"""
    parsed = LogAnalyzer.parse_log_text(raw_log, filename="test_auth.log")
    timeline = parsed.get("timeline", [])

    assert len(timeline) >= 2
    # Verify chronological order
    for i in range(len(timeline) - 1):
        assert timeline[i]["epoch_time"] <= timeline[i+1]["epoch_time"]

    # Verify evidence classification field
    for item in timeline:
        assert "evidence_classification" in item
        assert item["evidence_classification"] in ["OBSERVED", "CORRELATED", "HYPOTHETICAL"]

def test_risk_engine_breakdown_equality():
    res = RiskEngine.calculate_indicator_risk(
        indicator="185.220.101.5",
        ioc_type="IP Address",
        matched_docs=[{"filename": "doc1.pdf"}, {"filename": "doc2.pdf"}],
        matched_logs=[{"event_count": 10}],
        contexts=["c2 command and control beacon"]
    )

    score = res["score"]
    breakdown_sum = sum(b["points"] for b in res["breakdown"])
    assert score == breakdown_sum
    assert 0 <= score <= 100

def test_ioc_extractor_validation_and_lowercasing():
    text = "Found IP 185.220.101.5 and invalid version 1.38.0 along with domain LOGIN-MICROSOFT-SECURE.COM"
    iocs = IOCExtractor.extract_from_text(text, source_name="test.txt")

    ip_vals = [i["indicator"] for i in iocs if i["type"] == "IP Address"]
    dom_vals = [i["indicator"] for i in iocs if i["type"] == "Domain"]

    assert "185.220.101.5" in ip_vals
    assert "1.38.0" not in ip_vals  # Should filter package version from IPv4
    assert any("login-microsoft-secure.com" in d for d in dom_vals)  # Normalized lowercased

def test_rag_engine_low_confidence():
    emb = EmbeddingService()
    vs = VectorStore(embedding_service=emb)
    vs.clear()  # Ensure store is empty for test isolation
    llm = LLMService(provider="Demo Mode (Smart AI)")
    rag = RAGEngine(vector_store=vs, llm_service=llm)

    # Empty vector store
    res = rag.answer_question("What is the exact secret password inside nonexistent file?")
    assert res["is_low_confidence"] is True
    assert "Insufficient Threat Intelligence Evidence" in res["answer"] or "No Matching Artifact Found" in res["answer"]
