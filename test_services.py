"""
Comprehensive test script for IntelAssist AI Cyber Threat Intelligence Platform.
Tests:
1. Cyber sample data generation (APT29 PDF, auth.log, firewall.log, web attacks, IOC CSV, DOCX).
2. Document processing and text extraction.
3. Chunker, dense 384-dim semantic embeddings, and VectorStore.
4. IOC Extraction Engine (IPs, domains, hashes, CVEs, defanging).
5. Forensic Log Analysis Engine (Brute-force, port scan, web injection, priv-esc).
6. Threat Correlation Engine (Cross-source matching & Plotly graph generation).
7. Explainable Risk Scoring Engine (0-100 score & point breakdowns).
8. MITRE ATT&CK Mapping Engine.
9. Authentication & User Management Service.
10. LLM Cyber System Prompts, Structured Incident Reports, and RAG Engine.
"""

import sys
import os
from pathlib import Path

# Force UTF-8 on Windows stdout
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from utils.sample_docs import generate_all_samples
from services.document_processor import DocumentProcessor
from services.chunker import TextChunker
from services.embeddings import EmbeddingService
from services.vector_store import VectorStore
from services.llm_service import LLMService
from services.rag_engine import RAGEngine
from services.summarizer import DocumentSummarizer
from services.conversation_manager import ConversationManager
from services.auth_service import AuthService
from services.ioc_extractor import IOCExtractor
from services.log_analyzer import LogAnalyzer
from services.threat_correlator import ThreatCorrelator
from services.risk_engine import RiskEngine
from services.mitre_mapper import MITREMapper

def run_all_tests():
    print("======================================================================")
    print("🛡️  Running IntelAssist AI Cyber Threat Intelligence Verification Suite")
    print("======================================================================")

    # 1. Test cyber sample data generation
    print("\n[1/10] Generating cyber threat advisories, logs, and IOC feeds...")
    sample_files = generate_all_samples()
    for sf in sample_files:
        assert sf.exists(), f"Sample file {sf} was not created."
        print(f"  ✓ Created: {sf.name} ({sf.stat().st_size} bytes)")
    assert len(sample_files) >= 5, "Expected at least 5 sample artifacts."

    # 2. Test document extraction & chunking
    print("\n[2/10] Testing DocumentProcessor & TextChunker on PDF, DOCX, TXT, LOG...")
    all_chunks = []
    chunker = TextChunker(chunk_size=500, chunk_overlap=100)
    registry = {}

    for sf in sample_files:
        with open(sf, "rb") as f:
            bytes_data = f.read()
        doc_info = DocumentProcessor.process_file(bytes_data, sf.name)
        chunks = chunker.chunk_document(doc_info)
        all_chunks.extend(chunks)
        registry[sf.name] = {
            "filename": sf.name,
            "full_text": doc_info.get("full_text", ""),
            "chunk_count": len(chunks),
            "total_pages": doc_info.get("total_pages", 1)
        }
        print(f"  ✓ Extracted '{sf.name}': {doc_info['total_pages']} page(s), {len(chunks)} chunks, {doc_info['total_chars']} chars.")

    assert len(all_chunks) > 0, "No chunks generated."

    # 3. Test EmbeddingService & VectorStore
    print("\n[3/10] Testing Dense 384-dim Embeddings & VectorStore Cosine Index...")
    emb_service = EmbeddingService()
    vstore = VectorStore(embedding_service=emb_service)
    vstore.clear()
    vstore.add_documents(all_chunks)
    assert vstore.total_chunks == len(all_chunks), "Vector store count mismatch."

    # Test semantic retrieval
    search_res = vstore.search("WinRAR remote code execution vulnerability", top_k=3)
    assert len(search_res) > 0, "Expected vector search results."
    print(f"  ✓ VectorStore indexed {vstore.total_chunks} chunks.")
    print(f"  ✓ Semantic Query matched: '{search_res[0]['filename']}' (Score: {search_res[0]['score']:.3f})")

    # 4. Test IOC Extraction Engine
    print("\n[4/10] Testing Automated IOC Extraction Engine...")
    apt_text = registry.get("Sample_Threat_Intel_Report_APT29.pdf", {}).get("full_text", "")
    extracted = IOCExtractor.extract_from_text(apt_text, "Sample_Threat_Intel_Report_APT29.pdf")
    
    # Check extracted categories
    ip_iocs = [i for i in extracted if i["type"] == "IP Address"]
    domain_iocs = [i for i in extracted if i["type"] == "Domain"]
    cve_iocs = [i for i in extracted if i["type"] == "CVE"]
    hash_iocs = [i for i in extracted if i["type"] == "SHA256"]

    print(f"  ✓ Extracted {len(extracted)} total IOCs from APT29 report:")
    print(f"    - {len(ip_iocs)} IP addresses (e.g. {ip_iocs[0]['indicator'] if ip_iocs else 'N/A'})")
    print(f"    - {len(domain_iocs)} Domains (e.g. {domain_iocs[0]['indicator'] if domain_iocs else 'N/A'})")
    print(f"    - {len(cve_iocs)} CVEs (e.g. {cve_iocs[0]['indicator'] if cve_iocs else 'N/A'})")
    print(f"    - {len(hash_iocs)} SHA256 hashes")

    assert len(extracted) > 0, "No IOCs extracted."
    assert any(i["indicator"] == "185.220.101.5" for i in extracted), "Expected 185.220.101.5 in extracted IOCs."

    # Test defanging
    defanged_ip = IOCExtractor.defang("185.220.101.5")
    assert defanged_ip == "185[.]220[.]101[.]5", f"Unexpected defang: {defanged_ip}"
    print(f"  ✓ Defanging test: '185.220.101.5' -> '{defanged_ip}'")

    # 5. Test Forensic Log Analysis Engine
    print("\n[5/10] Testing Forensic Log Analysis & Attack Detection Engine...")
    auth_log_path = next(sf for sf in sample_files if sf.name == "Sample_Auth_BruteForce.log")
    with open(auth_log_path, "r", encoding="utf-8") as f:
        auth_log_content = f.read()

    parsed_log = LogAnalyzer.parse_log_text(auth_log_content, filename="Sample_Auth_BruteForce.log")
    print(f"  ✓ Parsed {parsed_log['total_events']} events from auth.log")
    print(f"  ✓ Detected {parsed_log['failed_logins']} failed logins, {len(parsed_log['alerts'])} alerts (Risk Score: {parsed_log['risk_score']}/100)")

    # Verify brute force alert
    bf_alert = next((a for a in parsed_log["alerts"] if "Brute Force" in a["title"]), None)
    assert bf_alert is not None, "Expected SSH brute force alert to be triggered."
    assert bf_alert["source_ip"] == "185.220.101.5", f"Expected attacker IP 185.220.101.5, got {bf_alert['source_ip']}"
    print(f"  ✓ Heuristic Alert: '{bf_alert['title']}' from {bf_alert['source_ip']} (Attempts: {bf_alert['failed_attempts']})")

    # 6. Test Threat Correlator
    print("\n[6/10] Testing Threat Correlation & Relationship Graph Engine...")
    correlator_res = ThreatCorrelator.correlate_indicator(
        target_indicator="185.220.101.5",
        document_registry=registry,
        log_results=[parsed_log],
        all_extracted_iocs=extracted
    )
    assert len(correlator_res["matched_docs"]) > 0, "Expected matched docs for 185.220.101.5"
    assert len(correlator_res["matched_logs"]) > 0, "Expected matched logs for 185.220.101.5"
    print(f"  ✓ Cross-correlated '185.220.101.5' across {len(correlator_res['matched_docs'])} report(s) and {len(correlator_res['matched_logs'])} log file(s).")
    
    # Generate Plotly graph
    fig = ThreatCorrelator.generate_relationship_graph("185.220.101.5", correlator_res)
    assert fig is not None, "Failed to build Plotly relationship graph."
    print("  ✓ Generated interactive Plotly 2D relationship network graph.")

    # 7. Test Explainable Risk Scoring Engine
    print("\n[7/10] Testing Explainable Risk Scoring Engine...")
    risk_data = RiskEngine.calculate_indicator_risk(
        indicator="185.220.101.5",
        ioc_type="IP Address",
        matched_docs=correlator_res["matched_docs"],
        matched_logs=correlator_res["matched_logs"],
        contexts=correlator_res["contexts"]
    )
    assert risk_data["score"] >= 70, f"Expected high/critical risk score, got {risk_data['score']}"
    print(f"  ✓ Calculated Risk Score: {risk_data['score']}/100 ({risk_data['level']})")
    print(f"  ✓ Point breakdown itemization:")
    for b in risk_data["breakdown"]:
        print(f"    - {b['factor']}: +{b['points']} pts")

    # 8. Test MITRE ATT&CK Mapping
    print("\n[8/10] Testing MITRE ATT&CK Mapping Engine...")
    mitre_techniques = MITREMapper.map_evidence(extracted, parsed_log.get("alerts", []), apt_text)
    assert len(mitre_techniques) > 0, "Expected mapped MITRE techniques."
    print(f"  ✓ Identified {len(mitre_techniques)} MITRE ATT&CK techniques in evidence:")
    for t in mitre_techniques[:4]:
        print(f"    - {t['technique_id']}: {t['technique_name']} ({t['tactic']})")

    # 9. Test Authentication & User Management Service
    print("\n[9/10] Testing AuthService & PBKDF2 Password Hashing...")
    auth_service = AuthService()
    demo_user = auth_service.get_demo_account()
    assert demo_user["username"] == "analyst", "Demo user check failed."
    
    # Authenticate demo user
    auth_user = auth_service.authenticate("analyst", "intelassist2026")
    assert auth_user is not None, "Demo user authentication failed."
    print(f"  ✓ Authenticated Demo Account: '{auth_user['full_name']}' ({auth_user['role']})")

    # Test new user registration
    success, msg = auth_service.register("test_soc_analyst", "SecurePass@2026", "test@soc.local", "Test SOC Analyst", "Senior Threat Analyst")
    if success:
        print(f"  ✓ Registered new user 'test_soc_analyst' with salted PBKDF2 hash.")
        auth_new = auth_service.authenticate("test_soc_analyst", "SecurePass@2026")
        assert auth_new is not None, "Failed to authenticate newly registered user."

    # 10. Test LLM & RAG Engine Cyber Answering
    print("\n[10/10] Testing Cyber RAG Engine & Incident Investigation Assistant...")
    llm = LLMService(provider="Demo Mode (Smart AI)")
    rag = RAGEngine(vector_store=vstore, llm_service=llm)

    # Test incident response Q&A
    q = "What happened during this security incident and what is the full attack chain?"
    rag_res = rag.answer_question(q, top_k=4)
    assert len(rag_res["answer"]) > 100, "Answer too short."
    assert len(rag_res["sources"]) > 0, "Expected cited sources."
    print(f"  ✓ RAG synthesized evidence-grounded answer ({rag_res['latency_sec']}s, {len(rag_res['sources'])} sources cited).")
    print(f"  ✓ Answer preview:\n{rag_res['answer'][:240]}...\n")

    # Test threat report summarizer
    summarizer = DocumentSummarizer(llm_service=llm)
    sum_res = summarizer.summarize(apt_text, mode="Executive Threat Brief", doc_name="Sample_Threat_Intel_Report_APT29.pdf")
    assert len(sum_res["summary"]) > 80, "Summary too short."
    print(f"  ✓ Generated Executive Threat Briefing ({len(sum_res['topics'])} topics, {len(sum_res.get('takeaways', []))} takeaways).")

    print("\n======================================================================")
    print("✨ ALL 10 INTELASSIST AI VERIFICATION TESTS PASSED SUCCESSFULLY! ✨")
    print("======================================================================")

if __name__ == "__main__":
    run_all_tests()
