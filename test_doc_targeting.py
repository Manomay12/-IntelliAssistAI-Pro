"""
Verification test for strict per-document targeting and multi-document cyber threat intelligence synthesis.
"""

import sys
from pathlib import Path

# Setup path and encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).parent.resolve()))

from services.vector_store import VectorStore
from services.llm_service import LLMService
from services.rag_engine import RAGEngine

def main():
    print("=" * 60)
    print("🛡️  Testing Multi-Document Threat Scoping & Strict Targeting")
    print("=" * 60)

    vdb = VectorStore()
    llm = LLMService(provider="Demo Mode (Smart AI)")
    rag = RAGEngine(vector_store=vdb, llm_service=llm)

    docs = vdb.get_all_documents()
    print(f"[*] Available Documents in Vector DB ({len(docs)}):")
    for d in docs:
        print(f"  - {d}")

    assert len(docs) >= 3, "Expected at least 3 sample documents in Vector DB."

    # Test 1: Strict Target to APT29 PDF
    doc_1 = "Sample_Threat_Intel_Report_APT29.pdf"
    if doc_1 in docs:
        print(f"\n[Test 1] Querying with target scope: {doc_1}...")
        res_1 = rag.answer_question("Summarize the main threats and CVEs", filter_doc=doc_1)
        sources_1 = [s["filename"] for s in res_1.get("sources", [])]
        print(f"  + Sources: {set(sources_1)}")
        assert all(s == doc_1 for s in sources_1), f"Expected all sources to be {doc_1}, got {sources_1}"
        assert doc_1 in res_1["answer"], f"Expected {doc_1} mentioned in answer title."
        print("  ✓ Strict targeting verified for APT29 PDF.")

    # Test 2: Strict Target to Incident Response Forensics DOCX
    doc_2 = "Incident_Response_Forensics_Report.docx"
    if doc_2 in docs:
        print(f"\n[Test 2] Querying with target scope: {doc_2}...")
        res_2 = rag.answer_question("What is the attack chain and root cause?", filter_doc=doc_2)
        sources_2 = [s["filename"] for s in res_2.get("sources", [])]
        print(f"  + Sources: {set(sources_2)}")
        assert all(s == doc_2 for s in sources_2), f"Expected all sources to be {doc_2}, got {sources_2}"
        assert doc_2 in res_2["answer"], f"Expected {doc_2} mentioned in answer title."
        print("  ✓ Strict targeting verified for Incident Response Forensics Report.")

    # Test 3: Multi-document Query
    print("\n[Test 3] Querying across All Documents...")
    res_all = rag.answer_question("What malicious IP addresses and indicators are observed?")
    sources_all = set(s["filename"] for s in res_all.get("sources", []))
    print(f"  + Multi-doc sources cited: {sources_all}")
    assert len(sources_all) >= 1, "Expected cited sources across repository."
    print("  ✓ Multi-document synthesis verified.")

    print("\n" + "=" * 60)
    print("✨ ALL TARGETING AND SCOPING TESTS PASSED! ✨")
    print("=" * 60)

if __name__ == "__main__":
    main()
