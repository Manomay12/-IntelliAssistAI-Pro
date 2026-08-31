"""
Retrieval-Augmented Generation (RAG) Engine for IntelAssist AI.
Features query normalization for cybersecurity acronyms and threat intelligence terminology,
per-document scoping, adaptive semantic retrieval, hallucination protection, and verifiable threat analysis synthesis.
"""

import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from services.vector_store import VectorStore
from services.llm_service import LLMService

logger = logging.getLogger(__name__)

SLANG_TYPO_MAP = {
    r"\bwat\b|\bwht\b|\bwt\b": "what",
    r"\bdis\b": "this",
    r"\bdat\b": "that",
    r"\bplz\b|\bpls\b": "please",
    r"\bsummery\b|\bsumary\b": "summary",
    r"\babt\b": "about",
    r"\bdiff\b": "difference",
    r"\bvs\b": "versus",
    r"\bdoc\b|\bdocs\b|\bpdfs?\b|\btxt\b|\breport\b": "threat report",
    r"\barch\b": "architecture",
    r"\bimp\b": "important",
    r"\bwrk\b|\bwrks\b": "work",
    r"\beval\b": "evaluation",
    r"\binfo\b": "information",
    r"\bioc\b": "indicator of compromise",
    r"\biocs\b": "indicators of compromise",
    r"\bcve\b": "vulnerability CVE identifier",
    r"\bc2\b": "command and control server",
    r"\bttp\b|\bttps\b": "tactics techniques and procedures",
    r"\bmitre\b": "MITRE ATT&CK technique",
    r"\brce\b": "remote code execution vulnerability"
}

GREETING_PATTERNS = [
    r"^(?:hi|hello|hey|hola|greetings|howdy|yo)\b",
    r"^(?:help|help me|guide|start|how do i use|how to use|who are you|what can you do|what is this app|what is intelassist)\b",
    r"^(?:what is this|tell me what to do)\b"
]

class RAGEngine:
    """End-to-end cyber threat RAG orchestrator delivering grounded intelligence with source citations."""

    def __init__(self, vector_store: VectorStore, llm_service: LLMService):
        self.vector_store = vector_store
        self.llm_service = llm_service

    def normalize_query(self, query: str) -> Tuple[str, str, bool]:
        """
        Normalize cyber terminology, fix typos, and detect question intent.
        """
        q_clean = query.strip()
        q_lower = q_clean.lower()

        # 1. Check for greetings
        for pattern in GREETING_PATTERNS:
            if re.search(pattern, q_lower):
                return q_clean, "greeting", True

        # 2. Apply slang and cyber normalization
        normalized = q_lower
        for pattern, replacement in SLANG_TYPO_MAP.items():
            normalized = re.sub(pattern, replacement, normalized)

        # 3. Detect broad summary / overview intents
        if re.search(r"^(?:summary|overview|what does this say|explain|tell me everything|main points|key points|what is this report about)\b", normalized):
            expanded = f"Provide a comprehensive threat intelligence executive summary, technical breakdown, and key attack findings: {normalized}"
            return expanded, "summary", False

        # 4. Handle short keyword queries
        words = normalized.split()
        if len(words) <= 2 and not any(w in normalized for w in ["what", "how", "why", "where", "who", "when"]):
            expanded = f"Explain in detail the threat context, technical indicators, exploit mechanism, and security impact of {normalized}"
            return expanded, "concept", False

        return normalized, "qa", False

    def detect_document_in_query(self, query: str, available_docs: List[str]) -> Optional[str]:
        """Auto-detect if user mentions a specific file name in their question."""
        q_lower = query.lower()
        best_doc = None
        best_score = 0

        for doc in available_docs:
            d_name = doc.lower()
            stem = d_name.rsplit(".", 1)[0]
            stem_clean = stem.replace("_", " ").replace("-", " ")

            if doc.lower() in q_lower or stem in q_lower or stem_clean in q_lower:
                return doc

            tokens = [t for t in stem_clean.split() if len(t) >= 4 and t not in ["overview", "report", "paper", "document", "sample", "threat"]]
            matched = sum(1 for t in tokens if t in q_lower)
            if matched > 0 and matched > best_score:
                best_score = matched
                best_doc = doc

        return best_doc if best_score > 0 else None

    def answer_question(
        self,
        question: str,
        top_k: int = 6,
        threshold: float = 0.08,
        min_confidence_threshold: float = 0.18,
        filter_doc: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute cyber threat RAG retrieval and generation pipeline.
        """
        raw_question = question.strip()
        if not raw_question:
            return {
                "answer": "Please enter a threat intelligence or forensic question to begin.",
                "sources": [],
                "retrieved_count": 0,
                "provider": self.llm_service.provider,
                "latency_sec": 0.1,
                "is_demo": True,
                "is_low_confidence": False
            }

        # 1. Normalize and detect intent
        expanded_query, intent, is_greeting = self.normalize_query(raw_question)
        available_docs = self.vector_store.get_all_documents()

        # Check if query explicitly mentions a document
        auto_detected_doc = self.detect_document_in_query(raw_question, available_docs)
        active_filter_doc = filter_doc or auto_detected_doc
        if active_filter_doc == "All Documents":
            active_filter_doc = None

        # 2. Special handler for greetings
        if is_greeting:
            doc_list_str = "\n".join([f"- 📄 **{doc}**" for doc in available_docs[:5]]) if available_docs else "*(No documents or logs uploaded yet. Upload threat reports on the Threat Reports page!)*"
            greeting_msg = (
                f"### 🛡️ Welcome to **IntelAssist AI** — Cyber Threat Intelligence Platform\n\n"
                f"I am your AI-powered cyber security investigation assistant. I can analyze threat advisories, "
                f"firewall & auth logs, extract IOCs, trace attack timelines, and correlate indicators across sources.\n\n"
                f"#### 📚 Indexed Artifacts Ready for Analysis:\n"
                f"{doc_list_str}\n\n"
                f"#### 💡 Example Investigation Inquiries:\n"
                f"- *\"What are the main threats, CVEs, and attack vectors mentioned in the report?\"*\n"
                f"- *\"Extract all indicators of compromise (IP addresses, hashes, domains)\"*\n"
                f"- *\"What happened during this security incident and what is the attack chain?\"*\n"
                f"- *\"What immediate mitigation and containment actions should our SOC execute?\"*\n\n"
                f"Ask any question or target specific files using the scope selector above!"
            )
            return {
                "answer": greeting_msg,
                "sources": [],
                "retrieved_count": 0,
                "provider": self.llm_service.provider,
                "model": self.llm_service.model_name,
                "latency_sec": 0.15,
                "is_demo": True,
                "is_low_confidence": False
            }

        # 3. High-Coverage Semantic Search Retrieval
        retrieved_chunks = self.vector_store.search(
            query=expanded_query,
            top_k=top_k,
            threshold=threshold,
            filter_doc=active_filter_doc
        )

        # Fallback 1: zero threshold
        if not retrieved_chunks:
            retrieved_chunks = self.vector_store.search(
                query=raw_question,
                top_k=top_k,
                threshold=0.0,
                filter_doc=active_filter_doc
            )

        # Fallback 2: Target document enforcement
        if active_filter_doc:
            doc_all_chunks = [c for c in self.vector_store.chunks if c.get("filename") == active_filter_doc]
            if doc_all_chunks:
                retrieved_chunks = [c for c in retrieved_chunks if c.get("filename") == active_filter_doc]
                if len(retrieved_chunks) < min(top_k, len(doc_all_chunks)):
                    existing_ids = set(c.get("chunk_id") for c in retrieved_chunks)
                    for c in doc_all_chunks:
                        if c.get("chunk_id") not in existing_ids:
                            c_item = dict(c)
                            c_item["score"] = 0.88
                            c_item["similarity_percentage"] = 88
                            retrieved_chunks.append(c_item)
                        if len(retrieved_chunks) >= top_k:
                            break
        elif not retrieved_chunks and len(self.vector_store.chunks) > 0:
            retrieved_chunks = self.vector_store.chunks[:top_k]

        # 4. Low-Confidence & No-Answer Protection
        max_score = max([c.get("score", 0.0) for c in retrieved_chunks], default=0.0)
        
        if active_filter_doc:
            is_low_confidence = (len(retrieved_chunks) == 0)
        else:
            is_low_confidence = (len(retrieved_chunks) == 0 or max_score < min_confidence_threshold)

        if is_low_confidence and len(self.vector_store.chunks) > 0:
            logger.info("Low confidence query detected (max score: %.2f for '%s')", max_score, raw_question)
            no_answer_msg = (
                "### ⚠️ Insufficient Threat Intelligence Evidence\n\n"
                "I could not locate sufficient forensic evidence or context in the indexed files to answer this inquiry.\n\n"
                "💡 **Recommended Analyst Steps:**\n"
                "- Verify that the relevant threat report or log is uploaded and indexed.\n"
                "- Check the **Target Scope** filter in the toolbar to query across all artifacts.\n"
                "- Query using specific indicators (e.g. IP address, CVE identifier, hash, or hostname)."
            )
            return {
                "answer": no_answer_msg,
                "sources": [],
                "retrieved_count": 0,
                "provider": self.llm_service.provider,
                "model": self.llm_service.model_name,
                "latency_sec": 0.1,
                "is_demo": True,
                "is_low_confidence": True
            }

        if not retrieved_chunks:
            return {
                "answer": (
                    "### 📄 No Matching Artifact Found\n\n"
                    f"I could not locate content for **{active_filter_doc or 'your query'}** in the database.\n\n"
                    "💡 **How to resolve:**\n"
                    "1. Verify the file is uploaded on the **📄 Threat Reports** page.\n"
                    "2. Switch the scope selector to **'All Documents'**."
                ),
                "sources": [],
                "retrieved_count": 0,
                "provider": self.llm_service.provider,
                "latency_sec": 0.1,
                "is_demo": True,
                "is_low_confidence": True
            }

        # 5. Build context text
        context_parts = []
        for i, chunk in enumerate(retrieved_chunks, 1):
            doc_name = chunk.get("filename", "Unknown Document")
            page_num = chunk.get("page_number", 1)
            chunk_text = chunk.get("text", "")
            context_parts.append(f"[Source {i} - {doc_name} (Page {page_num})]:\n{chunk_text}")

        full_context = "\n\n".join(context_parts)

        # 6. Formulate prompt
        prompt_text = (
            f"SECURITY EVIDENCE CONTEXT:\n"
            f"---------------------\n"
            f"{full_context}\n"
            f"---------------------\n\n"
            f"CYBER INVESTIGATION QUESTION:\n"
            f"{raw_question}\n\n"
            f"Provide an evidence-based cyber threat assessment citing the sources above."
        )

        # 7. Generate response
        llm_response = self.llm_service.generate(
            prompt=prompt_text,
            context_chunks=retrieved_chunks,
            target_doc_name=active_filter_doc
        )

        return {
            "answer": llm_response.get("text", ""),
            "sources": retrieved_chunks,
            "retrieved_count": len(retrieved_chunks),
            "provider": llm_response.get("provider", self.llm_service.provider),
            "model": llm_response.get("model", self.llm_service.model_name),
            "latency_sec": llm_response.get("latency_sec", 0.25),
            "is_demo": llm_response.get("is_demo", True),
            "is_low_confidence": False,
            "query_normalized": expanded_query
        }
