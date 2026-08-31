"""
Document summarization, topic modeling, entity extraction, and cross-document comparison service for IntelliAssist AI.
"""

import re
import math
import logging
from typing import List, Dict, Any, Optional, Tuple
from collections import Counter
from services.llm_service import LLMService

logger = logging.getLogger(__name__)

class DocumentSummarizer:
    """Provides multi-mode document summarization, entity extraction, and cross-document comparative analysis."""

    def __init__(self, llm_service: LLMService):
        self.llm_service = llm_service

    def extract_key_topics(self, text: str, max_topics: int = 8) -> List[str]:
        """Extract dominant keywords and key phrases using frequency and stopword filtering."""
        if not text:
            return []

        stopwords = {
            "the", "and", "is", "in", "it", "of", "to", "for", "with", "on", "that", "this",
            "are", "was", "as", "by", "an", "be", "from", "at", "or", "which", "will", "from",
            "can", "has", "have", "been", "were", "their", "such", "other", "into", "more",
            "document", "page", "using", "also", "used", "than", "first", "based", "system",
            "study", "paper", "data", "these", "about", "could", "should", "would", "between",
            "each", "when", "where", "after", "before", "over", "under", "both", "some", "most"
        }

        words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
        bigrams = []
        for i in range(len(words) - 1):
            w1, w2 = words[i], words[i+1]
            if w1 not in stopwords and w2 not in stopwords:
                bigrams.append(f"{w1.title()} {w2.title()}")

        filtered_words = [w.title() for w in words if w not in stopwords and len(w) > 4]

        counts_bi = Counter(bigrams).most_common(max_topics // 2)
        counts_single = Counter(filtered_words).most_common(max_topics // 2)

        topics = [item[0] for item in counts_bi] + [item[0] for item in counts_single]
        unique_topics = []
        for t in topics:
            if t not in unique_topics:
                unique_topics.append(t)

        return unique_topics[:max_topics]

    def extract_entities(self, text: str) -> Dict[str, List[str]]:
        """Extract important entities (Technologies, Organizations, Metrics/Numbers, Dates/Years)."""
        entities = {
            "Technologies & Frameworks": [],
            "Organizations & Roles": [],
            "Metrics & Percentages": [],
            "Dates & Years": []
        }

        metrics = re.findall(r'\b(?:\d+(?:\.\d+)?%|\$\d+(?:\.\d+)?|\d+(?:\.\d+)?\s*(?:MB|GB|ms|seconds|accuracy|F1|BLEU|parameters|users|requests))\b', text, re.IGNORECASE)
        entities["Metrics & Percentages"] = list(set(metrics))[:6]

        years = re.findall(r'\b(?:19\d\d|20\d\d|January|February|March|April|May|June|July|August|September|October|November|December)\b', text)
        entities["Dates & Years"] = list(set(years))[:5]

        tech_keywords = [
            "Python", "PyTorch", "TensorFlow", "LangChain", "Streamlit", "Transformers", "BERT",
            "FAISS", "ChromaDB", "LLM", "GPT", "Gemini", "RAG", "Vector Database", "NLP", "API",
            "REST", "Docker", "SQL", "Deep Learning", "Machine Learning", "Attention Mechanism",
            "Cosine Similarity", "Neural Network", "CNN", "RNN", "Embedding", "Encoder", "Decoder",
            "Pandas", "Scikit-Learn", "FastAPI", "React", "Node.js", "Kubernetes", "AWS", "Azure"
        ]
        found_tech = [k for k in tech_keywords if re.search(r'\b' + re.escape(k) + r'\b', text, re.IGNORECASE)]
        entities["Technologies & Frameworks"] = found_tech[:8]

        org_keywords = [
            "Google", "OpenAI", "DeepMind", "Microsoft", "Meta", "Amazon", "IEEE", "Stanford",
            "MIT", "Hugging Face", "University", "Research Team", "Enterprise", "Developer", "Client",
            "Author", "Investigator", "Clinician", "Analyst"
        ]
        found_orgs = [k for k in org_keywords if re.search(r'\b' + re.escape(k) + r'\b', text, re.IGNORECASE)]
        entities["Organizations & Roles"] = found_orgs[:6]

        return entities

    def _generate_smart_local_summary(self, text: str, mode: str, doc_name: str) -> str:
        """
        Generate high-quality multi-mode structured summary locally
        using sentence centrality ranking and keyword extraction.
        """
        raw_sentences = re.split(r'(?<=[.?!])\s+', text)
        sentences = [s.strip().replace("\n", " ") for s in raw_sentences if len(s.strip()) > 25]

        if not sentences:
            return f"**Summary of {doc_name}**\n\nThe document contains minimal textual content."

        words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
        word_freq = Counter(words)

        scored_sentences = []
        for i, s in enumerate(sentences):
            s_words = re.findall(r'\b[a-zA-Z]{3,}\b', s.lower())
            if not s_words:
                continue
            score = sum(word_freq.get(w, 0) for w in s_words) / len(s_words)
            if i < 5:
                score *= 1.3
            scored_sentences.append((score, i, s))

        scored_sentences.sort(key=lambda x: x[0], reverse=True)
        top_sentences = [item[2] for item in scored_sentences[:8]]
        top_chrono = sorted(scored_sentences[:6], key=lambda x: x[1])
        top_chrono_sentences = [item[2] for item in top_chrono]

        topics = self.extract_key_topics(text, max_topics=5)
        topics_str = ", ".join(topics) if topics else "Document Analysis"

        if mode == "Quick Summary":
            lead = top_chrono_sentences[0] if top_chrono_sentences else sentences[0]
            second = top_chrono_sentences[1] if len(top_chrono_sentences) > 1 else ""
            return (
                f"### ⚡ Quick Summary: {doc_name}\n\n"
                f"{lead} {second}\n\n"
                f"**Key Focus Area:** Focuses primarily on {topics_str}."
            )
        elif mode == "Bullet Points":
            lines = [f"### 📌 Key Summary Points: {doc_name}\n"]
            for idx, s in enumerate(top_chrono_sentences[:5], 1):
                lines.append(f"- **Point {idx}**: {s}")
            return "\n".join(lines)
        elif mode == "Key Findings":
            lines = [
                f"### 🎯 Key Findings & Insights: {doc_name}\n",
                f"Based on automated NLP analysis of **{doc_name}**, the primary findings include:\n"
            ]
            for idx, s in enumerate(top_sentences[:4], 1):
                lines.append(f"{idx}. **Finding {idx}**: {s}")
            lines.append(f"\n> **Core Impact**: The findings highlight significant relevance in **{topics_str}**.")
            return "\n".join(lines)
        elif mode == "Executive Summary":
            lines = [
                f"### 📋 Executive Summary: {doc_name}\n",
                "#### 1. Strategic Overview",
                f"{top_chrono_sentences[0] if top_chrono_sentences else sentences[0]}\n",
                "#### 2. Key Observations & Findings"
            ]
            for s in top_chrono_sentences[1:4]:
                lines.append(f"- {s}")
            lines.extend([
                "\n#### 3. Scope & Implications",
                f"This document centers on **{topics_str}**, providing actionable context and technical depth for researchers and stakeholders."
            ])
            return "\n".join(lines)
        else:
            lines = [
                f"### 📑 Comprehensive Summary: {doc_name}\n",
                "#### 📖 Introduction & Background",
                f"{top_chrono_sentences[0] if top_chrono_sentences else sentences[0]}\n",
                "#### 🔍 Core Details & Methodology"
            ]
            for s in top_chrono_sentences[1:4]:
                lines.append(f"- {s}")
            if len(top_chrono_sentences) > 4:
                lines.extend([
                    "\n#### 💡 Conclusions & Practical Takeaways",
                    f"{top_chrono_sentences[4]}"
                ])
            return "\n".join(lines)

    def summarize(self, text: str, mode: str = "Detailed Summary", doc_name: str = "Document") -> Dict[str, Any]:
        """Generate structured summary based on selected mode."""
        if not text or not text.strip():
            return {
                "mode": mode,
                "doc_name": doc_name,
                "summary": f"Document '{doc_name}' contains no readable text to summarize.",
                "topics": [],
                "entities": {},
                "takeaways": [],
                "is_demo": True,
                "provider": "IntelliAssist Local Engine"
            }

        topics = self.extract_key_topics(text)
        entities = self.extract_entities(text)

        if self.llm_service.api_key and ("Gemini" in self.llm_service.provider or "OpenAI" in self.llm_service.provider):
            try:
                truncated_text = text[:6000]
                prompt = (
                    f"Please generate a structured '{mode}' for the document named '{doc_name}'.\n\n"
                    f"DOCUMENT CONTENT:\n{truncated_text}\n\n"
                    f"Format with clean markdown headings, bullet points, and key findings."
                )
                system_instruction = (
                    f"You are an expert document intelligence summarizer. Generate a {mode} summarizing the content clearly."
                )
                llm_resp = self.llm_service.generate(prompt=prompt, system_instruction=system_instruction)
                summary_text = llm_resp.get("text", "")
                is_demo = llm_resp.get("is_demo", False)
                provider = llm_resp.get("provider", "LLM")
            except Exception as e:
                logger.warning("LLM summarization failed (%s), using local fallback", e)
                summary_text = self._generate_smart_local_summary(text, mode, doc_name)
                is_demo = True
                provider = "IntelliAssist Smart NLP Engine (Demo Mode)"
        else:
            summary_text = self._generate_smart_local_summary(text, mode, doc_name)
            is_demo = True
            provider = "IntelliAssist Smart NLP Engine (Demo Mode)"

        sentences = [s.strip().replace("\n", " ") for s in re.split(r'(?<=[.?!])\s+', text) if len(s.strip()) > 35]
        takeaways = []
        for s in sentences:
            if any(w in s.lower() for w in ["conclude", "result", "achieve", "propose", "demonstrate", "show", "finding", "important", "improve", "significantly"]):
                takeaways.append(s)
            if len(takeaways) >= 4:
                break

        if len(takeaways) < 3 and len(sentences) >= 3:
            takeaways = sentences[:4]

        return {
            "mode": mode,
            "doc_name": doc_name,
            "summary": summary_text,
            "topics": topics,
            "entities": entities,
            "takeaways": takeaways,
            "is_demo": is_demo,
            "provider": provider
        }

    def compare_documents(
        self,
        doc_a_name: str,
        doc_a_text: str,
        doc_b_name: str,
        doc_b_text: str
    ) -> Dict[str, Any]:
        """
        Perform in-depth cross-document comparison between Document A and Document B.
        Generates structured comparative matrix (Markdown table) and synthesized evaluation.
        """
        topics_a = self.extract_key_topics(doc_a_text, max_topics=5)
        topics_b = self.extract_key_topics(doc_b_text, max_topics=5)
        entities_a = self.extract_entities(doc_a_text)
        entities_b = self.extract_entities(doc_b_text)

        # Build concise excerpt profiles
        sentences_a = [s.strip().replace("\n", " ") for s in re.split(r'(?<=[.?!])\s+', doc_a_text) if len(s.strip()) > 25]
        sentences_b = [s.strip().replace("\n", " ") for s in re.split(r'(?<=[.?!])\s+', doc_b_text) if len(s.strip()) > 25]

        lead_a = sentences_a[0] if sentences_a else "Overview of Document A"
        lead_b = sentences_b[0] if sentences_b else "Overview of Document B"
        method_a = sentences_a[1] if len(sentences_a) > 1 else "Empirical analysis"
        method_b = sentences_b[1] if len(sentences_b) > 1 else "Empirical analysis"
        metrics_a = ", ".join(entities_a.get("Metrics & Percentages", [])) or "Standard evaluation metrics"
        metrics_b = ", ".join(entities_b.get("Metrics & Percentages", [])) or "Standard evaluation metrics"
        tech_a = ", ".join(entities_a.get("Technologies & Frameworks", [])) or "NLP / AI Pipelines"
        tech_b = ", ".join(entities_b.get("Technologies & Frameworks", [])) or "NLP / AI Pipelines"

        # Construct Markdown Comparison Table
        comparison_table = (
            f"| Comparative Dimension | 📄 {doc_a_name} | 📄 {doc_b_name} |\n"
            f"| :--- | :--- | :--- |\n"
            f"| **Primary Topic & Domain** | {', '.join(topics_a)} | {', '.join(topics_b)} |\n"
            f"| **Core Objective** | {lead_a[:140]}... | {lead_b[:140]}... |\n"
            f"| **Methodology & Architecture** | {method_a[:140]}... | {method_b[:140]}... |\n"
            f"| **Technologies & Frameworks** | {tech_a} | {tech_b} |\n"
            f"| **Key Metrics / Benchmarks** | {metrics_a} | {metrics_b} |\n"
            f"| **Document Length** | {len(doc_a_text.split()):,} words | {len(doc_b_text.split()):,} words |\n"
        )

        # Executive Comparative Synthesis
        executive_synthesis = (
            f"### ⚖️ Executive Cross-Document Comparison\n\n"
            f"#### 1. Strategic Thematic Contrast\n"
            f"- **{doc_a_name}** centers around **{', '.join(topics_a[:3])}**, emphasizing {lead_a[:120]}.\n"
            f"- **{doc_b_name}** focuses on **{', '.join(topics_b[:3])}**, presenting {lead_b[:120]}.\n\n"
            f"#### 2. Methodological & Technological Alignment\n"
            f"- **Technologies in {doc_a_name}**: `{tech_a}`\n"
            f"- **Technologies in {doc_b_name}**: `{tech_b}`\n\n"
            f"#### 3. Synergy & Research Takeaways\n"
            f"Comparing both documents reveals complementary perspectives: while **{doc_a_name}** addresses core foundational mechanics, "
            f"**{doc_b_name}** provides experimental depth and application benchmarks. Cross-referencing both creates a unified intelligence baseline."
        )

        # If LLM key is present, enhance synthesis
        if self.llm_service.api_key and ("Gemini" in self.llm_service.provider or "OpenAI" in self.llm_service.provider):
            try:
                prompt = (
                    f"Perform a professional academic comparison between Document A ('{doc_a_name}') and Document B ('{doc_b_name}').\n\n"
                    f"DOCUMENT A EXCERPT:\n{doc_a_text[:3000]}\n\n"
                    f"DOCUMENT B EXCERPT:\n{doc_b_text[:3000]}\n\n"
                    f"Generate a side-by-side comparison table and executive synthesis explaining similarities, differences, and key takeaways."
                )
                system_instruction = "You are an expert document intelligence researcher. Compare two documents thoroughly with clear markdown tables and synthesis."
                llm_resp = self.llm_service.generate(prompt=prompt, system_instruction=system_instruction)
                if len(llm_resp.get("text", "")) > 100:
                    executive_synthesis = llm_resp.get("text", "")
            except Exception as e:
                logger.warning("LLM comparison synthesis failed (%s), using deterministic matrix", e)

        full_report = f"# Comparative Analysis: {doc_a_name} vs {doc_b_name}\n\n## Summary Comparison Matrix\n\n{comparison_table}\n\n{executive_synthesis}"

        return {
            "doc_a": doc_a_name,
            "doc_b": doc_b_name,
            "topics_a": topics_a,
            "topics_b": topics_b,
            "comparison_table": comparison_table,
            "executive_synthesis": executive_synthesis,
            "full_report": full_report
        }
