"""
Sentiment and Intent Analysis service for IntelliAssist AI.
Calculates sentiment polarity, classifies user/document intent, and maps sentiment trends across chunks.
"""

import re
from typing import List, Dict, Any, Tuple

class SentimentIntentAnalyzer:
    """Performs rule-based & lexicon-enhanced sentiment scoring and multi-class intent classification."""

    POSITIVE_WORDS = {
        "good", "great", "excellent", "positive", "superior", "advantage", "benefit", "improved",
        "effective", "efficient", "optimal", "success", "innovative", "accurate", "reliable",
        "robust", "state-of-the-art", "promising", "breakthrough", "outstanding", "valuable",
        "enhance", "boost", "gain", "fast", "powerful", "clean", "easy", "satisfied",
        "precision", "remarkable", "exceptional", "impressive", "significant", "advance", "advancements"
    }

    NEGATIVE_WORDS = {
        "bad", "poor", "error", "failure", "flaw", "issue", "problem", "defect", "limitation",
        "drawback", "bottleneck", "inefficient", "slow", "vulnerable", "bug", "risk", "damage",
        "decline", "drop", "loss", "struggle", "difficult", "expensive", "outdated", "weakness",
        "catastrophic"
    }

    def analyze_sentiment(self, text: str) -> Dict[str, Any]:
        """Calculate sentiment polarity, label (Positive, Neutral, Negative), and confidence."""
        if not text or not text.strip():
            return {
                "label": "Neutral",
                "score": 0.0,
                "confidence": 50,
                "positive_score": 0.33,
                "neutral_score": 0.34,
                "negative_score": 0.33,
                "dominant_color": "#64748b"
            }

        words = re.findall(r'\b[a-zA-Z-]+\b', text.lower())
        if not words:
            return {"label": "Neutral", "score": 0.0, "confidence": 50, "positive_score": 0.33, "neutral_score": 0.34, "negative_score": 0.33, "dominant_color": "#64748b"}

        pos_count = sum(1 for w in words if w in self.POSITIVE_WORDS)
        neg_count = sum(1 for w in words if w in self.NEGATIVE_WORDS)
        total_matched = pos_count + neg_count

        if total_matched == 0:
            return {
                "label": "Neutral",
                "score": 0.05,
                "confidence": 75,
                "positive_score": 0.25,
                "neutral_score": 0.60,
                "negative_score": 0.15,
                "dominant_color": "#3b82f6"
            }

        polarity = (pos_count - neg_count) / max(1, total_matched)

        pos_score = round(max(0.05, (pos_count + 1) / (total_matched + 3)), 2)
        neg_score = round(max(0.05, (neg_count + 1) / (total_matched + 3)), 2)
        neu_score = round(max(0.1, 1.0 - (pos_score + neg_score)), 2)

        if polarity > 0.15:
            label = "Positive"
            confidence = int(min(98, max(65, pos_score * 100 + 20)))
            color = "#10b981"
        elif polarity < -0.15:
            label = "Negative"
            confidence = int(min(98, max(65, neg_score * 100 + 20)))
            color = "#ef4444"
        else:
            label = "Neutral"
            confidence = int(min(95, max(60, neu_score * 100 + 20)))
            color = "#3b82f6"

        return {
            "label": label,
            "score": round(polarity, 2),
            "confidence": confidence,
            "positive_score": pos_score,
            "neutral_score": neu_score,
            "negative_score": neg_score,
            "dominant_color": color
        }

    def analyze_intent(self, text: str) -> Dict[str, Any]:
        """
        Classify intent into:
        - Informational
        - Question
        - Request
        - Complaint
        - Opinion
        - Technical / Methodology
        """
        text_clean = text.lower().strip()

        scores = {
            "Question": 0.05,
            "Informational": 0.20,
            "Request": 0.05,
            "Opinion": 0.05,
            "Complaint": 0.05,
            "Technical": 0.15
        }

        if "?" in text or any(text_clean.startswith(w) for w in ["what", "how", "why", "where", "who", "when", "which", "can", "is", "are", "does"]):
            scores["Question"] += 0.70

        if any(w in text_clean for w in ["please", "generate", "summarize", "extract", "find", "show me", "give me", "list", "provide"]):
            scores["Request"] += 0.65

        if any(w in text_clean for w in ["wrong", "error", "fail", "bad", "issue", "bug", "terrible", "problem", "broken", "unhappy", "catastrophic"]):
            scores["Complaint"] += 0.60

        if any(w in text_clean for w in ["i think", "i believe", "in my opinion", "seems like", "feel like", "prefer", "recommend"]):
            scores["Opinion"] += 0.55

        if any(w in text_clean for w in ["algorithm", "architecture", "dataset", "accuracy", "model", "pipeline", "framework", "vector"]):
            scores["Technical"] += 0.50

        total = sum(scores.values())
        normalized = {k: round((v / total) * 100, 1) for k, v in scores.items()}
        primary_intent = max(normalized.items(), key=lambda x: x[1])

        return {
            "primary_intent": primary_intent[0],
            "confidence": primary_intent[1],
            "all_intents": normalized
        }

    def analyze_chunk_trends(self, chunks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Calculate sentiment trajectory over sequential document chunks."""
        trend_data = []
        for i, chunk in enumerate(chunks):
            sent = self.analyze_sentiment(chunk.get("text", ""))
            trend_data.append({
                "chunk_id": chunk.get("chunk_id", f"chunk_{i+1}"),
                "chunk_index": i + 1,
                "chunk_label": f"Chunk {i+1} (p.{chunk.get('page_number', 1)})",
                "score": sent["score"],
                "polarity": sent["score"],
                "label": sent["label"],
                "confidence": sent["confidence"],
                "color": sent["dominant_color"]
            })
        return trend_data
