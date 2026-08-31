"""
Unit tests for SentimentIntentAnalyzer using standard library unittest.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unittest
from services.sentiment_analyzer import SentimentIntentAnalyzer

class TestSentiment(unittest.TestCase):

    def setUp(self):
        self.sentiment_analyzer = SentimentIntentAnalyzer()

    def test_positive_sentiment(self):
        text = "The proposed algorithm achieved state-of-the-art results with remarkable precision and efficiency."
        res = self.sentiment_analyzer.analyze_sentiment(text)
        self.assertEqual(res["label"], "Positive")
        self.assertGreater(res["score"], 0)
        self.assertGreaterEqual(res["confidence"], 50)

    def test_negative_sentiment(self):
        text = "The model suffered from catastrophic failure, high latency, poor convergence, and frequent errors."
        res = self.sentiment_analyzer.analyze_sentiment(text)
        self.assertEqual(res["label"], "Negative")
        self.assertLess(res["score"], 0)

    def test_intent_detection(self):
        question_query = "What are the empirical benchmarks on the GLUE dataset?"
        intent_q = self.sentiment_analyzer.analyze_intent(question_query)
        self.assertIn(intent_q["primary_intent"], ["Question", "Informational"])

        request_query = "Please generate an executive brief for the leadership team."
        intent_r = self.sentiment_analyzer.analyze_intent(request_query)
        self.assertIn(intent_r["primary_intent"], ["Request", "Informational"])

    def test_chunk_trends(self):
        chunks = [
            {"chunk_id": "c1", "text": "Great introductory overview with strong results."},
            {"chunk_id": "c2", "text": "However, limitations and latency bottlenecks were observed."},
            {"chunk_id": "c3", "text": "Overall, the system provides significant advancements."}
        ]
        trends = self.sentiment_analyzer.analyze_chunk_trends(chunks)
        self.assertEqual(len(trends), 3)
        self.assertTrue(all("chunk_id" in t for t in trends))
        self.assertTrue(all("score" in t for t in trends))

if __name__ == "__main__":
    unittest.main()
