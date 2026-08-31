"""
Unit tests for RAGEngine using standard library unittest.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unittest
from services.rag_engine import RAGEngine
from services.vector_store import VectorStore
from services.llm_service import LLMService
from services.chunker import TextChunker
from services.document_processor import DocumentProcessor
from utils.sample_docs import generate_all_samples

class TestRAGEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.vector_store = VectorStore()
        cls.vector_store.clear()
        cls.llm_service = LLMService(provider="Demo Mode (Smart AI)")
        cls.rag_engine = RAGEngine(vector_store=cls.vector_store, llm_service=cls.llm_service)

        sample_files = generate_all_samples()
        chunker = TextChunker(chunk_size=500, chunk_overlap=100)
        all_chunks = []
        for sf in sample_files:
            with open(sf, "rb") as f:
                b = f.read()
            doc = DocumentProcessor.process_file(b, sf.name)
            all_chunks.extend(chunker.chunk_document(doc))
        cls.vector_store.add_documents(all_chunks)

    def test_query_normalization(self):
        expanded, intent, is_greeting = self.rag_engine.normalize_query("wat dis threat report say abt apt29")
        self.assertIn("what", expanded)
        self.assertIn("threat", expanded)
        self.assertFalse(is_greeting)

    def test_greeting_handling(self):
        res = self.rag_engine.answer_question("hello, how do I use this?")
        self.assertGreater(len(res["answer"]), 50)
        self.assertTrue("Hello" in res["answer"] or "Welcome" in res["answer"] or "IntelAssist" in res["answer"])
        self.assertEqual(res["retrieved_count"], 0)

    def test_standard_rag_answer(self):
        res = self.rag_engine.answer_question("What threats and CVEs were identified?")
        self.assertGreater(len(res["answer"]), 50)
        self.assertGreater(len(res["sources"]), 0)
        self.assertIn("filename", res["sources"][0])

    def test_strict_document_targeting(self):
        docs = self.vector_store.get_all_documents()
        target_doc = docs[0]
        res = self.rag_engine.answer_question("Summarize the main findings", filter_doc=target_doc)
        self.assertGreater(len(res["sources"]), 0)
        for src in res["sources"]:
            self.assertEqual(src["filename"], target_doc)

if __name__ == "__main__":
    unittest.main()
