"""
Unit tests for VectorStore using standard library unittest.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unittest
import tempfile
from services.vector_store import VectorStore
from services.embeddings import EmbeddingService

class TestVectorStore(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name)
        self.embedding_service = EmbeddingService()
        self.store = VectorStore(embedding_service=self.embedding_service, db_dir=self.db_path)
        self.store.clear()

        self.sample_chunks = [
            {
                "chunk_id": "c1",
                "filename": "apt29_advisory.pdf",
                "file_hash": "a1b2c3d4",
                "page_number": 1,
                "text": "APT29 leverages WinRAR vulnerability CVE-2023-38831 and C2 185.220.101.5."
            },
            {
                "chunk_id": "c2",
                "filename": "ir_forensics.docx",
                "file_hash": "e5f6g7h8",
                "page_number": 1,
                "text": "Incident Response forensics on SSH brute force attacks and privilege escalation."
            }
        ]

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_add_and_search_documents(self):
        added = self.store.add_documents(self.sample_chunks)
        self.assertEqual(added, len(self.sample_chunks))
        self.assertEqual(self.store.total_chunks, len(self.sample_chunks))

        results = self.store.search("WinRAR vulnerability", top_k=3)
        self.assertGreater(len(results), 0)
        self.assertIn("score", results[0])

    def test_document_scoping_filter(self):
        self.store.add_documents(self.sample_chunks)
        filtered = self.store.search("vulnerability", top_k=5, filter_doc="apt29_advisory.pdf")
        for r in filtered:
            self.assertEqual(r["filename"], "apt29_advisory.pdf")

    def test_delete_document(self):
        self.store.add_documents(self.sample_chunks)
        initial_chunks = self.store.total_chunks
        removed = self.store.delete_document("apt29_advisory.pdf")
        self.assertEqual(removed, 1)
        self.assertEqual(self.store.total_chunks, initial_chunks - 1)
        self.assertNotIn("apt29_advisory.pdf", self.store.get_all_documents())

    def test_save_and_load_from_disk(self):
        self.store.add_documents(self.sample_chunks)
        store2 = VectorStore(embedding_service=self.embedding_service, db_dir=self.db_path)
        self.assertEqual(store2.total_chunks, len(self.sample_chunks))
        self.assertEqual(store2.get_all_documents(), self.store.get_all_documents())

if __name__ == "__main__":
    unittest.main()
