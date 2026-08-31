"""
Unit tests for TextChunker service.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unittest
from services.chunker import TextChunker

class TestChunker(unittest.TestCase):

    def test_split_short_text(self):
        chunker = TextChunker(chunk_size=300, chunk_overlap=50)
        text = "Short text for quick chunking verification."
        chunks = chunker.split_text(text)
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0], text)

    def test_split_long_text_with_overlap(self):
        chunker = TextChunker(chunk_size=100, chunk_overlap=20)
        text = (
            "First sentence explaining transformers. "
            "Second sentence discussing attention mechanism. "
            "Third sentence describing multi-head self-attention. "
            "Fourth sentence evaluating cross-attention in encoder-decoder."
        )
        chunks = chunker.split_text(text)
        self.assertGreater(len(chunks), 1)
        for c in chunks:
            self.assertLessEqual(len(c), 150)

    def test_chunk_document_structure(self):
        chunker = TextChunker(chunk_size=200, chunk_overlap=40)
        mock_doc = {
            "filename": "ai_research.pdf",
            "file_hash": "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
            "total_pages": 2,
            "pages": [
                {
                    "page_number": 1,
                    "total_pages": 2,
                    "text": "Page 1 contains introduction to neural network architecture and optimization."
                },
                {
                    "page_number": 2,
                    "total_pages": 2,
                    "text": "Page 2 presents empirical evaluation benchmarks and cross-validation accuracy."
                }
            ]
        }

        chunks = chunker.chunk_document(mock_doc)
        self.assertGreaterEqual(len(chunks), 2)
        self.assertEqual(chunks[0]["filename"], "ai_research.pdf")
        self.assertEqual(chunks[0]["file_hash"], mock_doc["file_hash"])
        self.assertEqual(chunks[0]["page_number"], 1)
        self.assertTrue(any(c["page_number"] == 2 for c in chunks))
        self.assertTrue(all("chunk_id" in c for c in chunks))

    def test_chunk_document_empty_fallback(self):
        chunker = TextChunker(chunk_size=200, chunk_overlap=40)
        mock_empty = {
            "filename": "blank.txt",
            "file_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "pages": [],
            "full_text": ""
        }
        chunks = chunker.chunk_document(mock_empty)
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0]["filename"], "blank.txt")

if __name__ == "__main__":
    unittest.main()
