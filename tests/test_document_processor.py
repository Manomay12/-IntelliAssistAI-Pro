"""
Unit tests for DocumentProcessor service using standard library unittest.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unittest
from services.document_processor import DocumentProcessor
from utils.sample_docs import generate_all_samples

class TestDocumentProcessor(unittest.TestCase):

    def test_compute_file_hash(self):
        data1 = b"IntelAssist AI Document Content"
        data2 = b"IntelAssist AI Document Content"
        data3 = b"Different Document Content"

        hash1 = DocumentProcessor.compute_file_hash(data1)
        hash2 = DocumentProcessor.compute_file_hash(data2)
        hash3 = DocumentProcessor.compute_file_hash(data3)

        self.assertEqual(len(hash1), 64)
        self.assertEqual(hash1, hash2)
        self.assertNotEqual(hash1, hash3)

    def test_clean_text(self):
        raw = "  Hello \r\n\r\n World! \u00a0\u200b  This  is   a   test. \x00\x01\x02 "
        cleaned = DocumentProcessor.clean_text(raw)
        self.assertIn("Hello", cleaned)
        self.assertIn("World!", cleaned)
        self.assertNotIn("  ", cleaned)
        self.assertNotIn("\x00", cleaned)
        self.assertTrue(cleaned.startswith("Hello"))

    def test_process_text_file(self):
        text_content = "IntelAssist AI is a major platform for cyber threat intelligence.\nIt uses vector embeddings and RAG."
        bytes_data = text_content.encode("utf-8")
        
        doc_info = DocumentProcessor.process_file(bytes_data, "research_notes.txt")
        
        self.assertEqual(doc_info["filename"], "research_notes.txt")
        self.assertEqual(doc_info["file_ext"], ".txt")
        self.assertEqual(doc_info["file_size"], len(bytes_data))
        self.assertGreater(doc_info["total_words"], 5)
        self.assertGreaterEqual(len(doc_info["pages"]), 1)
        self.assertIn("IntelAssist AI", doc_info["full_text"])
        self.assertTrue(doc_info["is_valid"])

    def test_process_empty_file(self):
        doc_info = DocumentProcessor.process_file(b"", "empty_doc.txt")
        self.assertEqual(doc_info["file_size"], 0)
        self.assertIsNotNone(doc_info["warning"])

    def test_process_corrupt_docx(self):
        corrupt_bytes = b"PK\x03\x04NOT_A_VALID_DOCX_STREAM_CORRUPTED"
        doc_info = DocumentProcessor.process_file(corrupt_bytes, "corrupted.docx")
        self.assertEqual(doc_info["filename"], "corrupted.docx")
        self.assertIsNotNone(doc_info["warning"])

    def test_process_sample_documents(self):
        sample_documents = generate_all_samples()
        for sf in sample_documents:
            with open(sf, "rb") as f:
                bytes_data = f.read()
            doc_info = DocumentProcessor.process_file(bytes_data, sf.name)
            self.assertGreater(doc_info["total_chars"], 100)
            self.assertGreater(doc_info["total_words"], 20)
            self.assertGreaterEqual(doc_info["total_pages"], 1)
            self.assertEqual(len(doc_info["file_hash"]), 64)

if __name__ == "__main__":
    unittest.main()
