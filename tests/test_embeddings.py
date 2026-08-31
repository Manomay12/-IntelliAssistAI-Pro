"""
Unit tests for EmbeddingService using standard library unittest.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unittest
import numpy as np
from services.embeddings import EmbeddingService

class TestEmbeddings(unittest.TestCase):

    def setUp(self):
        self.embedding_service = EmbeddingService()

    def test_embedding_dimensions(self):
        texts = [
            "What is the command and control server in cyber attacks?",
            "SSH brute force authentication telemetry."
        ]
        vectors = self.embedding_service.embed_texts(texts)
        self.assertIsInstance(vectors, np.ndarray)
        self.assertEqual(vectors.shape, (2, 384))
        self.assertEqual(vectors.dtype, np.float32)

    def test_embedding_normalization(self):
        texts = ["Cosine similarity retrieval in vector databases."]
        vectors = self.embedding_service.embed_texts(texts)
        norm = np.linalg.norm(vectors[0])
        self.assertAlmostEqual(norm, 1.0, places=4)

    def test_embed_query(self):
        query = "deep threat intelligence analysis"
        q_vec = self.embedding_service.embed_query(query)
        self.assertIsInstance(q_vec, np.ndarray)
        self.assertEqual(q_vec.shape, (384,))
        norm = np.linalg.norm(q_vec)
        self.assertAlmostEqual(norm, 1.0, places=4)

    def test_active_model_name(self):
        model_name = self.embedding_service.get_active_model_name()
        self.assertIsInstance(model_name, str)
        self.assertGreater(len(model_name), 0)

    def test_empty_input(self):
        empty_vecs = self.embedding_service.embed_texts([])
        self.assertEqual(empty_vecs.shape, (0, 384))
        
        empty_q = self.embedding_service.embed_query("")
        self.assertEqual(empty_q.shape, (384,))

if __name__ == "__main__":
    unittest.main()
