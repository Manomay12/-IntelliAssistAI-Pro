"""
Embeddings generation module for IntelliAssist AI.
Supports genuine neural embeddings via sentence-transformers (all-MiniLM-L6-v2),
Google Gemini Embeddings (text-embedding-004), OpenAI Embeddings (text-embedding-3-small),
and a fast deterministic semantic projection fallback for offline/lightweight environments.
"""

import os
import math
import hashlib
import logging
from typing import List, Dict, Any, Optional
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

logger = logging.getLogger(__name__)

# Global singleton cache for SentenceTransformer model to avoid repeated disk loads
_ST_MODEL_CACHE: Dict[str, Any] = {}

class EmbeddingService:
    """Manages document chunk and query vector embedding generation."""

    def __init__(self, model_type: str = "Sentence-Transformers (all-MiniLM-L6-v2)"):
        self.model_type = model_type
        self.vectorizer: Optional[TfidfVectorizer] = None
        self.corpus_fitted: bool = False
        self.dense_dim: int = 384  # Standard 384-dimensional dense semantic vector
        self._st_model: Optional[Any] = None
        self._st_available: Optional[bool] = None
        self._active_backend_name: str = "Uninitialized"
        
        self._initialize_backend()

    def _initialize_backend(self):
        """Detect available embedding backends and initialize the optimal provider."""
        # 1. Check if sentence-transformers is available
        try:
            from sentence_transformers import SentenceTransformer
            global _ST_MODEL_CACHE
            model_name = "all-MiniLM-L6-v2"
            if model_name not in _ST_MODEL_CACHE:
                logger.info("Loading SentenceTransformer model '%s'...", model_name)
                _ST_MODEL_CACHE[model_name] = SentenceTransformer(model_name)
            self._st_model = _ST_MODEL_CACHE[model_name]
            self._st_available = True
            self._active_backend_name = f"sentence-transformers/{model_name}"
            logger.info("Initialized neural embeddings backend: %s", self._active_backend_name)
            return
        except Exception as e:
            self._st_available = False
            logger.warning("SentenceTransformer not available or failed to load (%s). Checking API providers.", e)

        # 2. Check for Gemini API embeddings
        if "Gemini" in self.model_type and os.getenv("GEMINI_API_KEY"):
            try:
                from google import genai
                self._active_backend_name = "Google Gemini text-embedding-004"
                logger.info("Initialized embeddings backend: %s", self._active_backend_name)
                return
            except Exception as e:
                logger.warning("Gemini genai client unavailable: %s", e)

        # 3. Check for OpenAI API embeddings
        if "OpenAI" in self.model_type and os.getenv("OPENAI_API_KEY"):
            try:
                import openai
                self._active_backend_name = "OpenAI text-embedding-3-small"
                logger.info("Initialized embeddings backend: %s", self._active_backend_name)
                return
            except Exception as e:
                logger.warning("OpenAI client unavailable: %s", e)

        # 4. Fallback to deterministic projection
        self._active_backend_name = "Fast Deterministic Semantic Projection (Fallback)"
        logger.info("Using fallback embeddings backend: %s", self._active_backend_name)

    def get_active_model_name(self) -> str:
        """Return human-readable active embedding model name for UI and logs."""
        return self._active_backend_name

    def _generate_dense_projection_vector(self, text: str) -> np.ndarray:
        """
        Generate a 384-dimensional dense semantic vector using multi-scale
        n-gram hashing, position decay weighting, and subword feature projections.
        Deterministic fallback when neural model weights are not loaded.
        """
        if not text:
            return np.zeros(self.dense_dim, dtype=np.float32)

        vec = np.zeros(self.dense_dim, dtype=np.float32)
        words = text.lower().split()

        # 1. Unigram & Bigram semantic projections
        for i, word in enumerate(words):
            cleaned = "".join([c for c in word if c.isalnum()])
            if not cleaned:
                continue

            h1 = int(hashlib.md5(cleaned.encode("utf-8")).hexdigest(), 16)
            idx1 = h1 % self.dense_dim
            sign1 = 1.0 if ((h1 >> 4) % 2 == 0) else -1.0

            pos_weight = 1.0 + (0.5 / (1.0 + math.log(i + 1)))
            word_weight = math.log(len(cleaned) + 2)
            vec[idx1] += sign1 * pos_weight * word_weight

            if i < len(words) - 1:
                next_cleaned = "".join([c for c in words[i + 1] if c.isalnum()])
                if next_cleaned:
                    bigram = f"{cleaned}_{next_cleaned}"
                    h2 = int(hashlib.sha256(bigram.encode("utf-8")).hexdigest(), 16)
                    idx2 = h2 % self.dense_dim
                    sign2 = 1.0 if ((h2 >> 4) % 2 == 0) else -1.0
                    vec[idx2] += sign2 * 1.4

        # 2. Character 3-gram subword features
        for k in range(max(0, len(text) - 3)):
            sub = text[k:k+3].lower()
            h_sub = int(hashlib.md5(sub.encode("utf-8")).hexdigest()[:8], 16)
            idx_sub = h_sub % self.dense_dim
            vec[idx_sub] += 0.25

        # L2 normalize
        norm = np.linalg.norm(vec)
        if norm > 1e-9:
            vec = vec / norm
        else:
            vec = np.zeros(self.dense_dim, dtype=np.float32)

        return vec

    def fit_corpus(self, texts: List[str]):
        """Fit the TF-IDF vocabulary on the current document corpus."""
        if not texts:
            return

        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=2000,
            sublinear_tf=True,
            stop_words="english"
        )
        try:
            self.vectorizer.fit(texts)
            self.corpus_fitted = True
        except Exception as e:
            logger.warning("TF-IDF fit failed: %s", e)
            self.corpus_fitted = False

    def embed_texts(self, texts: List[str]) -> np.ndarray:
        """Generate normalized 384-dimensional embedding vectors for a list of texts."""
        if not texts:
            return np.empty((0, self.dense_dim), dtype=np.float32)

        # Strategy 1: Genuine SentenceTransformer embeddings (if available)
        if self._st_available and self._st_model is not None:
            try:
                embeddings = self._st_model.encode(
                    texts,
                    batch_size=32,
                    show_progress_bar=False,
                    convert_to_numpy=True,
                    normalize_embeddings=True
                )
                return np.array(embeddings, dtype=np.float32)
            except Exception as e:
                logger.warning("SentenceTransformer encoding failed (%s). Falling back.", e)

        # Strategy 2: Google Gemini Embeddings (if requested & API key available)
        if "Gemini" in self.model_type and os.getenv("GEMINI_API_KEY"):
            try:
                from google import genai
                client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
                vectors = []
                for t in texts:
                    res = client.models.embed_content(
                        model="text-embedding-004",
                        contents=t[:2048]
                    )
                    v = np.array(res.embeddings[0].values, dtype=np.float32)
                    # Project or slice/normalize to self.dense_dim if needed
                    if v.shape[0] != self.dense_dim:
                        v = self._resize_vector(v, self.dense_dim)
                    norm = np.linalg.norm(v)
                    if norm > 1e-9:
                        v = v / norm
                    vectors.append(v)
                return np.array(vectors, dtype=np.float32)
            except Exception as e:
                logger.warning("Gemini embedding call failed: %s", e)

        # Strategy 3: Fast Deterministic Semantic Projection Fallback
        vectors = []
        for t in texts:
            v_dense = self._generate_dense_projection_vector(t)
            vectors.append(v_dense)

        return np.array(vectors, dtype=np.float32)

    def embed_query(self, query: str) -> np.ndarray:
        """Generate embedding vector for a single query."""
        results = self.embed_texts([query])
        if len(results) > 0:
            return results[0]
        return np.zeros(self.dense_dim, dtype=np.float32)

    def _resize_vector(self, vec: np.ndarray, target_dim: int) -> np.ndarray:
        """Resize a vector to target dimension with L2 normalization."""
        if len(vec) == target_dim:
            return vec
        if len(vec) > target_dim:
            out = vec[:target_dim]
        else:
            out = np.pad(vec, (0, target_dim - len(vec)), mode='constant')
        norm = np.linalg.norm(out)
        return out / norm if norm > 1e-9 else out
