"""
Vector Database engine for IntelliAssist AI.
Manages chunk storage, embedding indexing, cosine similarity search, duplicate detection, and persistence.
"""

import json
import os
import logging
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from utils.config import VECTOR_DB_DIR
from services.embeddings import EmbeddingService

logger = logging.getLogger(__name__)

class VectorStore:
    """In-memory & persistent Vector Database supporting high-speed cosine similarity retrieval."""

    def __init__(self, embedding_service: Optional[EmbeddingService] = None, db_dir: Path = VECTOR_DB_DIR):
        self.embedding_service = embedding_service or EmbeddingService()
        self.db_dir = Path(db_dir)
        self.chunks_file = self.db_dir / "chunks_metadata.json"
        self.vectors_file = self.db_dir / "vectors_index.npy"

        self.chunks: List[Dict[str, Any]] = []
        self.vectors: np.ndarray = np.empty((0, self.embedding_service.dense_dim), dtype=np.float32)

        self.load_from_disk()

    def add_documents(self, chunks: List[Dict[str, Any]]) -> int:
        """Add new chunks to the vector database and index their embeddings."""
        if not chunks:
            return 0

        # Extract texts to embed
        texts = [c.get("text", "") for c in chunks]
        new_vectors = self.embedding_service.embed_texts(texts)

        if len(self.chunks) == 0 or self.vectors.shape[0] == 0:
            self.chunks = list(chunks)
            self.vectors = new_vectors
        else:
            self.chunks.extend(chunks)
            self.vectors = np.vstack([self.vectors, new_vectors])

        self.save_to_disk()
        logger.info("Indexed %d new chunks into Vector Store (total: %d)", len(chunks), len(self.chunks))
        return len(chunks)

    def search(self, query: str, top_k: int = 4, threshold: float = 0.0, filter_doc: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Perform semantic search against indexed chunks using cosine similarity.
        Returns top-k matching chunks with similarity scores.
        """
        if len(self.chunks) == 0 or self.vectors.shape[0] == 0:
            return []

        # Embed the query
        q_vec = self.embedding_service.embed_query(query)
        q_norm = np.linalg.norm(q_vec)
        if q_norm < 1e-9:
            return []

        q_vec = q_vec / q_norm

        # Compute cosine similarity
        scores = np.dot(self.vectors, q_vec)

        # Keyword boost: Calculate keyword overlap bonus for precise entity matching
        query_words = set([w.lower() for w in query.split() if len(w) > 2])

        results = []
        for idx, score in enumerate(scores):
            chunk = self.chunks[idx]

            # Optional document filter
            if filter_doc and filter_doc != "All Documents" and chunk.get("filename") != filter_doc:
                continue

            chunk_text = chunk.get("text", "").lower()
            overlap_count = sum(1 for w in query_words if w in chunk_text)
            keyword_bonus = min(0.35, overlap_count * 0.07)

            final_score = float(score * 0.7 + keyword_bonus * 0.3)
            final_score = max(0.0, min(0.99, final_score))

            if final_score >= threshold:
                item = dict(chunk)
                item["score"] = final_score
                item["similarity_percentage"] = int(final_score * 100)
                results.append(item)

        # Sort descending by score
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:top_k]

    def get_all_documents(self) -> List[str]:
        """Return a sorted list of unique document filenames in the store."""
        docs = set(c.get("filename", "") for c in self.chunks if c.get("filename"))
        return sorted(list(docs))

    def get_indexed_file_hashes(self) -> Dict[str, str]:
        """Return mapping of file_hash -> filename for all indexed documents."""
        mapping = {}
        for c in self.chunks:
            f_hash = c.get("file_hash")
            f_name = c.get("filename")
            if f_hash and f_name and f_hash not in mapping:
                mapping[f_hash] = f_name
        return mapping

    def has_document_hash(self, file_hash: str) -> bool:
        """Check if a document with this SHA-256 hash is already indexed."""
        if not file_hash:
            return False
        return any(c.get("file_hash") == file_hash for c in self.chunks)

    def get_document_by_hash(self, file_hash: str) -> Optional[str]:
        """Retrieve the filename matching an existing file hash if indexed."""
        for c in self.chunks:
            if c.get("file_hash") == file_hash:
                return c.get("filename")
        return None

    def get_document_chunks(self, filename: str) -> List[Dict[str, Any]]:
        """Retrieve all chunks belonging to a specific document."""
        return [c for c in self.chunks if c.get("filename") == filename]

    def delete_document(self, filename: str) -> int:
        """Remove all chunks associated with a specific document and re-index."""
        if not filename:
            return 0

        keep_indices = [i for i, c in enumerate(self.chunks) if c.get("filename") != filename]
        removed_count = len(self.chunks) - len(keep_indices)

        if removed_count > 0:
            self.chunks = [self.chunks[i] for i in keep_indices]
            if len(keep_indices) > 0 and self.vectors.shape[0] > 0:
                self.vectors = self.vectors[keep_indices]
            else:
                self.vectors = np.empty((0, self.embedding_service.dense_dim), dtype=np.float32)
            self.save_to_disk()
            logger.info("Deleted document '%s' (removed %d chunks)", filename, removed_count)

        return removed_count

    def clear(self):
        """Clear all stored vectors and chunks."""
        self.chunks = []
        self.vectors = np.empty((0, self.embedding_service.dense_dim), dtype=np.float32)
        if self.chunks_file.exists():
            self.chunks_file.unlink()
        if self.vectors_file.exists():
            self.vectors_file.unlink()
        logger.info("Cleared VectorStore in-memory and on disk.")

    def save_to_disk(self):
        """Persist chunk metadata and vector array to disk."""
        try:
            self.db_dir.mkdir(parents=True, exist_ok=True)
            with open(self.chunks_file, "w", encoding="utf-8") as f:
                json.dump(self.chunks, f, indent=2, ensure_ascii=False)
            np.save(self.vectors_file, self.vectors)
        except Exception as e:
            logger.error("Failed to persist vector store to disk: %s", e)

    def load_from_disk(self):
        """Load indexed chunks and vectors from disk if available."""
        try:
            if self.chunks_file.exists() and self.vectors_file.exists():
                with open(self.chunks_file, "r", encoding="utf-8") as f:
                    self.chunks = json.load(f)
                self.vectors = np.load(self.vectors_file)
                logger.info("Loaded %d chunks from vector disk cache.", len(self.chunks))
        except Exception as e:
            logger.warning("Failed to load vector store from disk: %s", e)
            self.chunks = []
            self.vectors = np.empty((0, self.embedding_service.dense_dim), dtype=np.float32)

    @property
    def total_chunks(self) -> int:
        return len(self.chunks)

    @property
    def total_documents(self) -> int:
        return len(self.get_all_documents())
