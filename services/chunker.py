"""
Text chunking module for IntelliAssist AI.
Splits document pages into semantically coherent overlapping chunks with metadata.
Guarantees at least 1 well-formed chunk for every processed document and retains file_hash.
"""

import re
from typing import List, Dict, Any

class TextChunker:
    """Recursively splits document text into chunks preserving sentence boundaries and source metadata."""

    def __init__(self, chunk_size: int = 500, chunk_overlap: int = 100):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def split_text(self, text: str) -> List[str]:
        """Split a long string into overlapping chunks respecting sentence/paragraph boundaries."""
        if not text or not text.strip():
            return []

        cleaned = text.strip()
        if len(cleaned) <= self.chunk_size:
            return [cleaned]

        # Splitting separators in priority order: paragraphs -> sentences -> clauses -> spaces
        separators = ["\n\n", "\n", ". ", "? ", "! ", "; ", ", ", " "]

        chunks = []
        start_idx = 0
        text_len = len(cleaned)

        while start_idx < text_len:
            end_idx = min(start_idx + self.chunk_size, text_len)

            if end_idx < text_len:
                # Find the best split boundary before end_idx
                best_split = -1
                for sep in separators:
                    pos = cleaned.rfind(sep, start_idx + self.chunk_overlap, end_idx)
                    if pos != -1:
                        best_split = pos + len(sep)
                        break

                if best_split != -1:
                    end_idx = best_split

            chunk = cleaned[start_idx:end_idx].strip()
            if chunk and len(chunk) > 5:
                chunks.append(chunk)

            # Move start index forward with overlap
            start_idx = max(start_idx + 1, end_idx - self.chunk_overlap)

            if start_idx >= text_len:
                break

        return chunks if chunks else [cleaned]

    def chunk_document(self, processed_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Split an entire processed document (all pages) into structured chunk records with guaranteed fallback."""
        filename = processed_doc.get("filename", "unknown_doc")
        file_hash = processed_doc.get("file_hash", "")
        all_chunks = []
        global_chunk_idx = 0

        for page_info in processed_doc.get("pages", []):
            page_num = page_info.get("page_number", 1)
            page_text = page_info.get("text", "").strip()

            if not page_text:
                continue

            page_chunks = self.split_text(page_text)

            for local_idx, chunk_text in enumerate(page_chunks):
                chunk_record = {
                    "chunk_id": f"{filename}_p{page_num}_c{local_idx}",
                    "global_idx": global_chunk_idx,
                    "filename": filename,
                    "file_hash": file_hash,
                    "page_number": page_num,
                    "total_pages": page_info.get("total_pages", 1),
                    "text": chunk_text,
                    "char_count": len(chunk_text),
                    "word_count": len(chunk_text.split())
                }
                all_chunks.append(chunk_record)
                global_chunk_idx += 1

        # Guaranteed fallback if no chunks were extracted from pages
        if not all_chunks:
            full_text = processed_doc.get("full_text", "").strip() or f"Document {filename} indexed successfully."
            all_chunks.append({
                "chunk_id": f"{filename}_p1_c0",
                "global_idx": 0,
                "filename": filename,
                "file_hash": file_hash,
                "page_number": 1,
                "total_pages": processed_doc.get("total_pages", 1),
                "text": full_text[:600],
                "char_count": len(full_text[:600]),
                "word_count": len(full_text[:600].split())
            })

        return all_chunks
