"""
Document processor module for IntelliAssist AI.
Extracts raw text, cleans formatting, and records page metadata from PDF, DOCX, TXT, MD, CSV, and code files.
Includes robust multi-strategy text extraction, SHA-256 hashing, corrupt file protection, and scanned-PDF detection.
"""

import io
import os
import re
import hashlib
import logging
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
import pypdf
import docx

logger = logging.getLogger(__name__)

class DocumentProcessor:
    """Handles parsing, text extraction, cleaning, SHA-256 hashing, and metadata tracking across document types."""

    @staticmethod
    def compute_file_hash(file_bytes: bytes) -> str:
        """Compute SHA-256 hash of raw file bytes for duplicate detection."""
        return hashlib.sha256(file_bytes).hexdigest()

    @staticmethod
    def clean_text(text: str) -> str:
        """Clean excessive whitespaces, unprintable characters, and format artifacts while preserving structure."""
        if not text:
            return ""
        # Normalize newlines
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        # Replace non-breaking spaces
        text = text.replace("\u00a0", " ").replace("\u200b", "")
        # Replace multiple spaces/tabs with a single space
        text = re.sub(r"[ \t]+", " ", text)
        # Collapse excessive newlines into max 2
        text = re.sub(r"\n{3,}", "\n\n", text)
        # Remove null and non-printable control characters while keeping standard Latin/Unicode characters
        text = "".join([c for c in text if c in ("\n", "\t") or (32 <= ord(c) < 127) or ord(c) > 159])
        return text.strip()

    @classmethod
    def extract_from_pdf(cls, file_bytes: bytes, filename: str = "") -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Extract text page-by-page from a PDF file using resilient extraction strategies.
        Returns: (pages_data, warning_or_error_message)
        """
        pages_data = []
        total_pages = 1
        warning_msg = None

        if len(file_bytes) == 0:
            return [], "⚠️ The uploaded PDF is completely empty (0 bytes)."

        # Strategy 1: pypdf standard page text extraction
        try:
            stream = io.BytesIO(file_bytes)
            reader = pypdf.PdfReader(stream, strict=False)

            # Check for encryption
            if reader.is_encrypted:
                try:
                    decrypted = reader.decrypt("")
                    if decrypted == 0:
                        return [], f"🔒 PDF '{filename}' is password-protected. Please provide an unencrypted version."
                except Exception as e:
                    return [], f"🔒 PDF '{filename}' is password-protected and could not be decrypted: {e}"

            total_pages = max(1, len(reader.pages))

            for page_num, page in enumerate(reader.pages, start=1):
                page_text = ""
                try:
                    page_text = page.extract_text() or ""
                except Exception as e:
                    logger.debug("Page %d extract_text error: %s", page_num, e)

                # Fallback to content stream text if extract_text was empty
                if not page_text.strip():
                    try:
                        if "/Contents" in page:
                            contents = page["/Contents"]
                            if hasattr(contents, "get_data"):
                                raw_stream = contents.get_data().decode("latin-1", errors="ignore")
                                text_matches = re.findall(r'\(([^()]{2,})\)\s*T[jJ]', raw_stream)
                                if text_matches:
                                    page_text = " ".join(text_matches)
                    except Exception:
                        pass

                cleaned = cls.clean_text(page_text)
                if cleaned:
                    pages_data.append({
                        "page_number": page_num,
                        "total_pages": total_pages,
                        "text": cleaned,
                        "char_count": len(cleaned),
                        "word_count": len(cleaned.split()),
                        "filename": filename
                    })
        except Exception as e:
            logger.warning("pypdf extraction exception for %s: %s", filename, e)

        # Strategy 2: Raw string & content stream extraction fallback
        if not pages_data or sum(p.get("char_count", 0) for p in pages_data) < 20:
            try:
                decoded = file_bytes.decode('latin-1', errors='ignore')
                raw_strings = re.findall(r'\(([^()]{3,})\)', decoded)
                if raw_strings:
                    combined_raw = " ".join(raw_strings)
                    cleaned_fallback = cls.clean_text(combined_raw)
                    if len(cleaned_fallback) > 30:
                        words = cleaned_fallback.split()
                        words_per_page = 300
                        calc_pages = max(1, (len(words) + words_per_page - 1) // words_per_page)
                        pages_data = []
                        for p_idx in range(calc_pages):
                            p_words = words[p_idx*words_per_page : (p_idx+1)*words_per_page]
                            p_txt = " ".join(p_words)
                            pages_data.append({
                                "page_number": p_idx + 1,
                                "total_pages": calc_pages,
                                "text": p_txt,
                                "char_count": len(p_txt),
                                "word_count": len(p_words),
                                "filename": filename
                            })
            except Exception as e:
                logger.warning("Raw fallback extraction failed: %s", e)

        # Strategy 3: Detect scanned image PDF or corrupted content
        if not pages_data:
            warning_msg = (
                f"⚠️ We couldn't extract readable text from '{filename}'. "
                "The file may be a scanned image-only PDF, corrupted, or password-protected. "
                "OCR or text-selectable PDFs are recommended."
            )
            # Create a diagnostic placeholder record so indexing does not crash
            pages_data.append({
                "page_number": 1,
                "total_pages": total_pages,
                "text": f"Scanned/Image PDF Notice: '{filename}' contains {total_pages} page(s) without selectable text.",
                "char_count": 0,
                "word_count": 0,
                "filename": filename,
                "is_scanned": True
            })

        return pages_data, warning_msg

    @classmethod
    def extract_from_docx(cls, file_bytes: bytes, filename: str = "") -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Extract text from DOCX/DOC document including paragraphs, tables, and headers."""
        if len(file_bytes) == 0:
            return [], "⚠️ The uploaded DOCX file is empty (0 bytes)."

        try:
            stream = io.BytesIO(file_bytes)
            doc = docx.Document(stream)
            paragraphs = []

            for p in doc.paragraphs:
                txt = p.text.strip()
                if txt:
                    paragraphs.append(txt)

            for table in doc.tables:
                for row in table.rows:
                    row_text = " | ".join([cell.text.strip() for cell in row.cells if cell.text.strip()])
                    if row_text:
                        paragraphs.append(row_text)

            full_text = "\n\n".join(paragraphs)
            cleaned = cls.clean_text(full_text)

            if not cleaned:
                warning_msg = f"⚠️ DOCX file '{filename}' contains no readable text paragraphs or tables."
                cleaned = f"DOCX document '{filename}' is empty."
                total_pages = 1
                words = cleaned.split()
            else:
                warning_msg = None
                words = cleaned.split()
                words_per_page = 300
                total_pages = max(1, (len(words) + words_per_page - 1) // words_per_page)

            words_per_page = 300
            pages_data = []
            for page_idx in range(total_pages):
                start_w = page_idx * words_per_page
                end_w = min(len(words), (page_idx + 1) * words_per_page)
                page_text = " ".join(words[start_w:end_w])
                pages_data.append({
                    "page_number": page_idx + 1,
                    "total_pages": total_pages,
                    "text": page_text,
                    "char_count": len(page_text),
                    "word_count": len(page_text.split()),
                    "filename": filename
                })

            return pages_data, warning_msg
        except Exception as e:
            logger.error("DOCX parsing error for %s: %s", filename, e)
            warning = f"⚠️ Failed to parse DOCX '{filename}': {e}. The file might be corrupted or in legacy binary .doc format."
            return [{
                "page_number": 1,
                "total_pages": 1,
                "text": f"Corrupt DOCX '{filename}': {e}",
                "char_count": 0,
                "word_count": 0,
                "filename": filename
            }], warning

    @classmethod
    def extract_from_txt(cls, file_bytes: bytes, filename: str = "") -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Extract text from plain text, Markdown, CSV, or code files with multi-encoding fallback."""
        if len(file_bytes) == 0:
            return [], "⚠️ The uploaded text file is empty (0 bytes)."

        encodings = ["utf-8", "utf-8-sig", "latin-1", "cp1252", "iso-8859-1", "ascii", "gbk", "shift-jis"]
        raw_text = None
        for enc in encodings:
            try:
                raw_text = file_bytes.decode(enc)
                break
            except (UnicodeDecodeError, LookupError):
                continue

        if raw_text is None:
            raw_text = file_bytes.decode("utf-8", errors="replace")

        cleaned = cls.clean_text(raw_text)
        if not cleaned:
            return [{
                "page_number": 1,
                "total_pages": 1,
                "text": f"Text document '{filename}' is empty.",
                "char_count": 0,
                "word_count": 0,
                "filename": filename
            }], f"⚠️ Text file '{filename}' is empty."

        words = cleaned.split()
        words_per_page = 300
        total_pages = max(1, (len(words) + words_per_page - 1) // words_per_page)

        pages_data = []
        for page_idx in range(total_pages):
            start_w = page_idx * words_per_page
            end_w = min(len(words), (page_idx + 1) * words_per_page)
            page_text = " ".join(words[start_w:end_w])
            pages_data.append({
                "page_number": page_idx + 1,
                "total_pages": total_pages,
                "text": page_text,
                "char_count": len(page_text),
                "word_count": len(page_text.split()),
                "filename": filename
            })

        return pages_data, None

    @classmethod
    def process_file(cls, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        """
        Main dispatcher to parse any supported document format.
        Computes SHA-256 hash, extracts structured pages, cleans text, and tracks diagnostics.
        """
        ext = Path(filename).suffix.lower()
        file_hash = cls.compute_file_hash(file_bytes)
        file_size = len(file_bytes)

        if ext == ".pdf":
            pages_data, warning = cls.extract_from_pdf(file_bytes, filename)
        elif ext in [".docx", ".doc"]:
            pages_data, warning = cls.extract_from_docx(file_bytes, filename)
        else:
            pages_data, warning = cls.extract_from_txt(file_bytes, filename)

        full_text = "\n\n".join([p["text"] for p in pages_data])
        total_chars = sum(p.get("char_count", 0) for p in pages_data)
        total_words = len(full_text.split())
        total_pages = len(pages_data) if pages_data else 1
        is_valid = total_chars > 20 and warning is None

        return {
            "filename": filename,
            "file_hash": file_hash,
            "file_size": file_size,
            "file_ext": ext or ".txt",
            "total_pages": total_pages,
            "total_chars": total_chars,
            "total_words": total_words,
            "pages": pages_data,
            "full_text": full_text,
            "is_valid": is_valid,
            "warning": warning
        }
