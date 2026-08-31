"""
Pytest configuration and shared fixtures for IntelliAssist AI test suite.
"""

import sys
from pathlib import Path
import pytest
import numpy as np

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services.document_processor import DocumentProcessor
from services.chunker import TextChunker
from services.embeddings import EmbeddingService
from services.vector_store import VectorStore
from services.llm_service import LLMService
from services.rag_engine import RAGEngine
from services.summarizer import DocumentSummarizer
from services.sentiment_analyzer import SentimentIntentAnalyzer
from services.conversation_manager import ConversationManager
from utils.sample_docs import generate_all_samples

@pytest.fixture(scope="session")
def sample_documents():
    """Generate sample test files."""
    return generate_all_samples()

@pytest.fixture
def embedding_service():
    """Fixture providing initialized EmbeddingService."""
    return EmbeddingService()

@pytest.fixture
def temp_vector_store(tmp_path, embedding_service):
    """Fixture providing an isolated temporary VectorStore."""
    db_dir = tmp_path / "vector_db"
    return VectorStore(embedding_service=embedding_service, db_dir=db_dir)

@pytest.fixture
def sample_chunks(sample_documents):
    """Fixture returning chunked representations of sample documents."""
    chunker = TextChunker(chunk_size=400, chunk_overlap=80)
    all_chunks = []
    for sf in sample_documents:
        with open(sf, "rb") as f:
            bytes_data = f.read()
        doc_info = DocumentProcessor.process_file(bytes_data, sf.name)
        chunks = chunker.chunk_document(doc_info)
        all_chunks.extend(chunks)
    return all_chunks

@pytest.fixture
def populated_vector_store(temp_vector_store, sample_chunks):
    """Fixture providing a vector store populated with sample document chunks."""
    temp_vector_store.add_documents(sample_chunks)
    return temp_vector_store

@pytest.fixture
def rag_engine(populated_vector_store):
    """Fixture providing RAGEngine wired to demo LLM."""
    llm = LLMService(provider="Demo Mode (Smart AI)")
    return RAGEngine(vector_store=populated_vector_store, llm_service=llm)

@pytest.fixture
def summarizer():
    """Fixture providing DocumentSummarizer."""
    llm = LLMService(provider="Demo Mode (Smart AI)")
    return DocumentSummarizer(llm_service=llm)

@pytest.fixture
def sentiment_analyzer():
    """Fixture providing SentimentIntentAnalyzer."""
    return SentimentIntentAnalyzer()
