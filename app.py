"""
Main Application Entry Point for IntelAssist AI.
AI-Powered Cyber Threat Intelligence & Investigation Platform.
"""

import sys
import time
import os
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Tuple
import streamlit as st

# Auto-launch with streamlit run if executed directly via `python app.py`
if __name__ == "__main__" and not st.runtime.exists():
    from streamlit.web import cli as stcli
    sys.argv = ["streamlit", "run", sys.argv[0]]
    sys.exit(stcli.main())

# Streamlit Page Configuration - Must be the first Streamlit command
st.set_page_config(
    page_title="IntelAssist AI — Cyber Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Design System and Components
import importlib
import components.styles
import components.sidebar
import components.chat_ui
import services.auth_service
import services.ioc_extractor
import services.log_analyzer
import services.threat_correlator
import services.risk_engine
import services.mitre_mapper
import services.conversation_manager
import services.rag_engine
import services.llm_service
import pages_views.dashboard_view
import pages_views.documents_view
import pages_views.investigation_view
import pages_views.ioc_explorer_view
import pages_views.log_analysis_view
import pages_views.ai_investigation_view
import pages_views.timeline_view
import pages_views.chat_view
import pages_views.summarizer_view
import pages_views.search_view
import pages_views.analytics_view
import pages_views.history_view
import pages_views.settings_view
import pages_views.auth_view

importlib.reload(components.styles)
importlib.reload(components.sidebar)
importlib.reload(components.chat_ui)
importlib.reload(services.auth_service)
importlib.reload(services.ioc_extractor)
importlib.reload(services.log_analyzer)
importlib.reload(services.threat_correlator)
importlib.reload(services.risk_engine)
importlib.reload(services.mitre_mapper)
importlib.reload(services.conversation_manager)
importlib.reload(services.rag_engine)
importlib.reload(services.llm_service)

from components.styles import inject_custom_styles
from components.sidebar import render_sidebar
from utils.config import (
    APP_NAME, APP_TAGLINE, APP_VERSION, APP_FULL_TITLE,
    DEFAULT_LLM_PROVIDER, DEFAULT_TEMPERATURE, DEFAULT_MAX_TOKENS,
    DEFAULT_CHUNK_SIZE, DEFAULT_CHUNK_OVERLAP, UPLOAD_DIR, DATA_DIR, LOGS_DIR
)
from utils.sample_docs import generate_all_samples

# Services
from services.auth_service import AuthService
from services.document_processor import DocumentProcessor
from services.chunker import TextChunker
from services.embeddings import EmbeddingService
from services.vector_store import VectorStore
from services.llm_service import LLMService
from services.rag_engine import RAGEngine
from services.summarizer import DocumentSummarizer
from services.conversation_manager import ConversationManager
from services.ioc_extractor import IOCExtractor
from services.log_analyzer import LogAnalyzer
from services.threat_correlator import ThreatCorrelator
from services.risk_engine import RiskEngine
from services.mitre_mapper import MITREMapper

# Page Views
from pages_views.dashboard_view import render_dashboard
from pages_views.documents_view import render_documents_page
from pages_views.investigation_view import render_investigation_page
from pages_views.ioc_explorer_view import render_ioc_explorer_page
from pages_views.log_analysis_view import render_log_analysis_page
from pages_views.ai_investigation_view import render_ai_investigation_page
from pages_views.timeline_view import render_attack_timeline_page
from pages_views.chat_view import render_chat_page
from pages_views.search_view import render_search_page
from pages_views.summarizer_view import render_summarizer_page
from pages_views.analytics_view import render_analytics_page
from pages_views.history_view import render_history_page
from pages_views.settings_view import render_settings_page
from pages_views.auth_view import render_auth_page

import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("intelassist_ai")

# Inject CSS
inject_custom_styles()

DOCUMENTS_METADATA_FILE = DATA_DIR / "documents_metadata.json"
PARSED_LOGS_FILE = DATA_DIR / "parsed_logs.json"

def save_document_registry(registry: dict):
    """Persist document metadata to disk."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(DOCUMENTS_METADATA_FILE, "w", encoding="utf-8") as f:
            json.dump(registry, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error("Failed to save document registry: %s", e)

def load_document_registry() -> dict:
    """Load document metadata from disk if available."""
    if DOCUMENTS_METADATA_FILE.exists():
        try:
            with open(DOCUMENTS_METADATA_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_parsed_logs(logs: list):
    """Persist parsed log analysis results to disk."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(PARSED_LOGS_FILE, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error("Failed to save parsed logs: %s", e)

def load_parsed_logs() -> list:
    """Load parsed logs from disk if available."""
    if PARSED_LOGS_FILE.exists():
        try:
            with open(PARSED_LOGS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def initialize_state():
    """Initialize persistent session states, services, and default cyber data."""
    if "nav_page" not in st.session_state:
        st.session_state.nav_page = "Dashboard"

    if "auth_service" not in st.session_state:
        st.session_state.auth_service = AuthService()

    if "current_user" not in st.session_state:
        # Default to Demo Analyst for instantaneous hackathon demonstration
        st.session_state.current_user = st.session_state.auth_service.get_demo_account()

    if "settings" not in st.session_state:
        st.session_state.settings = {
            "provider": DEFAULT_LLM_PROVIDER,
            "model_name": "gemini-flash-latest",
            "temperature": DEFAULT_TEMPERATURE,
            "max_tokens": DEFAULT_MAX_TOKENS,
            "gemini_api_key": os.getenv("GEMINI_API_KEY", ""),
            "nvidia_api_key": os.getenv("NVIDIA_API_KEY", ""),
            "openai_api_key": os.getenv("OPENAI_API_KEY", "")
        }

    # Core AI singletons
    if "embedding_service" not in st.session_state:
        st.session_state.embedding_service = EmbeddingService()

    if "vector_store" not in st.session_state:
        st.session_state.vector_store = VectorStore(embedding_service=st.session_state.embedding_service)

    if "llm_service" not in st.session_state:
        s = st.session_state.settings
        st.session_state.llm_service = LLMService(
            provider=s["provider"],
            model_name=s["model_name"],
            temperature=s["temperature"],
            max_tokens=s["max_tokens"],
            api_key=s.get("gemini_api_key") or s.get("nvidia_api_key") or s.get("openai_api_key")
        )

    if "rag_engine" not in st.session_state:
        st.session_state.rag_engine = RAGEngine(
            vector_store=st.session_state.vector_store,
            llm_service=st.session_state.llm_service
        )

    if "summarizer" not in st.session_state:
        st.session_state.summarizer = DocumentSummarizer(llm_service=st.session_state.llm_service)

    if "conversation_manager" not in st.session_state:
        st.session_state.conversation_manager = ConversationManager()

    if "document_registry" not in st.session_state:
        st.session_state.document_registry = load_document_registry()

    if "parsed_logs" not in st.session_state:
        st.session_state.parsed_logs = load_parsed_logs()

    if "extracted_iocs" not in st.session_state:
        st.session_state.extracted_iocs = IOCExtractor.aggregate_document_iocs(st.session_state.document_registry)

    if "activity_logs" not in st.session_state:
        st.session_state.activity_logs = [
            {"icon": "🛡️", "title": "SOC Engine Online", "time": "Just now", "desc": "IntelAssist Threat Intelligence and Vector Database active."}
        ]

    if "total_investigations" not in st.session_state:
        st.session_state.total_investigations = 1

    if "total_questions" not in st.session_state:
        st.session_state.total_questions = 0

    if "total_summaries" not in st.session_state:
        st.session_state.total_summaries = 0

    if "total_searches" not in st.session_state:
        st.session_state.total_searches = 0

    if "latencies" not in st.session_state:
        st.session_state.latencies = [0.22, 0.28, 0.25]

    if "current_summary_data" not in st.session_state:
        st.session_state.current_summary_data = None

    if "chat_doc_filter" not in st.session_state:
        st.session_state.chat_doc_filter = "All Documents"

    if "selected_doc_preview" not in st.session_state:
        st.session_state.selected_doc_preview = None

    if "target_summary_doc" not in st.session_state:
        st.session_state.target_summary_doc = None

    if "investigation_target" not in st.session_state:
        st.session_state.investigation_target = "185.220.101.5"

initialize_state()

def record_activity(icon: str, title: str, desc: str = ""):
    """Add a new log item to recent activity feed."""
    st.session_state.activity_logs.insert(0, {
        "icon": icon,
        "title": title,
        "time": time.strftime("%H:%M:%S"),
        "desc": desc
    })
    if len(st.session_state.activity_logs) > 25:
        st.session_state.activity_logs.pop()

def process_and_index_files(files_or_paths):
    """Process files through text extraction, chunking, and vector database indexing."""
    chunker = TextChunker(chunk_size=DEFAULT_CHUNK_SIZE, chunk_overlap=DEFAULT_CHUNK_OVERLAP)
    new_chunks_count = 0

    progress_bar = st.progress(0, text="Initializing processing pipeline...")

    for idx, file_obj in enumerate(files_or_paths):
        if isinstance(file_obj, (str, Path)):
            path = Path(file_obj)
            filename = path.name
            with open(path, "rb") as f:
                file_bytes = f.read()
            file_size = len(file_bytes)
        else:
            filename = file_obj.name
            file_bytes = file_obj.getvalue()
            file_size = len(file_bytes)

        pct = int(min(90, (idx + 1) / max(1, len(files_or_paths)) * 80))
        progress_bar.progress(pct, text=f"Processing & indexing '{filename}'...")

        file_hash = DocumentProcessor.compute_file_hash(file_bytes)
        processed_doc = DocumentProcessor.process_file(file_bytes, filename)
        chunks = chunker.chunk_document(processed_doc)

        st.session_state.vector_store.delete_document(filename)
        st.session_state.vector_store.add_documents(chunks)
        new_chunks_count += len(chunks)

        # Check if file is a log file to also parse with LogAnalyzer
        ext = Path(filename).suffix.lower()
        if ext == ".log" or "log" in filename.lower():
            try:
                log_text = processed_doc.get("full_text", "")
                parsed_log = LogAnalyzer.parse_log_text(log_text, filename=filename)
                
                # Replace or add in parsed_logs
                st.session_state.parsed_logs = [l for l in st.session_state.parsed_logs if l.get("filename") != filename]
                st.session_state.parsed_logs.append(parsed_log)
                save_parsed_logs(st.session_state.parsed_logs)
            except Exception as e:
                logger.error("Failed to parse log file %s: %s", filename, e)

        # Record in registry
        st.session_state.document_registry[filename] = {
            "filename": filename,
            "file_hash": file_hash,
            "file_ext": processed_doc.get("file_ext", ".txt"),
            "file_size": file_size,
            "total_pages": processed_doc.get("total_pages", 1),
            "total_chars": processed_doc.get("total_chars", 0),
            "total_words": processed_doc.get("total_words", 0),
            "chunk_count": len(chunks),
            "full_text": processed_doc.get("full_text", ""),
            "upload_date": time.strftime("%b %d, %H:%M"),
            "status": "Ready"
        }

    # Refresh extracted IOCs
    st.session_state.extracted_iocs = IOCExtractor.aggregate_document_iocs(st.session_state.document_registry)
    save_document_registry(st.session_state.document_registry)
    st.session_state.vector_store.save_to_disk()

    progress_bar.progress(100, text="✓ Indexing complete!")
    time.sleep(0.2)
    record_activity("📄", f"Indexed {len(files_or_paths)} security artifact(s)", f"Extracted {len(st.session_state.extracted_iocs)} IOCs and {new_chunks_count} vector chunks.")
    st.toast(f"Successfully processed {len(files_or_paths)} artifact(s)!", icon="🛡️")

def load_demo_investigation_action():
    """Load realistic APT29 threat advisory, SSH brute force log, and firewall traffic."""
    sample_files = generate_all_samples()
    with st.spinner("Loading and indexing APT29 threat intelligence advisory and security logs..."):
        process_and_index_files(sample_files)
    st.session_state.investigation_target = "185.220.101.5"
    st.session_state.total_investigations += 1
    record_activity("⚡", "Loaded Cyber Threat Demo Investigation", "APT29 advisory, auth.log, firewall, and IOC feed ingested.")
    st.rerun()

# Auto-seed sample documents if registry is empty on initial startup
if len(st.session_state.document_registry) == 0:
    sample_files = generate_all_samples()
    process_and_index_files(sample_files)

# Session actions helper callbacks
all_sessions = st.session_state.conversation_manager.list_all_sessions()
current_sid = st.session_state.conversation_manager.current_session_id

def handle_load_session(s_id: str):
    if st.session_state.conversation_manager.load_session(s_id):
        st.session_state.nav_page = "Intelligence Chat"
        st.toast("Loaded case session!", icon="📂")
        st.rerun()

def handle_delete_session(s_id: str):
    st.session_state.conversation_manager.delete_session(s_id)
    st.toast("Deleted case session.", icon="🗑️")
    st.rerun()

def handle_clear_current_chat():
    st.session_state.conversation_manager.clear_current_chat()
    st.toast("Active case conversation cleared.", icon="🧹")
    st.rerun()

def handle_new_chat():
    st.session_state.conversation_manager.new_session()
    st.session_state.chat_doc_filter = "All Documents"
    st.session_state.nav_page = "Intelligence Chat"
    st.toast("Opened a new investigation case!", icon="✨")
    st.rerun()

def handle_delete_all_sessions():
    cnt = st.session_state.conversation_manager.delete_all_sessions()
    st.toast(f"Deleted all {cnt} saved case sessions.", icon="🗑️")
    st.rerun()

# Calculate critical alerts across parsed logs
all_critical_alerts = []
for p_log in st.session_state.parsed_logs:
    for a in p_log.get("alerts", []):
        if a.get("severity") in ["High", "Critical"]:
            all_critical_alerts.append(a)

# Sidebar Rendering
is_api_conn = bool(st.session_state.settings.get("gemini_api_key") or st.session_state.settings.get("nvidia_api_key") or st.session_state.settings.get("openai_api_key"))
selected_nav = render_sidebar(
    active_nav=st.session_state.nav_page,
    total_docs=len(st.session_state.document_registry),
    total_chunks=st.session_state.vector_store.total_chunks,
    total_iocs=len(st.session_state.extracted_iocs),
    critical_alerts_count=len(all_critical_alerts),
    provider_name=st.session_state.settings.get("provider", "Demo AI"),
    is_api_connected=is_api_conn,
    current_user=st.session_state.current_user,
    recent_sessions=all_sessions,
    current_session_id=current_sid,
    on_load_session=handle_load_session,
    on_delete_session=handle_delete_session,
    on_new_chat=handle_new_chat,
    on_clear_active_chat=handle_clear_current_chat,
    on_navigate=lambda p: (setattr(st.session_state, "nav_page", p), st.rerun()),
    on_logout=lambda: (setattr(st.session_state, "current_user", None), st.rerun())
)

if selected_nav != st.session_state.nav_page:
    st.session_state.nav_page = selected_nav
    st.rerun()

# ----------------- Navigation Router -----------------

doc_list = sorted(list(st.session_state.document_registry.values()), key=lambda x: x["filename"])
all_doc_names = [d["filename"] for d in doc_list]

def handle_quick_ask(question: str):
    st.session_state.nav_page = "Intelligence Chat"
    handle_chat_message(question, "All Documents")
    st.rerun()

def handle_investigate_ioc(indicator: str):
    st.session_state.investigation_target = indicator
    st.session_state.total_investigations += 1
    st.session_state.nav_page = "Threat Investigation"
    st.rerun()

def handle_open_doc(filename: str):
    st.session_state.selected_doc_preview = st.session_state.document_registry.get(filename)
    st.session_state.nav_page = "Threat Reports"
    st.rerun()

def handle_summarize_doc(filename: str):
    st.session_state.target_summary_doc = filename
    st.session_state.nav_page = "Threat Summaries"
    st.rerun()

def handle_chat_doc(filename: str):
    st.session_state.chat_doc_filter = filename
    st.session_state.nav_page = "Intelligence Chat"
    st.rerun()

def handle_delete_doc(filename: str):
    st.session_state.vector_store.delete_document(filename)
    if filename in st.session_state.document_registry:
        del st.session_state.document_registry[filename]
        save_document_registry(st.session_state.document_registry)
    st.session_state.extracted_iocs = IOCExtractor.aggregate_document_iocs(st.session_state.document_registry)
    record_activity("🗑️", f"Deleted {filename}", "Removed from vector database.")
    st.toast(f"Deleted {filename} and updated vector index.", icon="🗑️")
    st.rerun()

def handle_chat_message(prompt: str, doc_filter: str):
    """Process user threat questions through the RAG pipeline."""
    st.session_state.conversation_manager.add_message(role="user", content=prompt)
    
    with st.spinner("Retrieving threat evidence and synthesizing answer..."):
        filter_param = None if doc_filter == "All Documents" else doc_filter
        rag_res = st.session_state.rag_engine.answer_question(
            question=prompt,
            top_k=6,
            filter_doc=filter_param
        )

    st.session_state.conversation_manager.add_message(
        role="assistant",
        content=rag_res.get("answer", ""),
        sources=rag_res.get("sources", []),
        model_info={
            "provider": rag_res.get("provider", "IntelAssist AI"),
            "model": rag_res.get("model", ""),
            "latency_sec": rag_res.get("latency_sec", 0.25),
            "is_demo": rag_res.get("is_demo", False)
        }
    )

    st.session_state.total_questions += 1
    short_q = (prompt[:22] + "...") if len(prompt) > 25 else prompt
    record_activity("💬", f"Q&A: {short_q}", f"Cited {len(rag_res.get('sources', []))} chunks ({rag_res.get('latency_sec', 0.25)}s)")

# Page: 📊 Dashboard
if st.session_state.nav_page == "Dashboard":
    render_dashboard(
        doc_infos=doc_list,
        log_infos=st.session_state.parsed_logs,
        extracted_iocs=st.session_state.extracted_iocs,
        critical_alerts=all_critical_alerts,
        total_investigations=st.session_state.total_investigations,
        recent_activities=st.session_state.activity_logs,
        on_quick_ask=handle_quick_ask,
        on_investigate_ioc=handle_investigate_ioc,
        on_navigate=lambda p: (setattr(st.session_state, "nav_page", p), st.rerun()),
        on_open_doc=handle_open_doc,
        on_summarize_doc=handle_summarize_doc,
        on_chat_doc=handle_chat_doc,
        on_delete_doc=handle_delete_doc,
        on_load_demo_investigation=load_demo_investigation_action
    )

# Page: 📄 Threat Reports
elif st.session_state.nav_page == "Threat Reports":
    render_documents_page(
        doc_infos=doc_list,
        on_upload_files=lambda files: (process_and_index_files(files), st.rerun()),
        on_load_samples=load_demo_investigation_action,
        on_open_doc=handle_open_doc,
        on_summarize_doc=handle_summarize_doc,
        on_chat_doc=handle_chat_doc,
        on_delete_doc=handle_delete_doc,
        selected_doc_preview=st.session_state.selected_doc_preview
    )

# Page: 🎯 Threat Investigation
elif st.session_state.nav_page == "Threat Investigation":
    render_investigation_page(
        document_registry=st.session_state.document_registry,
        log_results=st.session_state.parsed_logs,
        all_extracted_iocs=st.session_state.extracted_iocs,
        on_ask_ai_about_indicator=lambda q: (setattr(st.session_state, "nav_page", "AI Investigation Assistant"), setattr(st.session_state, "current_inv_prompt", q), st.rerun()),
        initial_target=st.session_state.investigation_target
    )

# Page: 🏷️ IOC Explorer
elif st.session_state.nav_page == "IOC Explorer":
    render_ioc_explorer_page(
        all_extracted_iocs=st.session_state.extracted_iocs,
        on_investigate_ioc=handle_investigate_ioc
    )

# Page: 📋 Log Analysis
elif st.session_state.nav_page == "Log Analysis":
    render_log_analysis_page(
        log_data_list=st.session_state.parsed_logs,
        on_upload_log=lambda files: (process_and_index_files(files), st.rerun()),
        on_investigate_ip=handle_investigate_ioc
    )

# Page: 🤖 AI Investigation Assistant
elif st.session_state.nav_page == "AI Investigation Assistant":
    def execute_ai_investigation(query: str, doc_filter: Optional[str]):
        st.session_state.total_investigations += 1
        record_activity("🤖", f"AI Investigation: {query[:22]}...", "Evidence-grounded report generated.")
        return st.session_state.rag_engine.answer_question(
            question=query,
            top_k=8,
            filter_doc=doc_filter
        )

    render_ai_investigation_page(
        all_documents=all_doc_names,
        on_run_investigation=execute_ai_investigation,
        default_prompt=st.session_state.get("current_inv_prompt")
    )

# Page: ⏱️ Attack Timeline
elif st.session_state.nav_page == "Attack Timeline":
    render_attack_timeline_page(
        log_data_list=st.session_state.parsed_logs,
        document_registry=st.session_state.document_registry
    )

# Page: 🔎 Document Search
elif st.session_state.nav_page == "Document Search":
    def do_semantic_search(query: str, top_k: int, threshold: float, doc_filter: str):
        st.session_state.total_searches += 1
        short_q = (query[:22] + "...") if len(query) > 25 else query
        record_activity("🔎", f"Search: {short_q}", f"Top-{top_k} matches retrieved")
        return st.session_state.vector_store.search(
            query=query,
            top_k=top_k,
            threshold=threshold,
            filter_doc=None if doc_filter == "All Documents" else doc_filter
        )

    render_search_page(
        all_documents=all_doc_names,
        on_search=do_semantic_search,
        on_ask_about_result=lambda q: (setattr(st.session_state, "nav_page", "Intelligence Chat"), handle_chat_message(q, "All Documents"), st.rerun())
    )

# Page: 💬 Intelligence Chat
elif st.session_state.nav_page == "Intelligence Chat":
    render_chat_page(
        messages=st.session_state.conversation_manager.messages,
        all_documents=all_doc_names,
        selected_doc_filter=st.session_state.get("chat_doc_filter", "All Documents"),
        on_send_message=lambda q, df: (handle_chat_message(q, df), st.rerun()),
        on_feedback=lambda mid, fb: st.session_state.conversation_manager.set_feedback(mid, fb),
        on_new_session=handle_new_chat,
        on_clear_chat=handle_clear_current_chat,
        on_export_markdown=lambda: st.session_state.conversation_manager.export_as_markdown(),
        session_title=st.session_state.conversation_manager.title,
        saved_sessions=all_sessions,
        current_session_id=current_sid,
        on_load_session=handle_load_session,
        on_delete_session=handle_delete_session,
        doc_registry=st.session_state.document_registry,
        on_upload_files=lambda files: (process_and_index_files(files), st.rerun())
    )

# Page: 📝 Threat Summaries
elif st.session_state.nav_page == "Threat Summaries":
    def do_summarize(doc_name: str, mode: str):
        doc_info = st.session_state.document_registry.get(doc_name, {})
        full_text = doc_info.get("full_text", "")
        summary_result = st.session_state.summarizer.summarize(text=full_text, mode=mode, doc_name=doc_name)
        st.session_state.current_summary_data = summary_result
        st.session_state.total_summaries += 1
        short_d = (doc_name[:22] + "...") if len(doc_name) > 25 else doc_name
        record_activity("📝", f"Summary: {short_d}", f"Mode: {mode}")
        return summary_result

    def do_compare(doc_a_name: str, doc_b_name: str):
        doc_a_info = st.session_state.document_registry.get(doc_a_name, {})
        doc_b_info = st.session_state.document_registry.get(doc_b_name, {})
        text_a = doc_a_info.get("full_text", "")
        text_b = doc_b_info.get("full_text", "")
        record_activity("⚖️", f"Compare: {doc_a_name[:12]} vs {doc_b_name[:12]}", "Cross-report matrix generated")
        return st.session_state.summarizer.compare_documents(doc_a_name, text_a, doc_b_name, text_b)

    render_summarizer_page(
        all_documents=all_doc_names,
        on_summarize=do_summarize,
        on_compare=do_compare,
        current_summary_data=st.session_state.current_summary_data,
        default_doc=st.session_state.target_summary_doc
    )

# Page: 📈 Analytics
elif st.session_state.nav_page == "Analytics":
    avg_lat = sum(st.session_state.latencies) / max(1, len(st.session_state.latencies))
    render_analytics_page(
        doc_infos=doc_list,
        total_chunks=st.session_state.vector_store.total_chunks,
        total_questions=st.session_state.total_questions,
        total_summaries=st.session_state.total_summaries,
        total_searches=st.session_state.total_searches,
        extracted_iocs=st.session_state.extracted_iocs,
        avg_latency=avg_lat
    )

# Page: 🕘 Case History
elif st.session_state.nav_page == "Case History":
    def handle_rename_session(s_id: str, new_name: str):
        st.session_state.conversation_manager.rename_session(s_id, new_name)
        st.toast("Renamed case!", icon="✏️")

    render_history_page(
        sessions=all_sessions,
        current_session_id=current_sid,
        on_load_session=handle_load_session,
        on_rename_session=handle_rename_session,
        on_delete_session=handle_delete_session,
        on_delete_all_sessions=handle_delete_all_sessions,
        on_new_chat=handle_new_chat
    )

# Page: ⚙️ Settings
elif st.session_state.nav_page == "Settings":
    def handle_save_settings(new_settings: Dict[str, Any]):
        st.session_state.settings.update(new_settings)
        st.session_state.llm_service = LLMService(
            provider=new_settings["provider"],
            model_name=new_settings["model_name"],
            temperature=new_settings["temperature"],
            max_tokens=new_settings["max_tokens"],
            api_key=new_settings.get("gemini_api_key") or new_settings.get("nvidia_api_key") or new_settings.get("openai_api_key")
        )
        st.session_state.rag_engine.llm_service = st.session_state.llm_service
        st.session_state.summarizer.llm_service = st.session_state.llm_service

    def handle_clear_history():
        st.session_state.conversation_manager.new_session()
        for p in st.session_state.conversation_manager.storage_dir.glob("session_*.json"):
            try:
                p.unlink()
            except Exception:
                pass

    def handle_rebuild_index():
        st.session_state.vector_store.clear()
        for doc_info in st.session_state.document_registry.values():
            chunker = TextChunker(chunk_size=DEFAULT_CHUNK_SIZE, chunk_overlap=DEFAULT_CHUNK_OVERLAP)
            processed_doc = {
                "filename": doc_info["filename"],
                "pages": [{"page_number": 1, "text": doc_info["full_text"], "total_pages": doc_info.get("total_pages", 1)}]
            }
            chunks = chunker.chunk_document(processed_doc)
            st.session_state.vector_store.add_documents(chunks)

    def handle_clear_all():
        st.session_state.vector_store.clear()
        st.session_state.document_registry = {}
        st.session_state.parsed_logs = []
        st.session_state.extracted_iocs = []
        if DOCUMENTS_METADATA_FILE.exists():
            DOCUMENTS_METADATA_FILE.unlink()
        if PARSED_LOGS_FILE.exists():
            PARSED_LOGS_FILE.unlink()
        handle_clear_history()

    render_settings_page(
        current_settings=st.session_state.settings,
        on_save_settings=handle_save_settings,
        on_clear_history=handle_clear_history,
        on_rebuild_index=handle_rebuild_index,
        on_clear_all_data=handle_clear_all
    )

# Footer
st.markdown(f"""
<div class="app-footer">
    <b>{APP_NAME}</b> • {APP_FULL_TITLE}<br>
    Built with Python • Cyber RAG • Dense Embeddings • Forensic Threat Intelligence • Explainable AI
</div>
""", unsafe_allow_html=True)
