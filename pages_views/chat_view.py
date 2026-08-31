"""
Intelligence Chat Page View for IntelAssist AI.
"""

from typing import Dict, Any, List, Callable, Optional
import streamlit as st
from components.chat_ui import render_chat_message, render_suggested_questions

def render_chat_page(
    messages: List[Dict[str, Any]],
    all_documents: List[str],
    selected_doc_filter: str,
    on_send_message: Callable[[str, str], None],
    on_feedback: Callable[[str, str], None],
    on_new_session: Callable[[], None],
    on_clear_chat: Callable[[], None],
    on_export_markdown: Callable[[], str],
    session_title: str = "New Case Investigation",
    saved_sessions: Optional[List[Dict[str, Any]]] = None,
    current_session_id: Optional[str] = None,
    on_load_session: Optional[Callable[[str], None]] = None,
    on_delete_session: Optional[Callable[[str], None]] = None,
    doc_registry: Optional[Dict[str, Dict[str, Any]]] = None,
    on_upload_files: Optional[Callable[[List[Any]], None]] = None
):
    """Render the Cyber Intelligence Chat Page with in-chat uploading and source citations."""
    registry = doc_registry or {}
    total_docs = len(all_documents)
    total_pages = sum(d.get("total_pages", 1) for d in registry.values())
    total_chunks = sum(d.get("chunk_count", 0) for d in registry.values())

    # Top Header Banner
    st.markdown(f"""
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; flex-wrap:wrap; gap:10px;">
        <div>
            <div style="display:flex; align-items:center; gap:10px;">
                <h2 style="font-weight:800; color:#ffffff; margin:0; letter-spacing:-0.02em; font-size:1.6rem;">💬 Cyber Intelligence Chat</h2>
                <span style="font-size:0.75rem; background:rgba(56,189,248,0.18); color:#38bdf8; padding:4px 12px; border-radius:9999px; border:1px solid rgba(56,189,248,0.35); font-weight:700;">
                    🟢 RAG-Grounded Forensic QA
                </span>
            </div>
            <p style="color:#94a3b8; font-size:0.88rem; margin:4px 0 0 0;">
                Active Case: <b style="color:#f8fafc;">{session_title}</b> • <span style="color:#38bdf8; font-weight:600;">{len(messages)} messages exchanged</span>
            </p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Document Scope & Action Toolbar
    filter_options = ["All Documents"] + all_documents
    active_scope = st.session_state.get("chat_doc_filter", selected_doc_filter)
    if active_scope not in filter_options:
        active_scope = "All Documents"
        st.session_state.chat_doc_filter = "All Documents"

    default_filter_idx = filter_options.index(active_scope)

    col_scope, col_upload, col_new, col_clear, col_hist, col_export = st.columns([2.4, 1.3, 1.1, 1.1, 1.2, 1.1])

    with col_scope:
        doc_filter = st.selectbox(
            f"📄 Target Scope ({total_docs} Files)",
            filter_options,
            index=default_filter_idx,
            key=f"chat_scope_selector_{active_scope}",
            help="Choose whether to query all indexed threat artifacts or target search strictly to a single file"
        )
        st.session_state.chat_doc_filter = doc_filter

    with col_upload:
        st.markdown("<div style='margin-top:28px;'></div>", unsafe_allow_html=True)
        with st.popover("📤 Ingest File", use_container_width=True, help="Upload and index new PDF, DOCX, TXT, LOG, CSV files directly into Intelligence Chat"):
            st.markdown("<div style='font-size:0.9rem; font-weight:700; color:#ffffff; margin-bottom:6px;'>📤 Upload Security File</div>", unsafe_allow_html=True)
            st.markdown("<p style='font-size:0.8rem; color:#cbd5e1; margin-bottom:8px;'>Upload any threat report or security log. It will be indexed immediately for RAG chat!</p>", unsafe_allow_html=True)
            chat_files = st.file_uploader(
                "Upload files",
                type=["pdf", "docx", "doc", "txt", "md", "csv", "json", "log"],
                accept_multiple_files=True,
                key="chat_direct_file_uploader",
                label_visibility="collapsed"
            )
            if chat_files and on_upload_files:
                if st.button(f"⚡ Index {len(chat_files)} File(s) Now", key="chat_index_btn", type="primary", use_container_width=True):
                    on_upload_files(chat_files)
    
    with col_new:
        st.markdown("<div style='margin-top:28px;'></div>", unsafe_allow_html=True)
        if st.button("➕ New Case", key="chat_new_session_btn", type="primary", help="Start a new investigation case", use_container_width=True):
            on_new_session()
            
    with col_clear:
        st.markdown("<div style='margin-top:28px;'></div>", unsafe_allow_html=True)
        with st.popover("🗑️ Clear", use_container_width=True, help="Clear active conversation messages"):
            st.markdown("<div style='font-size:0.9rem; font-weight:700; color:#ffffff; margin-bottom:6px;'>🧹 Clear Active Messages</div>", unsafe_allow_html=True)
            st.markdown("<p style='font-size:0.82rem; color:#cbd5e1; margin-bottom:10px;'>Wipe messages from this active session?</p>", unsafe_allow_html=True)
            if st.button("Yes, Clear Chat", key="chat_confirm_clear_btn", type="primary", use_container_width=True):
                on_clear_chat()

    with col_hist:
        st.markdown("<div style='margin-top:28px;'></div>", unsafe_allow_html=True)
        sessions = saved_sessions or []
        with st.popover(f"📜 Cases ({len(sessions)})", use_container_width=True, help="View and switch between saved investigation sessions"):
            st.markdown("<div style='font-size:0.9rem; font-weight:700; color:#ffffff; margin-bottom:8px;'>📜 Saved Case Sessions</div>", unsafe_allow_html=True)
            if not sessions:
                st.markdown("<p style='font-size:0.8rem; color:#94a3b8;'>No saved cases yet.</p>", unsafe_allow_html=True)
            else:
                for s in sessions:
                    sid = s.get("session_id")
                    stitle = s.get("title", "Case")
                    is_cur = (sid == current_session_id)
                    indicator = "🟢 " if is_cur else ""
                    if st.button(f"{indicator}{stitle}", key=f"chat_pop_hist_{sid}", use_container_width=True):
                        if on_load_session:
                            on_load_session(sid)

    with col_export:
        st.markdown("<div style='margin-top:28px;'></div>", unsafe_allow_html=True)
        md_content = on_export_markdown()
        st.download_button(
            "📥 Export",
            data=md_content,
            file_name=f"investigation_case_{session_title.lower().replace(' ', '_')[:20]}.md",
            mime="text/markdown",
            use_container_width=True,
            help="Download complete case conversation log as Markdown"
        )

    st.markdown("<div style='margin:14px 0; border-bottom:1px solid rgba(56,189,248,0.12);'></div>", unsafe_allow_html=True)

    # Empty State with Suggested Inquiries
    if not messages:
        st.markdown(f"""
        <div class="modern-card" style="text-align:center; padding:32px 20px; margin-bottom:18px; border:1px solid rgba(56,189,248,0.25);">
            <div style="font-size:2.8rem; margin-bottom:10px;">🛡️</div>
            <h3 style="font-weight:800; font-size:1.25rem; color:#f8fafc; margin:0 0 6px 0;">
                IntelAssist AI Threat Intelligence Assistant
            </h3>
            <p style="font-size:0.88rem; color:#94a3b8; max-width:540px; margin:0 auto 16px auto;">
                Ask specific questions about your uploaded threat advisories, extract indicators of compromise, or investigate suspicious authentication events.
            </p>
        </div>
        """, unsafe_allow_html=True)

        render_suggested_questions(
            on_select=lambda q: on_send_message(q, doc_filter),
            active_doc=doc_filter
        )
    else:
        # Render Message Stream
        for msg in messages:
            render_chat_message(msg, on_feedback=on_feedback)

    # Chat Input Box
    chat_prompt = st.chat_input(
        placeholder=f"Ask anything about {doc_filter if doc_filter != 'All Documents' else 'your ingested threat reports and logs'}...",
        key="chat_user_input_box"
    )

    if chat_prompt and chat_prompt.strip():
        on_send_message(chat_prompt.strip(), doc_filter)
