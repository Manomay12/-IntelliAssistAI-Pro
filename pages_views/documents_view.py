"""
Threat Reports & Document Intelligence Repository View for IntelAssist AI.
"""

from typing import Dict, Any, List, Callable, Optional
import streamlit as st
from utils.helpers import format_file_size, get_file_icon

def render_documents_page(
    doc_infos: List[Dict[str, Any]],
    on_upload_files: Callable[[List[Any]], None],
    on_load_samples: Callable[[], None],
    on_open_doc: Callable[[str], None],
    on_summarize_doc: Callable[[str], None],
    on_chat_doc: Callable[[str], None],
    on_delete_doc: Callable[[str], None],
    selected_doc_preview: Optional[Dict[str, Any]] = None
):
    """Render the Threat Reports repository and multi-format ingestion workspace."""
    st.markdown("""
    <div style="margin-bottom:18px;">
        <div style="display:flex; align-items:center; gap:10px;">
            <h2 style="font-weight:800; color:#ffffff; margin:0; letter-spacing:-0.02em;">📄 Threat Reports & Intelligence Repository</h2>
            <span style="font-size:0.75rem; background:rgba(56,189,248,0.18); color:#38bdf8; padding:3px 10px; border-radius:9999px; border:1px solid rgba(56,189,248,0.35); font-weight:700;">
                Multi-Format RAG Ingestion
            </span>
        </div>
        <p style="color:#94a3b8; font-size:0.92rem; margin:4px 0 0 0;">
            Upload Threat Intelligence Reports, Malware Analyses, Security Advisories, Incident Forensics, or Vulnerability Bulletins in PDF, DOCX, TXT, or Markdown formats.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Ingestion Card
    st.markdown("""
    <div class="modern-card" style="border: 2px dashed rgba(56, 189, 248, 0.4); text-align:center; padding:24px 20px; margin-bottom:18px;">
        <div style="font-size:2.2rem; margin-bottom:6px;">📤</div>
        <h3 style="margin:0 0 4px 0; font-size:1.2rem; font-weight:700; color:#ffffff;">Upload Threat Intelligence Documents</h3>
        <p style="color:#94a3b8; font-size:0.85rem; margin-bottom:14px;">
            Extract text, compute SHA256 integrity, partition into overlapping chunks, and index dense 384-dimensional semantic vectors.
        </p>
        <div style="display:inline-flex; gap:12px; font-size:0.75rem; font-weight:600; color:#38bdf8; background:rgba(56,189,248,0.1); padding:4px 14px; border-radius:9999px; border:1px solid rgba(56,189,248,0.25);">
            <span>📕 PDF</span> • <span>📘 DOCX</span> • <span>📄 TXT</span> • <span>📊 CSV</span> • <span>Max 50MB</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    uploaded_files = st.file_uploader(
        "Upload files",
        type=["pdf", "docx", "doc", "txt", "md", "csv", "json", "log"],
        accept_multiple_files=True,
        label_visibility="collapsed",
        key="doc_file_uploader"
    )

    col_proc, col_samp = st.columns([3, 2])
    with col_proc:
        if uploaded_files:
            if st.button(f"⚡ Process & Index {len(uploaded_files)} File(s)", key="btn_process_uploads", type="primary", use_container_width=True):
                on_upload_files(uploaded_files)

    with col_samp:
        if st.button("📦 Load Sample Threat Advisory (APT29)", key="btn_load_samples_doc_page", use_container_width=True):
            on_load_samples()

    # Document Preview Modal / Expander if requested
    if selected_doc_preview:
        with st.expander(f"👁️ Viewing Artifact: {selected_doc_preview.get('filename')}", expanded=True):
            st.markdown(f"""
            <div style="display:flex; gap:16px; margin-bottom:12px; font-size:0.82rem; color:#94a3b8; flex-wrap:wrap;">
                <span>📄 Pages: <b>{selected_doc_preview.get('total_pages', 1)}</b></span>
                <span>🧩 Chunks: <b>{selected_doc_preview.get('chunk_count', 0)}</b></span>
                <span>🔤 Characters: <b>{selected_doc_preview.get('total_chars', 0):,}</b></span>
                <span>📝 Words: <b>{selected_doc_preview.get('total_words', 0):,}</b></span>
                <span>🔑 SHA256: <code class="mono-font" style="color:#38bdf8;">{selected_doc_preview.get('file_hash', 'N/A')[:16]}...</code></span>
            </div>
            """, unsafe_allow_html=True)
            
            st.text_area(
                "Extracted Text Content",
                selected_doc_preview.get("full_text", "No text content available."),
                height=260,
                disabled=True
            )

    st.markdown("<div style='margin:24px 0;'></div>", unsafe_allow_html=True)

    # Document Library Section
    st.markdown(f"""
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
        <h3 style="margin:0; font-size:1.15rem; font-weight:700; color:#f8fafc;">
            📚 Ingested Intelligence Repository ({len(doc_infos)} files indexed)
        </h3>
    </div>
    """, unsafe_allow_html=True)

    if not doc_infos:
        st.markdown("""
        <div class="modern-card" style="text-align:center; padding:36px 20px;">
            <div style="font-size:2.8rem; margin-bottom:10px;">📄</div>
            <h3 style="font-weight:700; color:#f8fafc; font-size:1.1rem; margin:0 0 6px 0;">Repository is empty</h3>
            <p style="font-size:0.85rem; color:#94a3b8; max-width:400px; margin:0 auto 16px auto;">
                Upload a threat intelligence document or click 'Load Sample Threat Advisory' above to begin.
            </p>
        </div>
        """, unsafe_allow_html=True)
    else:
        for doc in doc_infos:
            fname = doc.get("filename", "")
            fext = doc.get("file_ext", ".txt")
            fsize = format_file_size(doc.get("file_size", 0))
            fpages = doc.get("total_pages", 1)
            fchunks = doc.get("chunk_count", 0)
            fdate = doc.get("upload_date", "Recent")
            icon = get_file_icon(fext)

            c_info, c_chat, c_sum, c_view, c_del = st.columns([3.5, 1, 1, 1, 0.8])
            with c_info:
                st.markdown(f"""
                <div class="modern-card" style="padding:12px 16px; margin-bottom:8px;">
                    <div style="display:flex; align-items:center; gap:10px;">
                        <span style="font-size:1.4rem;">{icon}</span>
                        <div>
                            <div style="font-weight:700; font-size:0.92rem; color:#ffffff;">{fname}</div>
                            <div style="font-size:0.75rem; color:#94a3b8;">
                                {fsize} • {fpages} page(s) • {fchunks} vector chunks • Uploaded: {fdate}
                            </div>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            with c_chat:
                if st.button("💬 Q&A Chat", key=f"doc_chat_{fname[:14]}", use_container_width=True):
                    on_chat_doc(fname)
            with c_sum:
                if st.button("📝 Summarize", key=f"doc_sum_{fname[:14]}", use_container_width=True):
                    on_summarize_doc(fname)
            with c_view:
                if st.button("👁️ View Text", key=f"doc_view_{fname[:14]}", use_container_width=True):
                    on_open_doc(fname)
            with c_del:
                if st.button("🗑️", key=f"doc_del_{fname[:14]}", help=f"Delete {fname}", use_container_width=True):
                    on_delete_doc(fname)
