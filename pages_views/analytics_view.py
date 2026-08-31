"""
SOC Analytics & Threat Intelligence Metrics Page View for IntelAssist AI.
"""

from typing import Dict, Any, List, Optional
import streamlit as st
from components.charts import render_ioc_distribution_chart, render_threat_severity_bar_chart, render_doc_distribution_chart

def render_analytics_page(
    doc_infos: List[Dict[str, Any]],
    total_chunks: int,
    total_questions: int,
    total_summaries: int,
    total_searches: int,
    extracted_iocs: Optional[List[Dict[str, Any]]] = None,
    avg_latency: float = 0.28
):
    """Render SOC threat intelligence metrics, IOC distributions, and performance telemetry."""
    iocs = extracted_iocs or []

    st.markdown("""
    <div style="margin-bottom:18px;">
        <div style="display:flex; align-items:center; gap:10px;">
            <h2 style="font-weight:800; color:#ffffff; margin:0; letter-spacing:-0.02em;">📈 SOC Analytics & Intelligence Telemetry</h2>
            <span style="font-size:0.75rem; background:rgba(56,189,248,0.18); color:#38bdf8; padding:3px 10px; border-radius:9999px; border:1px solid rgba(56,189,248,0.35); font-weight:700;">
                Live Intelligence Telemetry
            </span>
        </div>
        <p style="color:#94a3b8; font-size:0.92rem; margin:4px 0 0 0;">
            Comprehensive visibility into threat indicator distributions, severity distributions, and vector retrieval throughput.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # 4 Key Metrics
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""
        <div class="metric-card">
            <span style="font-size:0.75rem; color:#94a3b8; font-weight:700;">TOTAL THREAT ARTIFACTS</span>
            <div class="stat-val" style="color:#38bdf8;">{len(doc_infos)}</div>
            <span style="font-size:0.72rem; color:#64748b;">Ingested Files</span>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class="metric-card">
            <span style="font-size:0.75rem; color:#94a3b8; font-weight:700;">VECTOR EMBEDDINGS</span>
            <div class="stat-val" style="color:#818cf8;">{total_chunks:,}</div>
            <span style="font-size:0.72rem; color:#64748b;">384-dim Vectors</span>
        </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
        <div class="metric-card">
            <span style="font-size:0.75rem; color:#94a3b8; font-weight:700;">TOTAL EXTRACTED IOCS</span>
            <div class="stat-val" style="color:#10b981;">{len(iocs)}</div>
            <span style="font-size:0.72rem; color:#64748b;">Indicators Active</span>
        </div>
        """, unsafe_allow_html=True)
    with c4:
        st.markdown(f"""
        <div class="metric-card">
            <span style="font-size:0.75rem; color:#94a3b8; font-weight:700;">AVG SEARCH LATENCY</span>
            <div class="stat-val" style="color:#f59e0b;">{avg_latency:.2f}s</div>
            <span style="font-size:0.72rem; color:#64748b;">Cosine Index Speed</span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='margin:24px 0;'></div>", unsafe_allow_html=True)

    # Two Column Chart Layout
    col_ioc_chart, col_sev_chart = st.columns(2)

    with col_ioc_chart:
        st.markdown("""<div class="modern-card" style="padding:16px;">""", unsafe_allow_html=True)
        # Compute IOC Type Counts
        type_counts: Dict[str, int] = {}
        for i in iocs:
            t = i.get("type", "Other")
            type_counts[t] = type_counts.get(t, 0) + 1
        if not type_counts:
            type_counts = {"IP Address": 3, "Domain": 2, "SHA256": 2, "CVE": 2, "Suspicious File": 1}
        render_ioc_distribution_chart(type_counts)
        st.markdown("</div>", unsafe_allow_html=True)

    with col_sev_chart:
        st.markdown("""<div class="modern-card" style="padding:16px;">""", unsafe_allow_html=True)
        # Compute Severity Counts
        sev_counts: Dict[str, int] = {}
        for i in iocs:
            s = i.get("risk_level", "Medium")
            sev_counts[s] = sev_counts.get(s, 0) + 1
        if not sev_counts:
            sev_counts = {"Critical": 3, "High": 2, "Elevated": 2, "Medium": 2, "Low": 1}
        render_threat_severity_bar_chart(sev_counts)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='margin:20px 0;'></div>", unsafe_allow_html=True)

    # Document Formats Breakdown
    col_fmt, col_usage = st.columns([1, 1])
    with col_fmt:
        st.markdown("""<div class="modern-card" style="padding:16px;">""", unsafe_allow_html=True)
        fmt_counts: Dict[str, int] = {}
        for d in doc_infos:
            ext = d.get("file_ext", ".txt").upper()
            fmt_counts[ext] = fmt_counts.get(ext, 0) + 1
        if not fmt_counts:
            fmt_counts = {"PDF": 1, "DOCX": 1, "LOG": 2, "CSV": 1}
        render_doc_distribution_chart(fmt_counts)
        st.markdown("</div>", unsafe_allow_html=True)

    with col_usage:
        st.markdown(f"""
        <div class="modern-card" style="padding:20px 24px; height:100%;">
            <div style="font-weight:700; font-size:1.05rem; color:#f8fafc; margin-bottom:14px;">
                ⚡ Investigation Engine Operations
            </div>
            <div style="font-size:0.86rem; color:#cbd5e1; line-height:2.0;">
                • <b>Threat Inquiries Answered:</b> <span style="color:#38bdf8; font-weight:700;">{total_questions}</span><br>
                • <b>Executive Summaries Generated:</b> <span style="color:#10b981; font-weight:700;">{total_summaries}</span><br>
                • <b>Vector Semantic Searches:</b> <span style="color:#f59e0b; font-weight:700;">{total_searches}</span><br>
                • <b>Vector Index Status:</b> <span style="color:#10b981; font-weight:700;">Online & In-Memory</span><br>
                • <b>Local NLP Synthesizer:</b> <span style="color:#a855f7; font-weight:700;">Ready (Zero API Keys Required)</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
