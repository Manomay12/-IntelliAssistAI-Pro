"""
SOC Operations Center Dashboard Page View for IntelAssist AI.
"""

from typing import Dict, Any, List, Callable, Optional
import streamlit as st
from components.metrics import render_soc_metric_grid
from utils.helpers import get_risk_badge_html, get_ioc_icon, get_file_icon

def render_dashboard(
    doc_infos: List[Dict[str, Any]],
    log_infos: List[Dict[str, Any]],
    extracted_iocs: List[Dict[str, Any]],
    critical_alerts: List[Dict[str, Any]],
    total_investigations: int,
    recent_activities: List[Dict[str, Any]],
    on_quick_ask: Callable[[str], None],
    on_investigate_ioc: Callable[[str], None],
    on_navigate: Callable[[str], None],
    on_open_doc: Callable[[str], None],
    on_summarize_doc: Callable[[str], None],
    on_chat_doc: Callable[[str], None],
    on_delete_doc: Callable[[str], None],
    on_load_demo_investigation: Callable[[], None]
):
    """Render the main Security Operations Center (SOC) dashboard."""
    # Top Hero Banner
    st.markdown("""
    <div class="hero-banner">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
            <div>
                <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
                    <span style="font-size:0.75rem; background:rgba(56,189,248,0.18); color:#38bdf8; padding:3px 10px; border-radius:9999px; border:1px solid rgba(56,189,248,0.4); font-weight:700;">
                        🟢 SOC ACTIVE DEFENSE MONITOR
                    </span>
                    <span style="font-size:0.75rem; color:#94a3b8;">• Evidence-Grounded AI Engine</span>
                </div>
                <h1 style="margin:0 0 6px 0; font-size:1.85rem; font-weight:800; color:#ffffff; letter-spacing:-0.02em;">
                    Security Operations & Threat Intelligence Center
                </h1>
                <p style="margin:0; color:#94a3b8; font-size:0.92rem; max-width:720px;">
                    Correlate threat advisories, forensic auth/firewall logs, and indicators of compromise with explainable risk scoring.
                </p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 1-Click Demo Banner for Hackathons
    c_demo_box, c_demo_btn = st.columns([4, 1.5])
    with c_demo_box:
        st.markdown("""
        <div style="background:rgba(2, 132, 199, 0.12); border:1px solid rgba(56, 189, 248, 0.3); border-radius:10px; padding:12px 16px; font-size:0.85rem; color:#cbd5e1; display:flex; align-items:center; gap:10px;">
            <span style="font-size:1.3rem;">⚡</span>
            <div>
                <b style="color:#ffffff;">Hackathon Evaluator Quick Load:</b> Ingest pre-configured APT29 threat advisory, SSH brute-force log, and firewall telemetry for an instant end-to-end investigation walkthrough.
            </div>
        </div>
        """, unsafe_allow_html=True)
    with c_demo_btn:
        st.markdown("<div style='margin-top:4px;'></div>", unsafe_allow_html=True)
        if st.button("⚡ Load Demo Investigation", key="dash_load_demo_btn", type="primary", use_container_width=True, help="Load and index sample APT29 advisory, auth.log, and firewall datasets"):
            on_load_demo_investigation()

    st.markdown("<div style='margin:16px 0;'></div>", unsafe_allow_html=True)

    # 6 SOC Metrics Grid
    high_risk_cnt = sum(1 for i in extracted_iocs if i.get("risk_level") in ["High", "Critical"])
    crit_alert_cnt = len(critical_alerts)
    render_soc_metric_grid(
        total_investigations=total_investigations,
        total_docs=len(doc_infos),
        total_logs=len(log_infos),
        total_iocs=len(extracted_iocs),
        high_risk_iocs=high_risk_cnt,
        critical_alerts=crit_alert_cnt
    )

    st.markdown("<div style='margin:22px 0;'></div>", unsafe_allow_html=True)

    # Quick Threat Query & Indicator Investigation Widget
    st.markdown("""
    <div class="modern-card" style="background:linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(11, 19, 37, 0.95) 100%); border-color:rgba(56, 189, 248, 0.35);">
        <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
            <span style="font-size:1.3rem;">🎯</span>
            <h3 style="margin:0; font-size:1.15rem; font-weight:700; color:#f8fafc;">Threat Indicator & Investigation Query</h3>
        </div>
        <p style="color:#94a3b8; font-size:0.85rem; margin-bottom:14px;">
            Enter an IP address, domain, file hash, CVE, or natural language query (e.g. <code style="color:#38bdf8;">185.220.101.5</code> or <code style="color:#38bdf8;">What attack techniques were used?</code>) to cross-correlate across all reports and logs.
        </p>
    </div>
    """, unsafe_allow_html=True)

    col_input, col_btn_investigate, col_btn_ask = st.columns([4.5, 1.2, 1.2])
    with col_input:
        quick_query = st.text_input(
            "Quick Indicator or Question",
            placeholder="e.g. 185.220.101.5, login-microsoft-secure.com, CVE-2023-38831, or 'Summarize the attack chain'",
            label_visibility="collapsed",
            key="dash_quick_ask_input"
        )
    with col_btn_investigate:
        if st.button("🎯 Investigate IOC", key="dash_btn_investigate", use_container_width=True):
            if quick_query.strip():
                on_investigate_ioc(quick_query.strip())
    with col_btn_ask:
        if st.button("🤖 Ask AI", key="dash_quick_ask_btn", type="primary", use_container_width=True):
            if quick_query.strip():
                on_quick_ask(quick_query.strip())

    st.markdown("<div style='margin:26px 0;'></div>", unsafe_allow_html=True)

    # Two Column Layout: Top Risk Indicators & Activity Feed
    col_iocs, col_act = st.columns([1.2, 1])

    with col_iocs:
        st.markdown("""
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
            <h3 style="margin:0; font-size:1.12rem; font-weight:700; color:#f8fafc;">🏷️ Top Risk Indicators (IOCs)</h3>
        </div>
        """, unsafe_allow_html=True)

        if not extracted_iocs:
            st.markdown("""
            <div class="modern-card" style="text-align:center; padding:28px 16px;">
                <div style="font-size:2.2rem; margin-bottom:8px;">🔍</div>
                <div style="font-weight:700; color:#f8fafc; font-size:0.95rem;">No indicators extracted yet</div>
                <p style="font-size:0.82rem; color:#94a3b8; margin:4px 0 14px 0;">
                    Upload threat advisories or click 'Load Demo Investigation' above to auto-extract IOCs.
                </p>
            </div>
            """, unsafe_allow_html=True)
        else:
            # Sort critical/high first
            priority_order = {"Critical": 4, "High": 3, "Elevated": 2, "Medium": 1, "Low": 0}
            sorted_iocs = sorted(extracted_iocs, key=lambda x: priority_order.get(x.get("risk_level", "Low"), 0), reverse=True)

            for ioc in sorted_iocs[:6]:
                ind = ioc.get("indicator", "")
                itype = ioc.get("type", "IOC")
                risk = ioc.get("risk_level", "Medium")
                ctx = ioc.get("context", "Observed Indicator")
                srcs = ", ".join(ioc.get("sources", ["Report"]))[:25]
                badge_html = get_risk_badge_html(risk)
                icon = get_ioc_icon(itype)

                c_card, c_act = st.columns([4, 1.2])
                with c_card:
                    st.markdown(f"""
                    <div class="modern-card" style="padding:10px 14px; margin-bottom:8px; display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <div style="display:flex; align-items:center; gap:8px;">
                                <span>{icon}</span>
                                <span class="mono-font" style="font-weight:700; color:#f8fafc; font-size:0.88rem;">{ind}</span>
                                <span style="font-size:0.7rem; color:#94a3b8;">({itype})</span>
                            </div>
                            <div style="font-size:0.74rem; color:#64748b; margin-top:2px;">
                                {ctx} • <span style="color:#38bdf8;">{srcs}</span>
                            </div>
                        </div>
                        <div>
                            {badge_html}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                with c_act:
                    if st.button("Inspect ➔", key=f"dash_inspect_{ind[:16]}", use_container_width=True):
                        on_investigate_ioc(ind)

            if len(extracted_iocs) > 6:
                if st.button(f"🔍 View All {len(extracted_iocs)} Extracted IOCs ➔", key="dash_view_all_iocs", use_container_width=True):
                    on_navigate("IOC Explorer")

    with col_act:
        st.markdown("""
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
            <h3 style="margin:0; font-size:1.12rem; font-weight:700; color:#f8fafc;">📋 SOC Activity & Telemetry Feed</h3>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""<div class="modern-card" style="padding:14px 18px; max-height:360px; overflow-y:auto;">""", unsafe_allow_html=True)
        
        if not recent_activities:
            st.markdown("<p style='font-size:0.82rem; color:#64748b;'>No activity logs recorded yet.</p>", unsafe_allow_html=True)
        else:
            for act in recent_activities[:7]:
                icon = act.get("icon", "⚡")
                title = act.get("title", "Event")
                t_str = act.get("time", "Just now")
                desc = act.get("desc", "")
                st.markdown(f"""
                <div class="activity-row">
                    <div style="font-size:1.1rem; width:24px; text-align:center;">{icon}</div>
                    <div style="flex:1;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <span style="font-weight:700; font-size:0.84rem; color:#f8fafc;">{title}</span>
                            <span style="font-size:0.7rem; color:#64748b;">{t_str}</span>
                        </div>
                        {f'<div style="font-size:0.75rem; color:#94a3b8; margin-top:2px;">{desc}</div>' if desc else ''}
                    </div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='margin:28px 0;'></div>", unsafe_allow_html=True)

    # Ingested Artifacts Section
    st.markdown(f"""
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
        <h3 style="margin:0; font-size:1.15rem; font-weight:700; color:#f8fafc;">
            📄 Ingested Threat Reports & Security Logs ({len(doc_infos)} files)
        </h3>
    </div>
    """, unsafe_allow_html=True)

    if not doc_infos:
        st.markdown("""
        <div class="modern-card" style="text-align:center; padding:32px 20px;">
            <div style="font-size:2.5rem; margin-bottom:10px;">📂</div>
            <div style="font-weight:700; font-size:1.05rem; color:#f8fafc; margin-bottom:6px;">No security artifacts indexed</div>
            <p style="font-size:0.85rem; color:#94a3b8; max-width:380px; margin:0 auto 16px auto;">
                Upload PDF threat reports, auth logs, or click 'Load Demo Investigation' above to populate the SOC database.
            </p>
        </div>
        """, unsafe_allow_html=True)
    else:
        for doc in doc_infos[:4]:
            fname = doc.get("filename", "")
            fext = doc.get("file_ext", ".txt")
            fpages = doc.get("total_pages", 1)
            fchunks = doc.get("chunk_count", 0)
            fdate = doc.get("upload_date", "Recent")
            icon = get_file_icon(fext)

            c_info, c_btn1, c_btn2, c_btn3 = st.columns([3, 1, 1, 1])
            with c_info:
                st.markdown(f"""
                <div class="modern-card" style="padding:12px 16px; margin-bottom:8px;">
                    <div style="display:flex; align-items:center; gap:10px;">
                        <span style="font-size:1.3rem;">{icon}</span>
                        <div>
                            <div style="font-weight:700; font-size:0.9rem; color:#ffffff;">{fname}</div>
                            <div style="font-size:0.75rem; color:#94a3b8;">
                                {fpages} page(s) • {fchunks} vectors • Uploaded: {fdate}
                            </div>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            with c_btn1:
                if st.button("💬 Q&A Chat", key=f"dash_chat_{fname[:14]}", use_container_width=True):
                    on_chat_doc(fname)
            with c_btn2:
                if st.button("📝 Summarize", key=f"dash_sum_{fname[:14]}", use_container_width=True):
                    on_summarize_doc(fname)
            with c_btn3:
                if st.button("👁️ View Text", key=f"dash_view_{fname[:14]}", use_container_width=True):
                    on_open_doc(fname)
