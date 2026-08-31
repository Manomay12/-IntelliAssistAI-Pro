"""
Threat Investigation & Indicator Correlation Page View for IntelAssist AI.
"""

from typing import Dict, Any, List, Callable, Optional
import streamlit as st
from services.threat_correlator import ThreatCorrelator
from services.risk_engine import RiskEngine
from services.mitre_mapper import MITREMapper
from components.charts import render_risk_gauge_chart
from utils.helpers import get_risk_badge_html, get_ioc_icon

SAMPLE_INDICATORS = [
    "185.220.101.5",
    "login-microsoft-secure.com",
    "cdn-update-service.org",
    "CVE-2023-38831",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "mimikatz.exe"
]

def render_investigation_page(
    document_registry: Dict[str, Any],
    log_results: List[Dict[str, Any]],
    all_extracted_iocs: List[Dict[str, Any]],
    on_ask_ai_about_indicator: Callable[[str], None],
    initial_target: Optional[str] = None
):
    """Render the Threat Investigation & Cross-Source Correlation workspace."""
    st.markdown("""
    <div style="margin-bottom:18px;">
        <div style="display:flex; align-items:center; gap:10px;">
            <h2 style="font-weight:800; color:#ffffff; margin:0; letter-spacing:-0.02em;">🎯 Threat Investigation & Cross-Source Correlation</h2>
            <span style="font-size:0.75rem; background:rgba(2,132,199,0.2); color:#38bdf8; padding:3px 10px; border-radius:9999px; border:1px solid rgba(56,189,248,0.35); font-weight:700;">
                Multi-Artifact Correlator
            </span>
        </div>
        <p style="color:#94a3b8; font-size:0.92rem; margin:4px 0 0 0;">
            Deep-dive into any IP address, domain, file hash, URL, or CVE to uncover cross-document links, log telemetry, risk factors, and entity relationship graphs.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Indicator Search Bar
    default_val = initial_target or ""
    col_inp, col_btn = st.columns([4.5, 1.2])
    with col_inp:
        target_input = st.text_input(
            "Target Indicator to Investigate",
            value=default_val,
            placeholder="Enter IP, Domain, URL, Hash, or CVE (e.g. 185.220.101.5)",
            key="investigation_target_input"
        )
    with col_btn:
        st.markdown("<div style='margin-top:28px;'></div>", unsafe_allow_html=True)
        investigate_clicked = st.button("🚀 Investigate", type="primary", use_container_width=True, key="btn_run_investigation")

    # Quick Samples Chips
    st.markdown("<div style='display:flex; align-items:center; gap:8px; margin:4px 0 18px 0; font-size:0.8rem; color:#94a3b8;'><span>Quick Samples:</span></div>", unsafe_allow_html=True)
    chip_cols = st.columns(len(SAMPLE_INDICATORS))
    for idx, sample in enumerate(SAMPLE_INDICATORS):
        with chip_cols[idx]:
            if st.button(sample[:18], key=f"chip_sample_{idx}", help=f"Investigate {sample}", use_container_width=True):
                target_input = sample
                investigate_clicked = True

    target_to_use = target_input.strip()

    if not target_to_use:
        st.markdown("""
        <div class="modern-card" style="text-align:center; padding:44px 20px;">
            <div style="font-size:3.2rem; margin-bottom:12px;">🎯</div>
            <h3 style="font-weight:700; color:#f8fafc; font-size:1.2rem; margin:0 0 6px 0;">Enter an Indicator of Compromise to Begin</h3>
            <p style="font-size:0.88rem; color:#94a3b8; max-width:480px; margin:0 auto 16px auto;">
                IntelAssist cross-correlates your query across all indexed threat intelligence reports, authentication logs, and firewall traffic to establish an evidence chain.
            </p>
        </div>
        """, unsafe_allow_html=True)
        return

    # Execute Correlation
    with st.spinner(f"Correlating '{target_to_use}' across threat reports, security logs, and vector database..."):
        correlation_data = ThreatCorrelator.correlate_indicator(
            target_indicator=target_to_use,
            document_registry=document_registry,
            log_results=log_results,
            all_extracted_iocs=all_extracted_iocs
        )

        # Detect IOC Type
        ioc_type = "IP Address" if any(c.isdigit() for c in target_to_use) and "." in target_to_use else "Indicator"
        if "cve-" in target_to_use.lower():
            ioc_type = "CVE"
        elif len(target_to_use) == 64 and all(c in "0123456789abcdefABCDEF" for c in target_to_use):
            ioc_type = "SHA256"
        elif "http" in target_to_use.lower() or "/" in target_to_use:
            ioc_type = "URL"
        elif ".com" in target_to_use.lower() or ".org" in target_to_use.lower():
            ioc_type = "Domain"
        elif any(target_to_use.lower().endswith(ext) for ext in [".exe", ".dll", ".sh", ".php", ".py"]):
            ioc_type = "Suspicious File"

        # Calculate Explainable Risk Score
        risk_data = RiskEngine.calculate_indicator_risk(
            indicator=target_to_use,
            ioc_type=ioc_type,
            matched_docs=correlation_data.get("matched_docs", []),
            matched_logs=correlation_data.get("matched_logs", []),
            contexts=correlation_data.get("contexts", [])
        )

    # 1. Investigation Summary Card & Risk Meter
    col_summary, col_gauge = st.columns([1.5, 1])

    with col_summary:
        badge_html = get_risk_badge_html(risk_data["level"])
        icon = get_ioc_icon(ioc_type)
        total_sources = len(correlation_data.get("matched_docs", [])) + len(correlation_data.get("matched_logs", []))

        st.markdown(f"""
        <div class="modern-card" style="border-left:5px solid {risk_data['color']}; padding:20px 24px; height:100%;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="font-size:1.5rem;">{icon}</span>
                    <span class="mono-font" style="font-size:1.25rem; font-weight:800; color:#ffffff;">{target_to_use}</span>
                </div>
                <div>{badge_html}</div>
            </div>
            <div style="font-size:0.85rem; color:#cbd5e1; line-height:1.8; margin-bottom:14px;">
                <b>Type:</b> {ioc_type} • <b>Correlated Sources:</b> <span style="color:#38bdf8; font-weight:700;">{total_sources} file(s)</span><br>
                <b>Investigation Status:</b> <span style="color:#10b981; font-weight:700;">Active Correlation Complete</span> • <b>Confidence:</b> {risk_data['confidence']}
            </div>
            <div style="font-size:0.82rem; color:#94a3b8; background:rgba(0,0,0,0.3); padding:10px 14px; border-radius:8px; border:1px solid rgba(255,255,255,0.06);">
                💡 <b>Analyst Context:</b> {correlation_data['contexts'][0] if correlation_data.get('contexts') else 'No direct context snippet recorded in database.'}
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col_gauge:
        st.markdown("""<div class="modern-card" style="padding:10px; height:100%;">""", unsafe_allow_html=True)
        render_risk_gauge_chart(risk_data["score"], title="Indicator Risk Score")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='margin:20px 0;'></div>", unsafe_allow_html=True)

    # 2. Explainable Factor Breakdown Card
    with st.expander("🔍 Explainable Risk Score Breakdown (Why this score?)", expanded=True):
        st.markdown(f"""
        <div style="font-size:0.88rem; color:#cbd5e1; margin-bottom:10px;">
            Calculated Risk Score: <b style="color:{risk_data['color']}; font-size:1rem;">{risk_data['score']}/100 ({risk_data['level']})</b>
        </div>
        """, unsafe_allow_html=True)
        for item in risk_data.get("breakdown", []):
            st.markdown(f"""
            <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid rgba(255,255,255,0.06); font-size:0.82rem;">
                <span style="color:#f8fafc;">• {item['factor']}</span>
                <span class="mono-font" style="color:#10b981; font-weight:700;">+{item['points']} pts</span>
            </div>
            """, unsafe_allow_html=True)
        st.markdown(f"<div style='font-size:0.75rem; color:#64748b; margin-top:8px;'>{risk_data['disclaimer']}</div>", unsafe_allow_html=True)

    st.markdown("<div style='margin:20px 0;'></div>", unsafe_allow_html=True)

    # 3. Interactive Relationship Graph
    st.markdown("""
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
        <h3 style="margin:0; font-size:1.15rem; font-weight:700; color:#f8fafc;">🕸️ Entity Relationship Network</h3>
        <span style="font-size:0.75rem; color:#94a3b8;">Interactive Plotly Visual Graph</span>
    </div>
    """, unsafe_allow_html=True)

    fig = ThreatCorrelator.generate_relationship_graph(target_to_use, correlation_data)
    st.plotly_chart(fig, use_container_width=True)

    st.markdown("<div style='margin:20px 0;'></div>", unsafe_allow_html=True)

    # 4. Correlation Tabs: Reports, Logs, Linked IOCs
    tab_reports, tab_logs, tab_linked = st.tabs([
        f"📄 Threat Reports ({len(correlation_data.get('matched_docs', []))})",
        f"📋 Security Logs ({len(correlation_data.get('matched_logs', []))})",
        f"🏷️ Co-occurring Indicators ({len(correlation_data.get('co_occurring_iocs', []))})"
    ])

    with tab_reports:
        matched_docs = correlation_data.get("matched_docs", [])
        if not matched_docs:
            st.info("No matching threat reports or documents found for this indicator.")
        else:
            for doc in matched_docs:
                st.markdown(f"""
                <div class="modern-card" style="margin-bottom:10px; border-left:4px solid #38bdf8;">
                    <div style="font-weight:700; color:#ffffff; font-size:0.95rem; margin-bottom:4px;">
                        📄 {doc['filename']}
                    </div>
                    <div style="font-size:0.85rem; color:#cbd5e1; line-height:1.6; background:rgba(0,0,0,0.25); padding:10px 12px; border-radius:6px;">
                        "...{doc['snippet']}..."
                    </div>
                </div>
                """, unsafe_allow_html=True)

    with tab_logs:
        matched_logs = correlation_data.get("matched_logs", [])
        if not matched_logs:
            st.info("No matching security log events recorded for this indicator.")
        else:
            for log in matched_logs:
                st.markdown(f"""
                <div class="modern-card" style="margin-bottom:10px; border-left:4px solid #f59e0b;">
                    <div style="font-weight:700; color:#ffffff; font-size:0.95rem; margin-bottom:4px;">
                        📋 {log['filename']} • <span style="color:#f59e0b;">{log['event_count']} matching event(s)</span>
                    </div>
                    <div style="font-size:0.82rem; color:#cbd5e1; line-height:1.6;">
                        First Event: <code>{log['first_event']}</code>
                    </div>
                </div>
                """, unsafe_allow_html=True)

    with tab_linked:
        co_iocs = correlation_data.get("co_occurring_iocs", [])
        if not co_iocs:
            st.info("No co-occurring indicators linked in current documents.")
        else:
            for ioc in co_iocs:
                rb = get_risk_badge_html(ioc.get("risk_level", "Medium"))
                st.markdown(f"""
                <div class="modern-card" style="padding:10px 14px; margin-bottom:8px; display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="mono-font" style="font-weight:700; color:#ffffff; font-size:0.88rem;">{ioc['indicator']}</span>
                        <span style="font-size:0.75rem; color:#94a3b8; margin-left:8px;">({ioc['type']})</span>
                    </div>
                    <div>{rb}</div>
                </div>
                """, unsafe_allow_html=True)

    st.markdown("<div style='margin:24px 0;'></div>", unsafe_allow_html=True)

    # 5. Quick AI Investigation Action
    st.markdown("""
    <div class="modern-card" style="background:linear-gradient(135deg, rgba(2, 132, 199, 0.15) 0%, rgba(15, 23, 42, 0.9) 100%); border-color:rgba(56, 189, 248, 0.35);">
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h4 style="margin:0 0 4px 0; color:#ffffff; font-size:1.05rem;">🤖 Ask AI Investigation Assistant About This Indicator</h4>
                <p style="margin:0; font-size:0.84rem; color:#94a3b8;">
                    Launch full evidence-based investigation report into this indicator with timeline, attack chain, and recommended mitigation actions.
                </p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    if st.button(f"🚀 Generate AI Investigation Report on '{target_to_use}' ➔", type="primary", use_container_width=True, key="btn_ask_ai_investigate"):
        on_ask_ai_about_indicator(f"Investigate indicator {target_to_use}. What threats, logs, attack flows, and mitigations are associated with it?")
