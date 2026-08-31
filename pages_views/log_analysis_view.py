"""
Forensic Log Analysis & Attack Detection Page View for IntelAssist AI.
"""

from typing import Dict, Any, List, Callable, Optional
import streamlit as st
from components.charts import render_timeline_activity_chart, render_risk_gauge_chart
from utils.helpers import get_risk_badge_html

def render_log_analysis_page(
    log_data_list: List[Dict[str, Any]],
    on_upload_log: Callable[[List[Any]], None],
    on_investigate_ip: Callable[[str], None]
):
    """Render the Forensic Log Analysis and Attack Detection workspace."""
    st.markdown("""
    <div style="margin-bottom:18px;">
        <div style="display:flex; align-items:center; gap:10px;">
            <h2 style="font-weight:800; color:#ffffff; margin:0; letter-spacing:-0.02em;">📋 Forensic Log Analysis & Attack Detection</h2>
            <span style="font-size:0.75rem; background:rgba(239,68,68,0.18); color:#ef4444; padding:3px 10px; border-radius:9999px; border:1px solid rgba(239,68,68,0.35); font-weight:700;">
                Forensic Rule Engine
            </span>
        </div>
        <p style="color:#94a3b8; font-size:0.92rem; margin:4px 0 0 0;">
            Upload Linux auth.log, firewall traffic logs, Nginx/Apache web access logs, or CSV security events to detect brute-force attacks, port scans, web injection, and privilege escalation.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Central Upload Card
    st.markdown("""
    <div class="modern-card" style="border: 2px dashed rgba(56, 189, 248, 0.4); text-align:center; padding:24px 20px; margin-bottom:18px;">
        <div style="font-size:2.2rem; margin-bottom:6px;">📤</div>
        <h3 style="margin:0 0 4px 0; font-size:1.18rem; font-weight:700; color:#ffffff;">Upload Security & System Logs</h3>
        <p style="color:#94a3b8; font-size:0.85rem; margin-bottom:12px;">
            Drop auth.log, iptables/firewall logs, web access logs, or CSV security events for instant heuristic pattern analysis.
        </p>
    </div>
    """, unsafe_allow_html=True)

    uploaded_logs = st.file_uploader(
        "Upload logs",
        type=["log", "txt", "csv", "json"],
        accept_multiple_files=True,
        label_visibility="collapsed",
        key="log_file_uploader"
    )

    if uploaded_logs:
        if st.button(f"⚡ Ingest & Analyze {len(uploaded_logs)} Log File(s)", key="btn_process_logs", type="primary", use_container_width=True):
            on_upload_log(uploaded_logs)

    if not log_data_list:
        st.markdown("""
        <div class="modern-card" style="text-align:center; padding:36px 20px; margin-top:16px;">
            <div style="font-size:2.8rem; margin-bottom:10px;">📋</div>
            <h3 style="font-weight:700; color:#f8fafc; font-size:1.15rem; margin:0 0 6px 0;">No Security Logs Ingested Yet</h3>
            <p style="font-size:0.85rem; color:#94a3b8; max-width:420px; margin:0 auto;">
                Upload your log files above or click 'Load Demo Investigation' on the Dashboard to inspect realistic SSH brute-force and firewall attack datasets.
            </p>
        </div>
        """, unsafe_allow_html=True)
        return

    # Select Active Log if multiple
    log_names = [l.get("filename", "Log") for l in log_data_list]
    selected_log_name = st.selectbox("Select Log Stream", log_names, key="select_active_log")
    active_log = next((l for l in log_data_list if l.get("filename") == selected_log_name), log_data_list[0])

    st.markdown("<div style='margin:18px 0;'></div>", unsafe_allow_html=True)

    # 5 Key Forensic Metrics Grid
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    with c1:
        st.markdown(f"""
        <div class="metric-card">
            <span style="font-size:0.75rem; color:#94a3b8; font-weight:700;">TOTAL EVENTS</span>
            <div class="stat-val" style="color:#38bdf8;">{active_log.get('total_events', 0):,}</div>
            <span style="font-size:0.72rem; color:#64748b;">Parsed lines</span>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class="metric-card">
            <span style="font-size:0.75rem; color:#94a3b8; font-weight:700;">SUSPICIOUS EVENTS</span>
            <div class="stat-val" style="color:#f59e0b;">{active_log.get('suspicious_events', 0)}</div>
            <span style="font-size:0.72rem; color:#64748b;">Flagged telemetry</span>
        </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
        <div class="metric-card">
            <span style="font-size:0.75rem; color:#94a3b8; font-weight:700;">CRITICAL ALERTS</span>
            <div class="stat-val" style="color:#ef4444;">{active_log.get('critical_alerts', 0)}</div>
            <span style="font-size:0.72rem; color:#64748b;">Action required</span>
        </div>
        """, unsafe_allow_html=True)
    with c4:
        st.markdown(f"""
        <div class="metric-card">
            <span style="font-size:0.75rem; color:#94a3b8; font-weight:700;">UNIQUE IPS</span>
            <div class="stat-val" style="color:#10b981;">{active_log.get('unique_ips', 0)}</div>
            <span style="font-size:0.72rem; color:#64748b;">Observed hosts</span>
        </div>
        """, unsafe_allow_html=True)
    with c5:
        st.markdown(f"""
        <div class="metric-card">
            <span style="font-size:0.75rem; color:#94a3b8; font-weight:700;">FAILED LOGINS</span>
            <div class="stat-val" style="color:#f97316;">{active_log.get('failed_logins', 0)}</div>
            <span style="font-size:0.72rem; color:#64748b;">Auth attempts</span>
        </div>
        """, unsafe_allow_html=True)
    with c6:
        r_score = active_log.get('risk_score', 0)
        r_col = "#ef4444" if r_score >= 80 else "#f59e0b" if r_score >= 40 else "#10b981"
        st.markdown(f"""
        <div class="metric-card">
            <span style="font-size:0.75rem; color:#94a3b8; font-weight:700;">RISK SCORE</span>
            <div class="stat-val" style="color:{r_col};">{r_score}/100</div>
            <span style="font-size:0.72rem; color:#64748b;">Heuristic score</span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='margin:24px 0;'></div>", unsafe_allow_html=True)

    # Correlated Detection Alerts
    st.markdown("""
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
        <h3 style="margin:0; font-size:1.15rem; font-weight:700; color:#f8fafc;">🚨 Heuristic Attack Detections & Alerts</h3>
        <span style="font-size:0.75rem; color:#94a3b8;">Explainable Rule Engine</span>
    </div>
    """, unsafe_allow_html=True)

    alerts = active_log.get("alerts", [])
    if not alerts:
        st.markdown("""
        <div class="modern-card" style="padding:16px; text-align:center; color:#10b981;">
            ✓ No critical security alerts triggered for this log stream.
        </div>
        """, unsafe_allow_html=True)
    else:
        for idx, alert in enumerate(alerts):
            sev = alert.get("severity", "High")
            card_class = "alert-card-critical" if sev == "Critical" else "alert-card-high" if sev == "High" else "alert-card-elevated"
            badge = get_risk_badge_html(sev)
            src_ip = alert.get("source_ip", "Unknown")

            st.markdown(f"""
            <div class="{card_class}">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span style="font-size:1.15rem;">🚨</span>
                        <b style="font-size:1.02rem; color:#ffffff;">{alert.get('title')}</b>
                    </div>
                    <div>{badge}</div>
                </div>
                <div style="font-size:0.84rem; color:#cbd5e1; line-height:1.7; margin-bottom:10px;">
                    <b>Source IP:</b> <code style="color:#38bdf8;">{src_ip}</code> • 
                    <b>Target Service:</b> {alert.get('target_service')} • 
                    <b>Failed Attempts / Count:</b> <b style="color:#f59e0b;">{alert.get('failed_attempts', 0)}</b><br>
                    <b>Evidence / Reason:</b> {alert.get('reason')}<br>
                    <b>Possible MITRE ATT&CK Mapping:</b> <code style="color:#a855f7;">{alert.get('mitre_technique', 'T1110')}</code>
                </div>
                <div style="font-size:0.82rem; background:rgba(0,0,0,0.35); padding:8px 12px; border-radius:6px; color:#f8fafc; border:1px solid rgba(255,255,255,0.08);">
                    🛡️ <b>Recommended SOC Action:</b> {alert.get('recommended_action')}
                </div>
            </div>
            """, unsafe_allow_html=True)

            if src_ip and src_ip != "127.0.0.1 (Local Host)":
                if st.button(f"🎯 Investigate Source IP '{src_ip}' ➔", key=f"btn_inv_alert_{idx}"):
                    on_investigate_ip(src_ip)

    st.markdown("<div style='margin:24px 0;'></div>", unsafe_allow_html=True)

    # Suspicious Activity Timeline Density
    timeline_data = active_log.get("timeline", [])
    if timeline_data:
        render_timeline_activity_chart(timeline_data)

    st.markdown("<div style='margin:24px 0;'></div>", unsafe_allow_html=True)

    # Raw Log Inspector with Filter
    with st.expander(f"🔍 Raw Security Events ({len(active_log.get('events', []))} events parsed)", expanded=False):
        raw_filter = st.text_input("Filter Raw Events", placeholder="Search by IP, user, error, port...", key="raw_log_filter")
        events_list = active_log.get("events", [])
        if raw_filter.strip():
            rf = raw_filter.strip().lower()
            events_list = [e for e in events_list if rf in str(e).lower()]

        for e in events_list[:80]:
            sev_badge = get_risk_badge_html(e.get("severity", "Low"))
            st.markdown(f"""
            <div style="padding:6px 10px; border-bottom:1px solid rgba(255,255,255,0.06); display:flex; justify-content:space-between; align-items:center; font-size:0.8rem;">
                <div style="display:flex; align-items:center; gap:10px;">
                    <span class="mono-font" style="color:#64748b;">[{e.get('timestamp', 'N/A')}]</span>
                    <span style="font-weight:700; color:#ffffff;">{e.get('event_type')}</span>
                    <span style="color:#cbd5e1;">{e.get('description')}</span>
                </div>
                <div>{sev_badge}</div>
            </div>
            """, unsafe_allow_html=True)
