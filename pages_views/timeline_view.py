"""
Attack & Forensic Event Timeline Page View for IntelAssist AI.
"""

from typing import Dict, Any, List, Optional
import streamlit as st
from utils.helpers import get_risk_badge_html

def render_attack_timeline_page(
    log_data_list: List[Dict[str, Any]],
    document_registry: Dict[str, Any]
):
    """Render the chronological Attack & Event Timeline workspace."""
    st.markdown("""
    <div style="margin-bottom:18px;">
        <div style="display:flex; align-items:center; gap:10px;">
            <h2 style="font-weight:800; color:#ffffff; margin:0; letter-spacing:-0.02em;">⏱️ Attack & Forensic Event Timeline</h2>
            <span style="font-size:0.75rem; background:rgba(56,189,248,0.18); color:#38bdf8; padding:3px 10px; border-radius:9999px; border:1px solid rgba(56,189,248,0.35); font-weight:700;">
                Chronological Correlation
            </span>
        </div>
        <p style="color:#94a3b8; font-size:0.92rem; margin:4px 0 0 0;">
            Reconstructed chronological sequence of security events, reconnaissance probes, authentication attempts, privilege changes, and threat intelligence milestones.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Gather all timeline points across logs
    all_events: List[Dict[str, Any]] = []
    for log_data in log_data_list:
        fname = log_data.get("filename", "Log")
        events = log_data.get("events", [])
        for e in events:
            all_events.append({
                "time": e.get("timestamp", "N/A"),
                "event_type": e.get("event_type", "Security Event"),
                "severity": e.get("severity", "Medium"),
                "source_ip": e.get("source_ip", "Unknown"),
                "description": e.get("description", ""),
                "source_file": fname,
                "raw": e.get("raw", "")
            })

    if not all_events:
        st.markdown("""
        <div class="modern-card" style="text-align:center; padding:40px 20px;">
            <div style="font-size:3rem; margin-bottom:10px;">⏱️</div>
            <h3 style="font-weight:700; color:#f8fafc; font-size:1.15rem; margin:0 0 6px 0;">No Timeline Events Recorded</h3>
            <p style="font-size:0.85rem; color:#94a3b8; max-width:440px; margin:0 auto;">
                Upload authentication logs, firewall logs, or click 'Load Demo Investigation' on the Dashboard to populate the attack timeline.
            </p>
        </div>
        """, unsafe_allow_html=True)
        return

    # Filter Controls
    col_sev, col_type, col_src = st.columns(3)
    with col_sev:
        selected_sev = st.selectbox("Filter by Severity", ["All Severities", "Critical", "High", "Elevated", "Medium", "Low"], key="timeline_sev_filter")
    with col_type:
        types = sorted(list(set(e["event_type"] for e in all_events)))
        selected_type = st.selectbox("Filter by Event Type", ["All Event Types"] + types, key="timeline_type_filter")
    with col_src:
        srcs = sorted(list(set(e["source_file"] for e in all_events)))
        selected_src = st.selectbox("Filter by Source File", ["All Files"] + srcs, key="timeline_src_filter")

    # Apply Filters
    filtered_events = all_events
    if selected_sev != "All Severities":
        filtered_events = [e for e in filtered_events if e["severity"] == selected_sev]
    if selected_type != "All Event Types":
        filtered_events = [e for e in filtered_events if e["event_type"] == selected_type]
    if selected_src != "All Files":
        filtered_events = [e for e in filtered_events if e["source_file"] == selected_src]

    st.markdown(f"""
    <div style="font-size:0.85rem; color:#94a3b8; margin:12px 0 16px 0;">
        Displaying <b style="color:#f8fafc;">{len(filtered_events)}</b> chronological event milestone(s)
    </div>
    """, unsafe_allow_html=True)

    # Timeline Cards Render
    for idx, event in enumerate(filtered_events[:60]):
        sev = event["severity"]
        border_color = "#ef4444" if sev == "Critical" else "#f97316" if sev == "High" else "#f59e0b" if sev == "Elevated" else "#38bdf8"
        badge_html = get_risk_badge_html(sev)

        # Infer possible MITRE tag
        mitre_tag = ""
        et_lower = event["event_type"].lower()
        if "brute force" in et_lower or "failed login" in et_lower:
            mitre_tag = "T1110 (Brute Force)"
        elif "privilege escalation" in et_lower:
            mitre_tag = "T1548 (Abuse Elevation)"
        elif "successful login" in et_lower:
            mitre_tag = "T1078 (Valid Accounts)"
        elif "web attack" in et_lower or "sql" in et_lower:
            mitre_tag = "T1190 (Exploit Public-Facing App)"
        elif "firewall" in et_lower:
            mitre_tag = "T1046 (Network Scanning)"

        st.markdown(f"""
        <div class="timeline-card" style="border-left-color:{border_color}; margin-bottom:12px; padding:14px 18px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                <div style="display:flex; align-items:center; gap:10px;">
                    <span class="mono-font" style="font-size:0.85rem; font-weight:700; color:#38bdf8; background:rgba(56,189,248,0.12); padding:2px 8px; border-radius:4px;">
                        ⏱️ {event['time']}
                    </span>
                    <b style="font-size:0.95rem; color:#ffffff;">{event['event_type']}</b>
                </div>
                <div>{badge_html}</div>
            </div>
            <div style="font-size:0.86rem; color:#cbd5e1; margin-bottom:6px; line-height:1.6;">
                {event['description']}
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.75rem; color:#64748b;">
                <span>Source: <b style="color:#94a3b8;">{event['source_file']}</b> • IP: <code style="color:#38bdf8;">{event['source_ip']}</code></span>
                {f'<span style="color:#a855f7; font-weight:600;">{mitre_tag}</span>' if mitre_tag else ''}
            </div>
        </div>
        """, unsafe_allow_html=True)
