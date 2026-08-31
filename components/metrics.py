"""
SOC Metric and Stat Card Components for IntelAssist AI.
"""

from typing import Any
import streamlit as st

def render_metric_card(label: str, value: Any, icon: str, delta: str = "", subtitle: str = "", color: str = "#38bdf8"):
    """Render a modern SOC Cyber metric tile."""
    st.markdown(f"""
    <div class="metric-card">
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <span style="font-size:0.8rem; font-weight:700; text-transform:uppercase; letter-spacing:0.04em; color:#94a3b8;">{label}</span>
            <span style="font-size:1.3rem;">{icon}</span>
        </div>
        <div class="stat-val" style="color:{color};">{value}</div>
        <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.75rem; color:#94a3b8;">
            <span>{subtitle}</span>
            {f'<span style="color:{color}; font-weight:700;">{delta}</span>' if delta else ''}
        </div>
    </div>
    """, unsafe_allow_html=True)

def render_soc_metric_grid(
    total_investigations: int,
    total_docs: int,
    total_logs: int,
    total_iocs: int,
    high_risk_iocs: int,
    critical_alerts: int
):
    """Render the 6-metric Security Operations Center grid."""
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    with col1:
        render_metric_card("Investigations", total_investigations, "🎯", "Active", "Cases Managed", "#38bdf8")
    with col2:
        render_metric_card("Threat Reports", total_docs, "📄", "Indexed", "Advisories & PDFs", "#38bdf8")
    with col3:
        render_metric_card("Logs Analyzed", total_logs, "📋", "Parsed", "Auth & Firewalls", "#a855f7")
    with col4:
        render_metric_card("Extracted IOCs", total_iocs, "🏷️", "Correlated", "IPs, Hashes, CVEs", "#10b981")
    with col5:
        render_metric_card("High-Risk IOCs", high_risk_iocs, "⚠️", "Elevated", "Threat Indicators", "#f59e0b" if high_risk_iocs > 0 else "#64748b")
    with col6:
        render_metric_card("Critical Alerts", critical_alerts, "🚨", "Immediate", "SOC Detections", "#ef4444" if critical_alerts > 0 else "#10b981")
