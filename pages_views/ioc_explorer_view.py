"""
Indicators of Compromise (IOC) Explorer Page View for IntelAssist AI.
"""

from typing import Dict, Any, List, Callable, Optional
import streamlit as st
import pandas as pd
import json
from utils.helpers import get_risk_badge_html, get_ioc_icon

def render_ioc_explorer_page(
    all_extracted_iocs: List[Dict[str, Any]],
    on_investigate_ioc: Callable[[str], None]
):
    """Render the comprehensive interactive IOC Explorer table and export workspace."""
    st.markdown("""
    <div style="margin-bottom:18px;">
        <div style="display:flex; align-items:center; gap:10px;">
            <h2 style="font-weight:800; color:#ffffff; margin:0; letter-spacing:-0.02em;">🏷️ Indicators of Compromise (IOC) Explorer</h2>
            <span style="font-size:0.75rem; background:rgba(16,185,129,0.15); color:#10b981; padding:3px 10px; border-radius:9999px; border:1px solid rgba(16,185,129,0.3); font-weight:700;">
                Automated Extraction Engine
            </span>
        </div>
        <p style="color:#94a3b8; font-size:0.92rem; margin:4px 0 0 0;">
            Extracted network artifacts, cryptographic hashes, vulnerability identifiers, and tool signatures across all ingested reports and logs.
        </p>
    </div>
    """, unsafe_allow_html=True)

    if not all_extracted_iocs:
        st.markdown("""
        <div class="modern-card" style="text-align:center; padding:40px 20px;">
            <div style="font-size:3rem; margin-bottom:12px;">🏷️</div>
            <h3 style="font-weight:700; color:#f8fafc; font-size:1.15rem; margin:0 0 6px 0;">No Indicators Extracted Yet</h3>
            <p style="font-size:0.88rem; color:#94a3b8; max-width:440px; margin:0 auto;">
                Upload threat intelligence reports or security logs to automatically populate the IOC database.
            </p>
        </div>
        """, unsafe_allow_html=True)
        return

    # Filter Controls
    col_search, col_type, col_risk = st.columns([3, 2, 2])
    with col_search:
        search_kw = st.text_input("🔍 Search Indicators", placeholder="Filter by IP, domain, hash, or context...", key="ioc_search_filter")
    with col_type:
        all_types = sorted(list(set(i.get("type", "Other") for i in all_extracted_iocs)))
        selected_type = st.selectbox("Filter by Type", ["All Types"] + all_types, key="ioc_type_filter")
    with col_risk:
        selected_risk = st.selectbox("Filter by Risk Level", ["All Risk Levels", "Critical", "High", "Elevated", "Medium", "Low"], key="ioc_risk_filter")

    # Apply Filters
    filtered = all_extracted_iocs
    if search_kw.strip():
        kw = search_kw.strip().lower()
        filtered = [i for i in filtered if kw in i.get("indicator", "").lower() or kw in i.get("context", "").lower() or kw in str(i.get("sources", "")).lower()]

    if selected_type != "All Types":
        filtered = [i for i in filtered if i.get("type") == selected_type]

    if selected_risk != "All Risk Levels":
        filtered = [i for i in filtered if i.get("risk_level") == selected_risk]

    # Metrics Summary Row
    total_cnt = len(filtered)
    crit_cnt = sum(1 for i in filtered if i.get("risk_level") == "Critical")
    high_cnt = sum(1 for i in filtered if i.get("risk_level") == "High")
    
    st.markdown(f"""
    <div style="display:flex; justify-content:space-between; align-items:center; margin:12px 0; font-size:0.85rem; color:#94a3b8;">
        <div>
            Showing <b style="color:#f8fafc;">{total_cnt}</b> indicator(s) • <span style="color:#ef4444; font-weight:700;">{crit_cnt} Critical</span> • <span style="color:#f97316; font-weight:700;">{high_cnt} High</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Interactive Table Layout
    st.markdown("""
    <div style="background:rgba(15, 23, 42, 0.75); border:1px solid rgba(56, 189, 248, 0.18); border-radius:10px; padding:8px 12px; margin-bottom:16px;">
        <div style="display:grid; grid-template-columns: 1.2fr 2.8fr 1.5fr 1.2fr 1.8fr 1.5fr; gap:10px; font-weight:700; font-size:0.78rem; text-transform:uppercase; letter-spacing:0.04em; color:#94a3b8; padding:8px 6px; border-bottom:1px solid rgba(255,255,255,0.08);">
            <div>Type</div>
            <div>Indicator</div>
            <div>Source(s)</div>
            <div>Risk Level</div>
            <div>Context / Association</div>
            <div style="text-align:right;">Action</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    for idx, ioc in enumerate(filtered):
        ind = ioc.get("indicator", "")
        itype = ioc.get("type", "IOC")
        risk = ioc.get("risk_level", "Medium")
        ctx = ioc.get("context", "Indicator")
        sources = ", ".join(ioc.get("sources", ["Document"]))
        icon = get_ioc_icon(itype)
        rb_html = get_risk_badge_html(risk)

        c_row, c_btn = st.columns([5.5, 1.2])
        with c_row:
            st.markdown(f"""
            <div style="background:rgba(15, 23, 42, 0.5); border:1px solid rgba(255,255,255,0.06); border-radius:8px; padding:10px 12px; margin-bottom:6px; display:grid; grid-template-columns: 1.2fr 2.8fr 1.5fr 1.2fr 1.8fr; gap:10px; align-items:center; font-size:0.84rem;">
                <div style="display:flex; align-items:center; gap:6px; font-weight:600; color:#cbd5e1;">
                    <span>{icon}</span> {itype}
                </div>
                <div class="mono-font" style="font-weight:700; color:#ffffff; overflow:hidden; text-overflow:ellipsis;">
                    {ind}
                </div>
                <div style="font-size:0.78rem; color:#38bdf8; overflow:hidden; text-overflow:ellipsis;">
                    {sources}
                </div>
                <div>
                    {rb_html}
                </div>
                <div style="font-size:0.78rem; color:#94a3b8; overflow:hidden; text-overflow:ellipsis;">
                    {ctx}
                </div>
            </div>
            """, unsafe_allow_html=True)
        with c_btn:
            if st.button("🎯 Investigate", key=f"ioc_table_inv_{idx}", use_container_width=True):
                on_investigate_ioc(ind)

    st.markdown("<div style='margin:24px 0;'></div>", unsafe_allow_html=True)

    # Export & Download Section
    st.markdown("""
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
        <h3 style="margin:0; font-size:1.1rem; font-weight:700; color:#f8fafc;">📥 Export Threat Indicators</h3>
    </div>
    """, unsafe_allow_html=True)

    # Prepare CSV export
    export_df = pd.DataFrame(filtered)
    csv_data = export_df.to_csv(index=False).encode('utf-8')
    json_data = json.dumps(filtered, indent=2).encode('utf-8')

    col_exp1, col_exp2, col_exp3 = st.columns([1.5, 1.5, 4])
    with col_exp1:
        st.download_button(
            "📥 Download CSV",
            data=csv_data,
            file_name="intelassist_extracted_iocs.csv",
            mime="text/csv",
            use_container_width=True,
            key="dl_ioc_csv"
        )
    with col_exp2:
        st.download_button(
            "📦 Download JSON",
            data=json_data,
            file_name="intelassist_extracted_iocs.json",
            mime="application/json",
            use_container_width=True,
            key="dl_ioc_json"
        )
