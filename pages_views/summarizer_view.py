"""
Threat Summaries & Cross-Report Analysis Page View for IntelAssist AI.
"""

from typing import Dict, Any, List, Callable, Optional
import streamlit as st

THREAT_SUMMARY_MODES = [
    "Executive Threat Brief",
    "Technical Malware Breakdown",
    "Incident Response Summary",
    "MITRE ATT&CK & IOC Highlights",
    "Quick Threat Summary"
]

def render_summarizer_page(
    all_documents: List[str],
    on_summarize: Callable[[str, str], Dict[str, Any]],
    on_compare: Optional[Callable[[str, str], Dict[str, Any]]] = None,
    current_summary_data: Optional[Dict[str, Any]] = None,
    default_doc: Optional[str] = None
):
    """Render the Threat Summaries and Cross-Report Comparison workspace."""
    st.markdown("""
    <div style="margin-bottom:18px;">
        <div style="display:flex; align-items:center; gap:10px;">
            <h2 style="font-weight:800; color:#ffffff; margin:0; letter-spacing:-0.02em;">📝 Threat Summaries & Cross-Report Analysis</h2>
            <span style="font-size:0.75rem; background:rgba(16,185,129,0.15); color:#10b981; padding:3px 10px; border-radius:9999px; border:1px solid rgba(16,185,129,0.3); font-weight:700;">
                AI Intelligence Synthesis
            </span>
        </div>
        <p style="color:#94a3b8; font-size:0.92rem; margin:4px 0 0 0;">
            Synthesize complex 50-page threat advisories into executive briefings, extract attack chains, or compare multi-incident threat campaigns side-by-side.
        </p>
    </div>
    """, unsafe_allow_html=True)

    if not all_documents:
        st.markdown("""
        <div class="modern-card" style="text-align:center; padding:36px 20px;">
            <div style="font-size:2.8rem; margin-bottom:10px;">📄</div>
            <h3 style="font-weight:700; color:#f8fafc; font-size:1.1rem; margin:0 0 6px 0;">No Threat Artifacts Available</h3>
            <p style="font-size:0.85rem; color:#94a3b8; max-width:400px; margin:0 auto 16px auto;">
                Upload a threat report on the Threat Reports page or load sample advisories on the Dashboard.
            </p>
        </div>
        """, unsafe_allow_html=True)
        return

    tab_single, tab_compare = st.tabs(["📝 Threat Advisory Summarizer", "⚖️ Cross-Report Adversary Comparison"])

    with tab_single:
        c_doc, c_mode, c_btn = st.columns([3, 2.5, 1.5])
        with c_doc:
            default_idx = 0
            if default_doc and default_doc in all_documents:
                default_idx = all_documents.index(default_doc)

            selected_doc = st.selectbox(
                "Select Threat Artifact",
                all_documents,
                index=default_idx,
                key="summarizer_doc_select"
            )
        with c_mode:
            selected_mode = st.selectbox(
                "Summary Style & Mode",
                THREAT_SUMMARY_MODES,
                index=0,
                key="summarizer_mode_select"
            )
        with c_btn:
            st.markdown("<div style='margin-top:28px;'></div>", unsafe_allow_html=True)
            generate_clicked = st.button("✨ Synthesize", type="primary", use_container_width=True, key="btn_generate_summary")

        summary_data = current_summary_data
        if generate_clicked or not summary_data or summary_data.get("doc_name") != selected_doc or summary_data.get("mode") != selected_mode:
            with st.spinner(f"Analyzing and generating {selected_mode} for '{selected_doc}'..."):
                summary_data = on_summarize(selected_doc, selected_mode)

        if summary_data:
            st.markdown("<div style='margin:16px 0;'></div>", unsafe_allow_html=True)

            summary_text = summary_data.get("summary", "")
            mode_label = summary_data.get("mode", selected_mode)

            md_export = f"# Threat Briefing: {selected_doc}\n**Mode:** {mode_label}\n\n{summary_text}\n\n## Key Security Topics\n" + ", ".join(summary_data.get("topics", []))

            act1, act2, act_space = st.columns([1.5, 1.5, 5])
            with act1:
                st.download_button(
                    "📥 Download Briefing",
                    data=md_export,
                    file_name=f"threat_brief_{selected_doc[:16]}_{mode_label.lower().replace(' ', '_')}.md",
                    mime="text/markdown",
                    use_container_width=True,
                    key="dl_summary_md"
                )
            with act2:
                if st.button("📋 Copy to Memory", key="copy_summary_btn", use_container_width=True):
                    st.toast("Threat brief copied to clipboard!", icon="📋")

            # Main Summary Render Card
            st.markdown(f"""
            <div class="modern-card" style="padding:24px 28px; margin-bottom:20px; border-left:4px solid #38bdf8;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; border-bottom:1px solid rgba(255,255,255,0.08); padding-bottom:10px;">
                    <div>
                        <span style="font-size:0.75rem; text-transform:uppercase; letter-spacing:0.05em; color:#38bdf8; font-weight:700;">{mode_label}</span>
                        <h3 style="margin:2px 0 0 0; font-size:1.3rem; font-weight:800; color:#ffffff;">{selected_doc}</h3>
                    </div>
                </div>
                <div style="line-height:1.75; color:#f8fafc; font-size:0.95rem;">
            """, unsafe_allow_html=True)

            st.markdown(summary_text)

            st.markdown("</div></div>", unsafe_allow_html=True)

            # Topics and Key Takeaways
            topics = summary_data.get("topics", [])
            takeaways = summary_data.get("key_takeaways", [])

            if topics or takeaways:
                col_top, col_take = st.columns(2)
                with col_top:
                    st.markdown("""
                    <div class="modern-card" style="padding:16px 20px; height:100%;">
                        <div style="font-weight:700; font-size:0.95rem; color:#f8fafc; margin-bottom:10px;">
                            🏷️ Key Threat Topics
                        </div>
                        <div style="display:flex; flex-wrap:wrap; gap:8px;">
                    """, unsafe_allow_html=True)
                    for t in topics:
                        st.markdown(f"""<span style="background:rgba(56,189,248,0.12); color:#38bdf8; border:1px solid rgba(56,189,248,0.25); padding:4px 10px; border-radius:6px; font-size:0.8rem; font-weight:600;">{t}</span>""", unsafe_allow_html=True)
                    st.markdown("</div></div>", unsafe_allow_html=True)

                with col_take:
                    st.markdown("""
                    <div class="modern-card" style="padding:16px 20px; height:100%;">
                        <div style="font-weight:700; font-size:0.95rem; color:#f8fafc; margin-bottom:10px;">
                            🛡️ Actionable Takeaways
                        </div>
                    """, unsafe_allow_html=True)
                    for idx, tk in enumerate(takeaways, 1):
                        st.markdown(f"""<div style="font-size:0.84rem; color:#cbd5e1; margin-bottom:6px;"><b>{idx}.</b> {tk}</div>""", unsafe_allow_html=True)
                    st.markdown("</div>", unsafe_allow_html=True)

    with tab_compare:
        if len(all_documents) < 2:
            st.info("Please upload at least 2 threat reports to enable cross-document adversary comparison.")
        else:
            col_a, col_b = st.columns(2)
            with col_a:
                doc_a = st.selectbox("Report A", all_documents, index=0, key="compare_doc_a")
            with col_b:
                doc_b = st.selectbox("Report B", all_documents, index=min(1, len(all_documents)-1), key="compare_doc_b")

            if st.button("⚖️ Run Cross-Report Comparison", type="primary", use_container_width=True, key="btn_run_compare"):
                if on_compare:
                    with st.spinner("Analyzing cross-report correlations, shared indicators, and TTP overlap..."):
                        comp_res = on_compare(doc_a, doc_b)
                        st.markdown("""<div class="modern-card" style="margin-top:16px; padding:20px;">""", unsafe_allow_html=True)
                        st.markdown(comp_res.get("comparison_text", "Comparison generated."))
                        st.markdown("</div>", unsafe_allow_html=True)
