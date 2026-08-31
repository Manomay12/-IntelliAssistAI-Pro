"""
AI Incident Investigation Assistant Page View for IntelAssist AI.
"""

from typing import Dict, Any, List, Callable, Optional
import streamlit as st

QUICK_INVESTIGATION_QUESTIONS = [
    "What happened during this security incident and what is the full attack chain?",
    "Extract all indicators of compromise, affected accounts, and lateral movement traces.",
    "Summarize the SSH brute force attack from 185.220.101.5 and privilege escalation.",
    "What are the recommended SOC containment, eradication, and recovery steps?",
    "Which CVE vulnerabilities were exploited during this intrusion?",
    "Map all observed evidence to possible MITRE ATT&CK techniques."
]

def render_ai_investigation_page(
    all_documents: List[str],
    on_run_investigation: Callable[[str, str], Dict[str, Any]],
    default_prompt: Optional[str] = None
):
    """Render the AI Incident Investigation Assistant workspace."""
    st.markdown("""
    <div style="margin-bottom:18px;">
        <div style="display:flex; align-items:center; gap:10px;">
            <h2 style="font-weight:800; color:#ffffff; margin:0; letter-spacing:-0.02em;">🤖 AI Incident Investigation Assistant</h2>
            <span style="font-size:0.75rem; background:rgba(168,85,247,0.2); color:#c084fc; padding:3px 10px; border-radius:9999px; border:1px solid rgba(168,85,247,0.4); font-weight:700;">
                Evidence-Grounded Synthesizer
            </span>
        </div>
        <p style="color:#94a3b8; font-size:0.92rem; margin:4px 0 0 0;">
            Ask complex incident response questions. IntelAssist evaluates ingested threat reports and log events, reconstructing attack flows while explicitly distinguishing observed evidence from hypotheses.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Scope & Query Configuration
    col_scope, col_query = st.columns([2, 5])
    with col_scope:
        doc_options = ["All Documents & Logs"] + all_documents
        selected_scope = st.selectbox("Investigation Target Scope", doc_options, key="ai_inv_scope_select")
        active_scope = None if selected_scope == "All Documents & Logs" else selected_scope

    with col_query:
        init_q = default_prompt or ""
        investigation_query = st.text_input(
            "Incident Question / Investigation Objective",
            value=init_q,
            placeholder="e.g. 'What happened during this security incident?'",
            key="ai_inv_input_query"
        )

    # Quick Investigation Preset Chips
    st.markdown("<div style='font-size:0.78rem; font-weight:700; color:#64748b; margin:6px 0 8px 0;'>QUICK INVESTIGATION PROMPTS:</div>", unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    for idx, q in enumerate(QUICK_INVESTIGATION_QUESTIONS[:3]):
        with [c1, c2, c3][idx]:
            if st.button(q, key=f"quick_inv_btn_{idx}", use_container_width=True):
                investigation_query = q
                st.session_state.current_inv_prompt = q
                st.rerun()

    c4, c5, c6 = st.columns(3)
    for idx, q in enumerate(QUICK_INVESTIGATION_QUESTIONS[3:]):
        with [c4, c5, c6][idx]:
            if st.button(q, key=f"quick_inv_btn_{idx+3}", use_container_width=True):
                investigation_query = q
                st.session_state.current_inv_prompt = q
                st.rerun()

    st.markdown("<div style='margin:16px 0;'></div>", unsafe_allow_html=True)

    # Run Investigation Button
    if st.button("🚀 Run AI Incident Investigation Report", type="primary", use_container_width=True, key="btn_execute_ai_inv"):
        if not investigation_query.strip():
            st.warning("Please enter an incident investigation question or select a preset prompt above.")
        else:
            with st.spinner("Analyzing document context, log events, and synthesizing evidence-grounded incident report..."):
                inv_result = on_run_investigation(investigation_query.strip(), active_scope)
                st.session_state.last_inv_result = inv_result

    # Display Last Result if Available
    last_res = st.session_state.get("last_inv_result")
    if last_res:
        st.markdown("<div style='margin:20px 0;'></div>", unsafe_allow_html=True)
        st.markdown("""<div class="modern-card" style="border-top:4px solid #a855f7; padding:24px 28px;">""", unsafe_allow_html=True)
        
        answer_text = last_res.get("answer", "")
        st.markdown(answer_text)

        st.markdown("<div style='margin:20px 0; border-bottom:1px solid rgba(255,255,255,0.08);'></div>", unsafe_allow_html=True)

        # Source Citations Bar
        sources = last_res.get("sources", [])
        if sources:
            st.markdown(f"**📚 Referenced Forensic Sources ({len(sources)} vector chunks cited):**")
            for idx, src in enumerate(sources[:4], 1):
                st.markdown(f"""
                <div style="font-size:0.8rem; color:#cbd5e1; background:rgba(0,0,0,0.3); padding:8px 12px; border-radius:6px; margin-bottom:6px; border:1px solid rgba(255,255,255,0.06);">
                    <b>[Source {idx}]</b> 📄 <code>{src.get('filename')}</code> (Page {src.get('page_number', 1)}) — Relevance: <b>{src.get('similarity_percentage', 90)}%</b>
                </div>
                """, unsafe_allow_html=True)

        # Export Report Button
        st.download_button(
            "📥 Export Investigation Report (.md)",
            data=answer_text,
            file_name="incident_investigation_report.md",
            mime="text/markdown",
            key="dl_inv_report_btn",
            use_container_width=True
        )

        st.markdown("</div>", unsafe_allow_html=True)
