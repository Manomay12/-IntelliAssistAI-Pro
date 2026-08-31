"""
Chat Interface Components for IntelAssist AI.
"""

from typing import List, Dict, Any, Callable, Optional
import streamlit as st
from components.source_card import render_sources_section

def render_suggested_questions(on_select: Callable[[str], None], active_doc: Optional[str] = None):
    """Render modern clickable prompt suggestion chips tailored to cyber threat investigations."""
    if active_doc and active_doc != "All Documents":
        short_name = active_doc if len(active_doc) < 22 else active_doc[:19] + "..."
        suggestions = [
            f"🎯 What are the main threats and CVEs in {short_name}?",
            f"🏷️ Extract all Indicators of Compromise (IOCs) from {short_name}",
            f"🔄 Reconstruct the attack chain and techniques in {short_name}",
            f"🛡️ What are the recommended SOC containment steps for {short_name}?"
        ]
    else:
        suggestions = [
            "🎯 What are the primary threats, CVEs, and adversary groups identified?",
            "🏷️ Extract all indicators of compromise (IPs, domains, hashes, CVEs)",
            "🔄 Reconstruct the chronological incident attack chain",
            "🛡️ What are the recommended SOC mitigation and response actions?",
            "🔍 Which suspicious IP addresses and domains require perimeter blocking?"
        ]

    st.markdown("<div style='font-size:0.75rem; font-weight:700; text-transform:uppercase; letter-spacing:0.04em; color:#94a3b8; margin-bottom:8px;'>💡 SUGGESTED THREAT INQUIRIES</div>", unsafe_allow_html=True)
    cols = st.columns(len(suggestions))
    for i, (col, sug) in enumerate(zip(cols, suggestions)):
        with col:
            words = sug.split()
            label = words[0] + " " + " ".join(words[1:3])
            if st.button(label, key=f"sug_{i}_{active_doc or 'all'}", help=sug, use_container_width=True):
                on_select(sug[2:].strip())

def render_chat_message(
    msg: Dict[str, Any],
    on_feedback: Optional[Callable[[str, str], None]] = None,
    on_copy: Optional[Callable[[str], None]] = None
):
    """Render a single user or assistant chat message."""
    role = msg.get("role", "user")
    content = msg.get("content", "")
    timestamp = msg.get("timestamp", "")
    msg_id = msg.get("id", "")
    sources = msg.get("sources", [])
    model_info = msg.get("model_info", {})
    feedback = msg.get("feedback")

    if role == "user":
        st.markdown(f"""
        <div style="display:flex; justify-content:flex-end; margin-bottom:16px;">
            <div style="background:linear-gradient(135deg, #0284c7 0%, #0369a1 100%); border:1px solid rgba(56,189,248,0.4); border-radius:12px; border-bottom-right-radius:2px; padding:12px 18px; max-width:82%; box-shadow:0 4px 14px rgba(2,132,199,0.3);">
                <div style="display:flex; justify-content:space-between; align-items:center; gap:16px; margin-bottom:6px; border-bottom:1px solid rgba(255,255,255,0.2); padding-bottom:4px;">
                    <span style="font-weight:700; font-size:0.78rem; color:#ffffff; display:flex; align-items:center; gap:5px;">
                        <span>👤</span> Analyst Inquiry
                    </span>
                    <span style="font-size:0.72rem; color:#e0f2fe;">
                        {timestamp}
                    </span>
                </div>
                <div style="font-size:0.94rem; font-weight:500; color:#ffffff; line-height:1.5;">{content}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        provider = model_info.get("provider", "IntelAssist AI")
        latency = model_info.get("latency_sec", 0.3)
        is_demo = model_info.get("is_demo", False)

        tag = "⚡ Smart Cyber NLP" if is_demo else f"🤖 {provider}"

        st.markdown(f"""
        <div style="display:flex; justify-content:flex-start; margin-bottom:6px;">
            <div style="background:rgba(15, 23, 42, 0.85); border:1px solid rgba(56, 189, 248, 0.22); border-radius:12px; border-bottom-left-radius:2px; padding:16px 20px; width:100%; box-shadow:0 4px 16px rgba(0,0,0,0.4);">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; border-bottom:1px solid rgba(255,255,255,0.06); padding-bottom:6px;">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span style="font-size:1.15rem;">🛡️</span>
                        <span style="font-weight:700; color:#38bdf8;">IntelAssist AI Intelligence</span>
                        <span style="font-size:0.7rem; padding:2px 8px; border-radius:9999px; background:rgba(56,189,248,0.15); color:#38bdf8; border:1px solid rgba(56,189,248,0.3); font-weight:700;">{tag}</span>
                    </div>
                    <div style="font-size:0.75rem; color:#64748b;">
                        ⏱️ {latency}s • {timestamp}
                    </div>
                </div>
                <div style="line-height:1.65; color:#f1f5f9;">
        """, unsafe_allow_html=True)

        st.markdown(content)

        st.markdown("</div></div></div>", unsafe_allow_html=True)

        # Render sources if available
        if sources:
            render_sources_section(sources, key_prefix=f"msg_{msg_id}")

        # Feedback & Action buttons
        f_col1, f_col2, f_col3, f_spacer = st.columns([0.6, 0.6, 1.2, 7])
        with f_col1:
            if st.button("👍", key=f"thumb_up_{msg_id}", help="Accurate Intelligence"):
                if on_feedback:
                    on_feedback(msg_id, "up")
                    st.toast("Feedback recorded!", icon="✨")
        with f_col2:
            if st.button("👎", key=f"thumb_down_{msg_id}", help="Needs Adjustment"):
                if on_feedback:
                    on_feedback(msg_id, "down")
                    st.toast("Feedback recorded.", icon="📝")
        with f_col3:
            if st.button("📋 Copy Text", key=f"copy_{msg_id}", help="Copy response to clipboard"):
                st.toast("Intelligence response copied to clipboard!", icon="📋")
