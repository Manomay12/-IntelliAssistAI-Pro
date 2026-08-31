"""
Case History & Investigation Records Page View for IntelAssist AI.
"""

from typing import Dict, Any, List, Callable, Optional
import streamlit as st

def render_history_page(
    sessions: List[Dict[str, Any]],
    current_session_id: str,
    on_load_session: Callable[[str], None],
    on_rename_session: Callable[[str, str], None],
    on_delete_session: Callable[[str], None],
    on_delete_all_sessions: Callable[[], None],
    on_new_chat: Callable[[], None]
):
    """Render the Case History & Investigation Records manager."""
    st.markdown("""
    <div style="margin-bottom:18px;">
        <div style="display:flex; align-items:center; gap:10px;">
            <h2 style="font-weight:800; color:#ffffff; margin:0; letter-spacing:-0.02em;">🕘 Case History & Investigation Records</h2>
            <span style="font-size:0.75rem; background:rgba(56,189,248,0.18); color:#38bdf8; padding:3px 10px; border-radius:9999px; border:1px solid rgba(56,189,248,0.35); font-weight:700;">
                Forensic Case Files
            </span>
        </div>
        <p style="color:#94a3b8; font-size:0.92rem; margin:4px 0 0 0;">
            Review past security case discussions, reopen threat analyses, export transcripts, or manage forensic session logs.
        </p>
    </div>
    """, unsafe_allow_html=True)

    total_messages = sum(s.get("message_count", 0) for s in sessions)
    
    m_c1, m_c2, m_c3, a_c1, a_c2 = st.columns([1.2, 1.2, 1.2, 1.3, 1.5])
    with m_c1:
        st.markdown(f"""
        <div class="metric-card" style="padding:10px 14px;">
            <div class="stat-val" style="font-size:1.3rem; color:#38bdf8;">{len(sessions)}</div>
            <div style="font-size:0.75rem; color:#94a3b8;">Total Cases</div>
        </div>
        """, unsafe_allow_html=True)
    with m_c2:
        st.markdown(f"""
        <div class="metric-card" style="padding:10px 14px;">
            <div class="stat-val" style="font-size:1.3rem; color:#10b981;">{total_messages}</div>
            <div style="font-size:0.75rem; color:#94a3b8;">Inquiries Exchanged</div>
        </div>
        """, unsafe_allow_html=True)
    with m_c3:
        st.markdown(f"""
        <div class="metric-card" style="padding:10px 14px;">
            <div class="stat-val" style="font-size:1.3rem; color:#f59e0b;">{current_session_id[:6]}...</div>
            <div style="font-size:0.75rem; color:#94a3b8;">Active Case ID</div>
        </div>
        """, unsafe_allow_html=True)
    with a_c1:
        st.markdown("<div style='margin-top:12px;'></div>", unsafe_allow_html=True)
        if st.button("➕ New Case", key="hist_new_chat_btn", type="primary", use_container_width=True):
            on_new_chat()
    with a_c2:
        st.markdown("<div style='margin-top:12px;'></div>", unsafe_allow_html=True)
        with st.popover("🗑️ Clear All Cases", use_container_width=True):
            st.markdown("<div style='font-size:0.85rem; font-weight:700; color:#ffffff; margin-bottom:6px;'>Wipe all saved case history?</div>", unsafe_allow_html=True)
            if st.button("Yes, Delete All", key="hist_confirm_del_all", type="primary", use_container_width=True):
                on_delete_all_sessions()

    st.markdown("<div style='margin:20px 0;'></div>", unsafe_allow_html=True)

    if not sessions:
        st.markdown("""
        <div class="modern-card" style="text-align:center; padding:36px 20px;">
            <div style="font-size:2.8rem; margin-bottom:10px;">📜</div>
            <h3 style="font-weight:700; color:#f8fafc; font-size:1.1rem; margin:0 0 6px 0;">No Investigation Cases Recorded</h3>
            <p style="font-size:0.85rem; color:#94a3b8; max-width:400px; margin:0 auto;">
                Start an investigation in the Intelligence Chat to generate case records.
            </p>
        </div>
        """, unsafe_allow_html=True)
        return

    # List Sessions
    for s in sessions:
        sid = s.get("session_id", "")
        title = s.get("title", "Case File")
        m_count = s.get("message_count", 0)
        updated = s.get("updated_at", "Recently")
        is_active = (sid == current_session_id)

        border_col = "#38bdf8" if is_active else "rgba(255,255,255,0.1)"
        active_badge = "🟢 Active Case" if is_active else "📁 Archived Case"

        c_info, c_load, c_ren, c_del = st.columns([4, 1.2, 1.2, 0.8])
        with c_info:
            st.markdown(f"""
            <div class="modern-card" style="padding:12px 18px; margin-bottom:8px; border-left:4px solid {border_col};">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <div style="font-weight:700; font-size:0.95rem; color:#ffffff;">{title}</div>
                        <div style="font-size:0.75rem; color:#94a3b8; margin-top:2px;">
                            {m_count} messages • Updated: {updated} • ID: <code style="color:#38bdf8;">{sid[:8]}</code>
                        </div>
                    </div>
                    <span style="font-size:0.72rem; color:{'#10b981' if is_active else '#94a3b8'}; font-weight:700;">{active_badge}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
        with c_load:
            if st.button("📂 Open Case", key=f"hist_open_{sid}", use_container_width=True):
                on_load_session(sid)
        with c_ren:
            with st.popover("✏️ Rename", use_container_width=True):
                new_t = st.text_input("New Title", value=title, key=f"hist_ren_input_{sid}")
                if st.button("Save", key=f"hist_ren_save_{sid}", type="primary", use_container_width=True):
                    if new_t.strip():
                        on_rename_session(sid, new_t.strip())
                        st.rerun()
        with c_del:
            if st.button("🗑️", key=f"hist_del_{sid}", help=f"Delete case {sid[:8]}", use_container_width=True):
                on_delete_session(sid)
