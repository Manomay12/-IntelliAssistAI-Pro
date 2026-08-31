"""
Sidebar Navigation, Case Management, and SOC Health Telemetry for IntelAssist AI.
"""

from typing import Tuple, List, Dict, Any, Optional, Callable
import streamlit as st
from utils.config import APP_NAME, APP_TAGLINE, APP_VERSION

NAV_ITEMS = [
    # OVERVIEW
    ("📊 Dashboard", "Dashboard"),
    # INTELLIGENCE
    ("📄 Threat Reports", "Threat Reports"),
    ("🎯 Threat Investigation", "Threat Investigation"),
    ("🏷️ IOC Explorer", "IOC Explorer"),
    # ANALYSIS
    ("📋 Log Analysis", "Log Analysis"),
    ("🤖 AI Investigation Assistant", "AI Investigation Assistant"),
    ("⏱️ Attack Timeline", "Attack Timeline"),
    # KNOWLEDGE
    ("🔎 Document Search", "Document Search"),
    ("💬 Intelligence Chat", "Intelligence Chat"),
    ("📝 Threat Summaries", "Threat Summaries"),
    # INSIGHTS
    ("📈 Analytics", "Analytics"),
    ("🕘 Case History", "Case History"),
    # SYSTEM
    ("⚙️ Settings", "Settings")
]

def render_sidebar(
    active_nav: str,
    total_docs: int,
    total_chunks: int,
    total_iocs: int,
    critical_alerts_count: int,
    provider_name: str,
    is_api_connected: bool,
    current_user: Optional[Dict[str, Any]] = None,
    recent_sessions: Optional[List[Dict[str, Any]]] = None,
    current_session_id: Optional[str] = None,
    on_load_session: Optional[Callable[[str], None]] = None,
    on_delete_session: Optional[Callable[[str], None]] = None,
    on_new_chat: Optional[Callable[[], None]] = None,
    on_clear_active_chat: Optional[Callable[[], None]] = None,
    on_navigate: Optional[Callable[[str], None]] = None,
    on_logout: Optional[Callable[[], None]] = None
) -> str:
    """Render the SOC Cyber sidebar with organized navigation, telemetry, and case history."""
    with st.sidebar:
        # App Logo & Branding Header
        st.markdown(f"""
        <div style="padding:6px 2px 14px 2px; border-bottom:1px solid rgba(56, 189, 248, 0.15); margin-bottom:12px;">
            <div style="display:flex; align-items:center; gap:10px;">
                <div style="background:linear-gradient(135deg, #0284c7 0%, #0369a1 100%); width:38px; height:38px; border-radius:10px; display:flex; align-items:center; justify-content:center; font-size:1.3rem; box-shadow:0 4px 12px rgba(2,132,199,0.4); border:1px solid rgba(56,189,248,0.3);">
                    🛡️
                </div>
                <div>
                    <div style="font-weight:800; font-size:1.18rem; color:#ffffff; letter-spacing:-0.02em; line-height:1.1;">{APP_NAME}</div>
                    <div style="font-size:0.7rem; color:#38bdf8; font-weight:700; text-transform:uppercase; letter-spacing:0.05em;">{APP_TAGLINE}</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Authenticated Analyst Status Card
        if current_user and current_user.get("authenticated"):
            u_name = current_user.get("full_name", "Security Analyst")
            u_role = current_user.get("role", "Threat Investigator")
            
            c_u1, c_u2 = st.columns([3.5, 1])
            with c_u1:
                st.markdown(f"""
                <div style="font-size:0.78rem; color:#cbd5e1; margin-bottom:8px;">
                    <span style="color:#94a3b8;">Analyst:</span> <b style="color:#f8fafc;">{u_name}</b><br>
                    <span style="font-size:0.68rem; color:#38bdf8;">● {u_role}</span>
                </div>
                """, unsafe_allow_html=True)
            with c_u2:
                if on_logout:
                    if st.button("🚪", key="sb_logout_btn", help="Log out of current session"):
                        on_logout()

        # Navigation Section
        st.markdown("<div style='font-size:0.7rem; font-weight:800; text-transform:uppercase; letter-spacing:0.06em; color:#64748b; margin:10px 0 6px 0;'>CYBER INTELLIGENCE SUITE</div>", unsafe_allow_html=True)
        
        labels = [item[0] for item in NAV_ITEMS]
        raw_keys = [item[1] for item in NAV_ITEMS]
        default_idx = raw_keys.index(active_nav) if active_nav in raw_keys else 0

        selected_label = st.radio(
            "SOC Navigation",
            labels,
            index=default_idx,
            label_visibility="collapsed",
            key=f"sidebar_nav_{active_nav}"
        )
        selected_page = raw_keys[labels.index(selected_label)]

        st.markdown("<div style='margin-top:12px; border-bottom:1px solid rgba(56, 189, 248, 0.12);'></div>", unsafe_allow_html=True)

        # Quick Investigation Actions Section
        st.markdown("<div style='font-size:0.7rem; font-weight:800; text-transform:uppercase; letter-spacing:0.06em; color:#64748b; margin:10px 0 6px 0;'>CASE ACTIONS</div>", unsafe_allow_html=True)
        col_new, col_clr = st.columns(2)
        with col_new:
            if st.button("➕ New Case", key="sb_btn_new_chat", use_container_width=True, help="Open a new investigation case"):
                if on_new_chat:
                    on_new_chat()
        with col_clr:
            with st.popover("🗑️ Clear Chat", use_container_width=True, help="Clear active investigation messages"):
                st.markdown("<p style='font-size:0.82rem; color:#f8fafc; margin:0 0 8px 0;'>Clear active investigation conversation?</p>", unsafe_allow_html=True)
                if st.button("Confirm Clear", key="sb_btn_confirm_clear", type="primary", use_container_width=True):
                    if on_clear_active_chat:
                        on_clear_active_chat()

        # Recent Investigations / Case History in Sidebar
        sessions = recent_sessions or []
        st.markdown("<div style='font-size:0.7rem; font-weight:800; text-transform:uppercase; letter-spacing:0.06em; color:#64748b; margin:12px 0 6px 0;'>ACTIVE CASES</div>", unsafe_allow_html=True)

        if not sessions:
            st.markdown("""
            <div style="font-size:0.75rem; color:#64748b; padding:6px; background:rgba(255,255,255,0.01); border-radius:6px; border:1px dashed rgba(255,255,255,0.08); text-align:center;">
                No saved investigation cases
            </div>
            """, unsafe_allow_html=True)
        else:
            for s in sessions[:4]:
                s_id = s.get("session_id", "")
                title = s.get("title", "Investigation")
                if len(title) > 20:
                    title = title[:18] + "..."
                msg_count = s.get("message_count", 0)
                is_active = (s_id == current_session_id)
                active_indicator = "🔹 " if is_active else ""

                c_item, c_del = st.columns([4, 1])
                with c_item:
                    btn_label = f"{active_indicator}{title} ({msg_count})"
                    if st.button(btn_label, key=f"sb_hist_load_{s_id}", help=f"Load case: {s.get('title', '')}", use_container_width=True):
                        if on_load_session:
                            on_load_session(s_id)
                with c_del:
                    if st.button("🗑️", key=f"sb_hist_del_{s_id}", help="Delete case"):
                        if on_delete_session:
                            on_delete_session(s_id)

        st.markdown("<div style='margin-top:12px; border-bottom:1px solid rgba(56, 189, 248, 0.12);'></div>", unsafe_allow_html=True)

        # Live SOC Telemetry
        st.markdown("<div style='font-size:0.7rem; font-weight:800; text-transform:uppercase; letter-spacing:0.06em; color:#64748b; margin:10px 0 6px 0;'>SOC TELEMETRY</div>", unsafe_allow_html=True)

        status_class = "status-online" if is_api_connected else "status-demo"
        api_text = f"{provider_name}" if is_api_connected else "Smart Cyber NLP"

        st.markdown(f"""
        <div style="background:rgba(15, 23, 42, 0.8); border:1px solid rgba(56, 189, 248, 0.18); border-radius:10px; padding:10px 12px; font-size:0.76rem; line-height:1.7;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="color:#94a3b8;">AI Engine:</span>
                <span style="font-weight:600; color:#f8fafc; display:flex; align-items:center;">
                    <span class="status-dot {status_class}"></span> {api_text}
                </span>
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="color:#94a3b8;">Threat Reports:</span>
                <span style="font-weight:700; color:#38bdf8;">{total_docs} files</span>
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="color:#94a3b8;">Indexed Vectors:</span>
                <span style="font-weight:700; color:#818cf8;">{total_chunks} chunks</span>
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="color:#94a3b8;">Extracted IOCs:</span>
                <span style="font-weight:700; color:#10b981;">{total_iocs} indicators</span>
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="color:#94a3b8;">Critical Alerts:</span>
                <span style="font-weight:700; color:{'#ef4444' if critical_alerts_count > 0 else '#94a3b8'};">{critical_alerts_count} active</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Platform Footer
        st.markdown(f"""
        <div style="margin-top:12px; padding:4px 2px; display:flex; align-items:center; gap:8px;">
            <div style="width:26px; height:26px; border-radius:50%; background:#1e293b; border:1px solid rgba(56,189,248,0.25); display:flex; align-items:center; justify-content:center; font-size:0.75rem;">
                🛡️
            </div>
            <div>
                <div style="font-size:0.76rem; font-weight:700; color:#f8fafc;">IntelAssist AI Platform</div>
                <div style="font-size:0.65rem; color:#64748b;">{APP_VERSION}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        return selected_page
