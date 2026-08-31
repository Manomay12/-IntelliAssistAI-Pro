"""
Authentication and Analyst Access Page View for IntelAssist AI.
"""

from typing import Dict, Any, Callable
import streamlit as st
from utils.config import APP_NAME, APP_TAGLINE, APP_VERSION

def render_auth_page(
    on_login: Callable[[str, str], Tuple[bool, str, Optional[Dict[str, Any]]]],
    on_register: Callable[[str, str, str, str], Tuple[bool, str]],
    on_demo_login: Callable[[], Dict[str, Any]]
):
    """Render the SOC Login / Sign Up portal."""
    st.markdown("""
    <div style="text-align:center; padding:30px 0 10px 0;">
        <div style="display:inline-flex; align-items:center; justify-content:center; width:64px; height:64px; border-radius:16px; background:linear-gradient(135deg, #0284c7 0%, #0369a1 100%); box-shadow:0 8px 24px rgba(2,132,199,0.5); font-size:2rem; margin-bottom:12px; border:1px solid rgba(56,189,248,0.4);">
            🛡️
        </div>
        <h1 style="font-weight:800; font-size:2.2rem; color:#ffffff; margin:0 0 6px 0; letter-spacing:-0.03em;">
            IntelAssist AI
        </h1>
        <p style="color:#38bdf8; font-weight:700; font-size:0.92rem; text-transform:uppercase; letter-spacing:0.06em; margin:0 0 8px 0;">
            Cyber Threat Intelligence & Investigation Platform
        </p>
        <p style="color:#94a3b8; font-size:0.88rem; max-width:480px; margin:0 auto 24px auto;">
            Enterprise forensic log analysis, indicator correlation, and AI-powered incident response.
        </p>
    </div>
    """, unsafe_allow_html=True)

    col_space1, col_center, col_space2 = st.columns([1, 1.4, 1])

    with col_center:
        st.markdown("""
        <div class="modern-card" style="border:1px solid rgba(56, 189, 248, 0.3); padding:28px 24px;">
        """, unsafe_allow_html=True)

        tab_login, tab_signup, tab_demo = st.tabs(["🔐 Analyst Login", "📝 Create Account", "⚡ Instant Demo"])

        with tab_login:
            st.markdown("<div style='margin-top:14px;'></div>", unsafe_allow_html=True)
            u_name = st.text_input("Username", key="auth_login_user", placeholder="e.g. analyst")
            u_pass = st.text_input("Password", type="password", key="auth_login_pass", placeholder="••••••••")

            if st.button("🚀 Access SOC Portal", type="primary", use_container_width=True, key="btn_submit_login"):
                if not u_name or not u_pass:
                    st.error("Please enter both username and password.")
                else:
                    success, msg, user_dict = on_login(u_name, u_pass)
                    if success:
                        st.success("Authenticated! Redirecting to SOC Dashboard...")
                        st.rerun()
                    else:
                        st.error(msg)

        with tab_signup:
            st.markdown("<div style='margin-top:14px;'></div>", unsafe_allow_html=True)
            reg_name = st.text_input("Full Name", key="auth_reg_fullname", placeholder="e.g. Alex Rivera")
            reg_user = st.text_input("Username", key="auth_reg_user", placeholder="e.g. arivera")
            reg_email = st.text_input("Email", key="auth_reg_email", placeholder="arivera@intelassist.ai")
            reg_pass = st.text_input("Password", type="password", key="auth_reg_pass", placeholder="Min 6 characters")

            if st.button("✨ Register Analyst Account", type="primary", use_container_width=True, key="btn_submit_reg"):
                if not reg_user or not reg_pass:
                    st.error("Username and password are required.")
                else:
                    success, msg = on_register(reg_user, reg_pass, reg_email, reg_name)
                    if success:
                        st.success(msg)
                    else:
                        st.error(msg)

        with tab_demo:
            st.markdown("""
            <div style="padding:12px 0; text-align:center;">
                <div style="font-weight:700; color:#f8fafc; font-size:1.05rem; margin-bottom:6px;">Hackathon Evaluator Quick Access</div>
                <p style="font-size:0.82rem; color:#94a3b8; margin-bottom:18px;">
                    Instantly sign in as <b>Lead SOC Investigator</b> with pre-seeded threat reports, authentication logs, and correlated IOCs.
                </p>
            </div>
            """, unsafe_allow_html=True)
            
            if st.button("⚡ Continue as Demo Analyst", type="primary", use_container_width=True, key="btn_demo_login"):
                on_demo_login()
                st.toast("Signed in as Demo Analyst!", icon="🛡️")
                st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown(f"""
        <div style="text-align:center; margin-top:20px; font-size:0.75rem; color:#64748b;">
            {APP_NAME} • {APP_VERSION} • Zero External Dependencies Required
        </div>
        """, unsafe_allow_html=True)
