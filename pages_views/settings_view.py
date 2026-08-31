"""
Settings & System Management Page View for IntelAssist AI.
"""

from typing import Dict, Any, Callable
import streamlit as st
from utils.config import (
    AVAILABLE_PROVIDERS,
    AVAILABLE_GEMINI_MODELS,
    AVAILABLE_NVIDIA_MODELS,
    AVAILABLE_OPENAI_MODELS,
    APP_VERSION
)

def render_settings_page(
    current_settings: Dict[str, Any],
    on_save_settings: Callable[[Dict[str, Any]], None],
    on_clear_history: Callable[[], None],
    on_rebuild_index: Callable[[], None],
    on_clear_all_data: Callable[[], None]
):
    """Render the Settings and System Management page."""
    st.markdown("""
    <div style="margin-bottom:18px;">
        <div style="display:flex; align-items:center; gap:10px;">
            <h2 style="font-weight:800; color:#ffffff; margin:0; letter-spacing:-0.02em;">⚙️ Platform & Intelligence Settings</h2>
            <span style="font-size:0.75rem; background:rgba(56,189,248,0.18); color:#38bdf8; padding:3px 10px; border-radius:9999px; border:1px solid rgba(56,189,248,0.35); font-weight:700;">
                System Configuration
            </span>
        </div>
        <p style="color:#94a3b8; font-size:0.92rem; margin:4px 0 0 0;">
            Configure AI providers (Google Gemini, NVIDIA NIM, OpenAI, or Smart Local Cyber NLP), API keys, and vector database persistence.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # 1. AI Model & Provider Configuration
    st.markdown("""
    <div class="modern-card">
        <h3 style="margin:0 0 14px 0; font-size:1.1rem; font-weight:700; color:#f8fafc;">🤖 Threat Intelligence AI Model Setup</h3>
    """, unsafe_allow_html=True)

    c_prov, c_model = st.columns(2)
    with c_prov:
        cur_prov = current_settings.get("provider", "Demo Mode (Smart AI)")
        provider = st.selectbox(
            "LLM Provider",
            AVAILABLE_PROVIDERS,
            index=AVAILABLE_PROVIDERS.index(cur_prov) if cur_prov in AVAILABLE_PROVIDERS else 0,
            key="set_provider_select"
        )
    with c_model:
        if "Gemini" in provider:
            models_list = AVAILABLE_GEMINI_MODELS
        elif "NVIDIA" in provider:
            models_list = AVAILABLE_NVIDIA_MODELS
        elif "OpenAI" in provider:
            models_list = AVAILABLE_OPENAI_MODELS
        else:
            models_list = ["Cyber-DeepNLP-v3 (Offline Local)", "Forensic-RAG-Synthesizer"]

        cur_model = current_settings.get("model_name", models_list[0])
        model_name = st.selectbox(
            "Model Name",
            models_list,
            index=models_list.index(cur_model) if cur_model in models_list else 0,
            key="set_model_select"
        )

    st.markdown("<div style='margin:12px 0;'></div>", unsafe_allow_html=True)

    # Hyperparameters
    c_temp, c_tok = st.columns(2)
    with c_temp:
        temperature = st.slider("Temperature (Precision / Analytical Rigor)", min_value=0.0, max_value=1.0, value=float(current_settings.get("temperature", 0.2)), step=0.05)
    with c_tok:
        max_tokens = st.slider("Max Response Tokens", min_value=512, max_value=4096, value=int(current_settings.get("max_tokens", 2048)), step=256)

    st.markdown("<div style='margin:12px 0;'></div>", unsafe_allow_html=True)

    # API Keys Configuration
    with st.expander("🔑 External API Keys (Optional — Demo AI is 100% functional offline)", expanded=False):
        gemini_key = st.text_input("Google Gemini API Key", value=current_settings.get("gemini_api_key", ""), type="password", key="set_gemini_key")
        nvidia_key = st.text_input("NVIDIA NIM API Key", value=current_settings.get("nvidia_api_key", ""), type="password", key="set_nvidia_key")
        openai_key = st.text_input("OpenAI API Key", value=current_settings.get("openai_api_key", ""), type="password", key="set_openai_key")

    if st.button("💾 Save Platform Configuration", type="primary", key="btn_save_settings"):
        new_settings = {
            "provider": provider,
            "model_name": model_name,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "gemini_api_key": gemini_key.strip(),
            "nvidia_api_key": nvidia_key.strip(),
            "openai_api_key": openai_key.strip()
        }
        on_save_settings(new_settings)
        st.toast("Settings saved successfully!", icon="✅")

    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='margin:24px 0;'></div>", unsafe_allow_html=True)

    # 2. Data & Index Lifecycle Management
    st.markdown("""
    <div class="modern-card">
        <h3 style="margin:0 0 14px 0; font-size:1.1rem; font-weight:700; color:#f8fafc;">💾 Data Lifecycle & Index Management</h3>
        <p style="font-size:0.85rem; color:#94a3b8; margin-bottom:18px;">
            Re-index existing documents, clear case conversations, or purge database artifacts.
        </p>
    """, unsafe_allow_html=True)

    c_b1, c_b2, c_b3 = st.columns(3)
    with c_b1:
        if st.button("🔄 Rebuild Vector Embeddings Index", use_container_width=True, key="btn_rebuild_index"):
            with st.spinner("Re-chunking and re-embedding all indexed documents..."):
                on_rebuild_index()
            st.toast("Vector index rebuilt successfully!", icon="⚡")

    with c_b2:
        with st.popover("🧹 Clear All Case History", use_container_width=True):
            st.markdown("<p style='font-size:0.84rem; color:#ffffff;'>Clear all saved investigation cases?</p>", unsafe_allow_html=True)
            if st.button("Confirm Delete All Cases", key="btn_conf_clr_hist", type="primary", use_container_width=True):
                on_clear_history()
                st.toast("Case history cleared.", icon="🧹")

    with c_b3:
        with st.popover("⚠️ Factory Reset All Data", use_container_width=True):
            st.markdown("<p style='font-size:0.84rem; color:#ef4444; font-weight:700;'>Wipe ALL documents, logs, IOCs, and vectors?</p>", unsafe_allow_html=True)
            if st.button("Yes, Wipe All Artifacts", key="btn_conf_wipe_all", type="primary", use_container_width=True):
                on_clear_all_data()
                st.toast("Platform database reset complete.", icon="🗑️")
                st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
