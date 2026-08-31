"""
CSS Design System and Styling Injection for IntelAssist AI.
Implements a sleek, modern Cybersecurity SOC Operations Center aesthetic with dark glassmorphism,
monospace indicator chips, risk score badges, high-contrast action toolbars, and responsive telemetry cards.
"""

import streamlit as st

def inject_custom_styles():
    """Inject custom cybersecurity CSS rules into the Streamlit app header."""
    st.markdown("""
    <style>
    /* Google Fonts Import */
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    /* Global Root Variables */
    :root {
        --primary: #0284c7;
        --primary-hover: #0369a1;
        --primary-light: rgba(56, 189, 248, 0.15);
        --cyber-blue: #38bdf8;
        --secondary: #64748b;
        --accent-purple: #a855f7;
        --success: #10b981;
        --warning: #f59e0b;
        --danger: #ef4444;
        --bg-dark: #080c14;
        --card-bg: rgba(15, 23, 42, 0.75);
        --card-border: rgba(56, 189, 248, 0.18);
        --card-hover: rgba(56, 189, 248, 0.3);
        --text-main: #f8fafc;
        --text-muted: #94a3b8;
    }

    /* Base Typography & Body */
    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    code, pre, .mono-font {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Streamlit Main Container Tweaks */
    .block-container {
        padding-top: 1.2rem;
        padding-bottom: 5.5rem;
        max-width: 1320px;
    }

    /* Custom Modern Scrollbars */
    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-track {
        background: transparent;
    }
    ::-webkit-scrollbar-thumb {
        background: rgba(56, 189, 248, 0.25);
        border-radius: 9999px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: rgba(56, 189, 248, 0.5);
    }

    /* Top Action Bar Buttons & Popovers */
    div[data-testid="stPopover"] > div > button,
    div[data-testid="stButton"] > button,
    div[data-testid="stDownloadButton"] > button {
        background: linear-gradient(145deg, #111c35 0%, #0b1325 100%) !important;
        border: 1px solid rgba(56, 189, 248, 0.25) !important;
        color: #f8fafc !important;
        font-weight: 600 !important;
        font-size: 0.85rem !important;
        border-radius: 8px !important;
        padding: 8px 14px !important;
        transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1) !important;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.4) !important;
        white-space: nowrap !important;
        min-height: 38px !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        gap: 6px !important;
    }

    div[data-testid="stPopover"] > div > button:hover,
    div[data-testid="stButton"] > button:hover,
    div[data-testid="stDownloadButton"] > button:hover {
        background: linear-gradient(145deg, #1e2e50 0%, #111c35 100%) !important;
        border-color: rgba(56, 189, 248, 0.6) !important;
        color: #38bdf8 !important;
        transform: translateY(-1px) !important;
        box-shadow: 0 4px 14px rgba(56, 189, 248, 0.25) !important;
    }

    /* Primary Cyber Buttons */
    button[kind="primary"],
    div[data-testid="stButton"] > button[kind="primary"] {
        background: linear-gradient(135deg, #0284c7 0%, #2563eb 100%) !important;
        border: 1px solid rgba(56, 189, 248, 0.4) !important;
        color: #ffffff !important;
        font-weight: 700 !important;
        box-shadow: 0 4px 14px rgba(2, 132, 199, 0.4) !important;
    }
    button[kind="primary"]:hover,
    div[data-testid="stButton"] > button[kind="primary"]:hover {
        background: linear-gradient(135deg, #0369a1 0%, #1d4ed8 100%) !important;
        border-color: rgba(56, 189, 248, 0.8) !important;
        box-shadow: 0 6px 20px rgba(56, 189, 248, 0.5) !important;
        transform: translateY(-1px) !important;
    }

    /* Popover Body Container */
    div[data-testid="stPopoverBody"] {
        background: #0b1325 !important;
        border: 1px solid rgba(56, 189, 248, 0.35) !important;
        border-radius: 12px !important;
        box-shadow: 0 16px 36px rgba(0, 0, 0, 0.8) !important;
        padding: 16px !important;
        min-width: 320px !important;
    }

    /* SOC Hero Banner */
    .hero-banner {
        background: linear-gradient(135deg, #0c1830 0%, #080f1e 100%);
        border: 1px solid rgba(56, 189, 248, 0.22);
        border-radius: 14px;
        padding: 24px 28px;
        margin-bottom: 22px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.05);
        position: relative;
        overflow: hidden;
    }

    .hero-banner::after {
        content: "";
        position: absolute;
        top: 0;
        right: 0;
        width: 350px;
        height: 100%;
        background: radial-gradient(circle at 100% 0%, rgba(56, 189, 248, 0.08) 0%, transparent 70%);
        pointer-events: none;
    }

    /* Modern SOC Cards */
    .modern-card {
        background: var(--card-bg);
        border: 1px solid var(--card-border);
        border-radius: 12px;
        padding: 20px;
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
    }
    .modern-card:hover {
        border-color: var(--card-hover);
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.45);
    }

    /* Threat Alert Card */
    .alert-card-critical {
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.12) 0%, rgba(15, 23, 42, 0.8) 100%);
        border: 1px solid rgba(239, 68, 68, 0.45);
        border-left: 5px solid #ef4444;
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 12px;
    }

    .alert-card-high {
        background: linear-gradient(135deg, rgba(249, 115, 22, 0.12) 0%, rgba(15, 23, 42, 0.8) 100%);
        border: 1px solid rgba(249, 115, 22, 0.45);
        border-left: 5px solid #f97316;
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 12px;
    }

    .alert-card-elevated {
        background: linear-gradient(135deg, rgba(245, 158, 11, 0.12) 0%, rgba(15, 23, 42, 0.8) 100%);
        border: 1px solid rgba(245, 158, 11, 0.45);
        border-left: 5px solid #f59e0b;
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 12px;
    }

    /* Metric Stat Card */
    .metric-card {
        background: linear-gradient(145deg, #0f1a30 0%, #091020 100%);
        border: 1px solid rgba(56, 189, 248, 0.16);
        border-radius: 12px;
        padding: 18px 20px;
        position: relative;
        overflow: hidden;
    }
    .metric-card:hover {
        border-color: rgba(56, 189, 248, 0.35);
        transform: translateY(-2px);
    }
    .metric-card .stat-val {
        font-size: 1.85rem;
        font-weight: 800;
        letter-spacing: -0.03em;
        line-height: 1.1;
        margin: 6px 0 2px 0;
        font-family: 'JetBrains Mono', monospace;
    }

    /* Indicator Badge Pill */
    .ioc-chip {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: rgba(15, 23, 42, 0.9);
        border: 1px solid rgba(56, 189, 248, 0.3);
        border-radius: 6px;
        padding: 4px 10px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.82rem;
        color: #38bdf8;
    }

    /* Activity Feed Item */
    .activity-row {
        display: flex;
        align-items: flex-start;
        gap: 12px;
        padding: 10px 0;
        border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }
    .activity-row:last-child {
        border-bottom: none;
    }

    /* Timeline Point Card */
    .timeline-card {
        background: rgba(15, 23, 42, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-left: 3px solid #38bdf8;
        border-radius: 8px;
        padding: 12px 14px;
        margin-bottom: 10px;
    }

    /* Status Dot */
    .status-dot {
        display: inline-block;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        margin-right: 6px;
    }
    .status-online {
        background: #10b981;
        box-shadow: 0 0 8px #10b981;
    }
    .status-demo {
        background: #38bdf8;
        box-shadow: 0 0 8px #38bdf8;
    }
    .status-alert {
        background: #ef4444;
        box-shadow: 0 0 8px #ef4444;
    }

    /* Footer */
    .app-footer {
        text-align: center;
        color: #64748b;
        font-size: 0.8rem;
        margin-top: 40px;
        padding-top: 20px;
        border-top: 1px solid rgba(255, 255, 255, 0.08);
    }
    </style>
    """, unsafe_allow_html=True)
