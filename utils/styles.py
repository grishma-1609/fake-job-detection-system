"""
Cybersecurity UI Theme & CSS Styler for Streamlit.
Provides dark-mode cybersecurity aesthetics, glowing neon accents, card layouts, and risk badges.
"""

import streamlit as st


def apply_cybersecurity_theme():
    """Injects custom CSS styling for a cybersecurity SOC/SaaS look."""
    css = """
    <style>
    /* Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap');

    /* Global Root Variables */
    :root {
        --cyber-bg: #090D16;
        --cyber-card: #111827;
        --cyber-card-border: #1E293B;
        --cyber-card-hover: #1A2234;
        --cyber-cyan: #00F0FF;
        --cyber-cyan-glow: rgba(0, 240, 255, 0.25);
        --cyber-blue: #3B82F6;
        --cyber-green: #10B981;
        --cyber-amber: #F59E0B;
        --cyber-red: #EF4444;
        --cyber-purple: #8B5CF6;
        --text-primary: #F8FAFC;
        --text-secondary: #94A3B8;
        --text-muted: #64748B;
    }

    /* Base Font Family */
    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    /* Main Container Padding */
    .block-container {
        padding-top: 1.8rem;
        padding-bottom: 3rem;
        max-width: 1280px;
    }

    /* Cyber Hero Header */
    .cyber-header {
        background: linear-gradient(135deg, rgba(17, 24, 39, 0.95) 0%, rgba(15, 23, 42, 0.85) 100%);
        border: 1px solid rgba(0, 240, 255, 0.2);
        border-radius: 12px;
        padding: 24px 28px;
        margin-bottom: 24px;
        box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.5), 0 0 15px -3px rgba(0, 240, 255, 0.15);
        position: relative;
        overflow: hidden;
    }

    .cyber-header::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        width: 4px;
        height: 100%;
        background: linear-gradient(180deg, #00F0FF, #3B82F6);
    }

    .cyber-title {
        font-size: 26px;
        font-weight: 800;
        color: #FFFFFF;
        letter-spacing: -0.02em;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 12px;
    }

    .cyber-subtitle {
        color: var(--text-secondary);
        font-size: 14px;
        margin-top: 6px;
        font-weight: 400;
    }

    /* Card Box */
    .cyber-card {
        background: #111827;
        border: 1px solid #1F2937;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 18px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        transition: border-color 0.2s ease, transform 0.2s ease;
    }

    .cyber-card:hover {
        border-color: rgba(0, 240, 255, 0.35);
    }

    /* Metric Cards */
    .stat-card {
        background: linear-gradient(145deg, #131B2E 0%, #0D1322 100%);
        border: 1px solid #1E293B;
        border-radius: 12px;
        padding: 18px 20px;
        position: relative;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.4);
    }

    .stat-label {
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--text-muted);
        margin-bottom: 4px;
    }

    .stat-value {
        font-size: 28px;
        font-weight: 800;
        color: #F8FAFC;
        line-height: 1.2;
    }

    .stat-subtext {
        font-size: 11px;
        color: var(--text-secondary);
        margin-top: 4px;
    }

    /* Risk Badges */
    .risk-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 6px 14px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 13px;
        letter-spacing: 0.03em;
        text-transform: uppercase;
    }

    .risk-badge-low {
        background: rgba(16, 185, 129, 0.15);
        color: #34D399;
        border: 1px solid rgba(16, 185, 129, 0.4);
    }

    .risk-badge-medium {
        background: rgba(245, 158, 11, 0.15);
        color: #FBBF24;
        border: 1px solid rgba(245, 158, 11, 0.4);
    }

    .risk-badge-high {
        background: rgba(239, 68, 68, 0.15);
        color: #F87171;
        border: 1px solid rgba(239, 68, 68, 0.4);
    }

    .risk-badge-critical {
        background: rgba(220, 38, 38, 0.25);
        color: #FF4D4D;
        border: 1px solid rgba(239, 68, 68, 0.8);
        box-shadow: 0 0 10px rgba(239, 68, 68, 0.4);
    }

    /* Flag Item Card */
    .flag-item {
        background: rgba(239, 68, 68, 0.08);
        border-left: 3px solid #EF4444;
        border-radius: 6px;
        padding: 10px 14px;
        margin-bottom: 8px;
        font-size: 13px;
        color: #FECACA;
    }

    .trust-item {
        background: rgba(16, 185, 129, 0.08);
        border-left: 3px solid #10B981;
        border-radius: 6px;
        padding: 10px 14px;
        margin-bottom: 8px;
        font-size: 13px;
        color: #A7F3D0;
    }

    .info-item {
        background: rgba(59, 130, 246, 0.08);
        border-left: 3px solid #3B82F6;
        border-radius: 6px;
        padding: 10px 14px;
        margin-bottom: 8px;
        font-size: 13px;
        color: #BFDBFE;
    }

    /* Tag/Pill */
    .cyber-pill {
        display: inline-block;
        background: #1E293B;
        color: #00F0FF;
        border: 1px solid rgba(0, 240, 255, 0.3);
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 11px;
        font-family: 'JetBrains Mono', monospace;
        margin-right: 6px;
        margin-bottom: 6px;
    }

    /* Code & Terminal Monospace */
    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Streamlit Button Tweaks */
    div.stButton > button:first-child {
        border-radius: 8px;
        font-weight: 600;
        transition: all 0.2s ease-in-out;
    }

    /* Active Sidebar Navigation Styling */
    section[data-testid="stSidebar"] {
        background-color: #0B0F19;
        border-right: 1px solid #1E293B;
    }
    </style>
    """
    st.markdown(css, unsafe_allow_html=True)


def render_cyber_header(title: str, subtitle: str, badge: str = "SOC LEVEL 3 ENGINES ACTIVE"):
    """Renders cybersecurity header with glowing badge."""
    html = f"""
    <div class="cyber-header">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 10px;">
            <div>
                <h1 class="cyber-title">
                    <span style="color: #00F0FF;">⚡</span> {title}
                </h1>
                <p class="cyber-subtitle">{subtitle}</p>
            </div>
            <span class="cyber-pill" style="border-color: #00F0FF; background: rgba(0, 240, 255, 0.1); color: #00F0FF; font-weight: 600;">
                🛡️ {badge}
            </span>
        </div>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)
