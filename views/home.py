"""
Home Page: Landing page for Intelligent Fake Job & Recruitment Scam Detection System.
Features hero section, cybersecurity threat landscape statistics, and feature highlights.
"""

import streamlit as st
from utils.styles import render_cyber_header


def render_home():
    """Renders modern cybersecurity landing page."""
    render_cyber_header(
        title="Intelligent Fake Job & Recruitment Scam Detection System",
        subtitle="AI-driven threat intelligence engine combining NLP, Machine Learning, URL security auditing, and domain verification.",
        badge="PRODUCTION V2.4"
    )

    # Hero Banner Cards
    st.markdown("""
    <div style="background: linear-gradient(135deg, rgba(16, 24, 39, 0.9) 0%, rgba(30, 41, 59, 0.7) 100%);
                border: 1px solid rgba(0, 240, 255, 0.3); border-radius: 12px; padding: 24px; margin-bottom: 24px;">
        <h2 style="color: #F8FAFC; margin-top: 0; font-size: 22px;">
            Defending Job Seekers Against Advanced Recruitment Fraud & Phishing
        </h2>
        <p style="color: #94A3B8; font-size: 15px; line-height: 1.6;">
            Employment scams cost victims hundreds of millions annually through identity theft, fake equipment checks,
            and registration fees. This system implements an academic-grade cybersecurity pipeline that merges
            state-of-the-art Natural Language Processing with multi-layered domain verification to detect subtle fraud cues.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Quick Action Buttons
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("🔍 Analyze a Job Posting", use_container_width=True, type="primary"):
            st.session_state["current_page"] = "Detect Job"
            st.rerun()
    with col2:
        if st.button("📊 View Threat Dashboard", use_container_width=True):
            st.session_state["current_page"] = "Dashboard"
            st.rerun()
    with col3:
        if st.button("🛡️ Learn About Scam Vectors", use_container_width=True):
            st.session_state["current_page"] = "Security Guide"
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    # Key Architecture Pillars (Feature Cards)
    st.markdown("### ⚡ Multi-Layered Threat Defense Architecture")

    fcol1, fcol2, fcol3 = st.columns(3)

    with fcol1:
        st.markdown("""
        <div class="cyber-card" style="height: 100%;">
            <div style="font-size: 28px; margin-bottom: 10px;">🤖</div>
            <h4 style="color: #00F0FF; margin: 0 0 8px 0;">AI & NLP Text Classification</h4>
            <p style="color: #94A3B8; font-size: 13px; line-height: 1.5;">
                Trained on real-world employment scam corpora (EMSCAD benchmark) using TF-IDF n-grams
                and machine learning to isolate linguistic deception cues, urgency markers, and fee solicitations.
            </p>
        </div>
        """, unsafe_allow_html=True)

    with fcol2:
        st.markdown("""
        <div class="cyber-card" style="height: 100%;">
            <div style="font-size: 28px; margin-bottom: 10px;">🌐</div>
            <h4 style="color: #38BDF8; margin: 0 0 8px 0;">URL & Domain Security Audit</h4>
            <p style="color: #94A3B8; font-size: 13px; line-height: 1.5;">
                Safely inspects TLS/HTTPS encryption, URL shorteners, IP-literal hostnames,
                free-form hosting traps (Google Forms/Formspree), and redirect anomalies without intrusive probes.
            </p>
        </div>
        """, unsafe_allow_html=True)

    with fcol3:
        st.markdown("""
        <div class="cyber-card" style="height: 100%;">
            <div style="font-size: 28px; margin-bottom: 10px;">🏢</div>
            <h4 style="color: #A78BFA; margin: 0 0 8px 0;">Company Identity Verification</h4>
            <p style="color: #94A3B8; font-size: 13px; line-height: 1.5;">
                Cross-validates claimed employer identity, official web domain, and recruiter email.
                Flags free public emails (Gmail/Yahoo) used to falsely represent established enterprises.
            </p>
        </div>
        """, unsafe_allow_html=True)

    scol1, scol2 = st.columns(2)

    with scol1:
        st.markdown("""
        <div class="cyber-card" style="height: 100%;">
            <div style="font-size: 28px; margin-bottom: 10px;">⚖️</div>
            <h4 style="color: #FBBF24; margin: 0 0 8px 0;">Hybrid Cybersecurity Risk Engine</h4>
            <p style="color: #94A3B8; font-size: 13px; line-height: 1.5;">
                Calculates a transparent 0-100 risk score and level (LOW, MEDIUM, HIGH, CRITICAL)
                based on weighted red flags, credential demand severity, and mitigating authenticity factors.
            </p>
        </div>
        """, unsafe_allow_html=True)

    with scol2:
        st.markdown("""
        <div class="cyber-card" style="height: 100%;">
            <div style="font-size: 28px; margin-bottom: 10px;">💡</div>
            <h4 style="color: #34D399; margin: 0 0 8px 0;">Explainable AI & Audit Reports</h4>
            <p style="color: #94A3B8; font-size: 13px; line-height: 1.5;">
                Transparent "Why this posting was flagged" breakdown detailing lexical weights,
                red flag attribution, downloadable PDF threat dossiers, and actionable safety advisories.
            </p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Workflow Stepper Diagram
    st.markdown("### 🔄 Threat Inspection Pipeline")
    st.markdown("""
    ```
    [Job Submission] ──> [Input Sanitization] ──> [TF-IDF & NLP Analysis] ──> [ML Inference]
                                                                                   │
    [Explainable Dossier] <── [Risk Engine (0-100)] <── [Domain Consistency] <── [URL Security]
    ```
    """)
