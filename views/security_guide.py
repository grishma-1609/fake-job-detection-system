"""
Security Guide Page:
In-depth cybersecurity educational resource detailing recruitment scam vectors,
warning indicators, verification methodologies, and safe employment practices.
"""

import streamlit as st
from utils.styles import render_cyber_header


def render_security_guide():
    """Renders comprehensive cybersecurity awareness and education guide."""
    render_cyber_header(
        title="Recruitment Fraud & Cybersecurity Threat Guide",
        subtitle="Tactical intelligence and defense countermeasures against modern employment scams and social engineering.",
        badge="CYBERSECURITY INTELLIGENCE"
    )

    st.markdown("""
    > [!NOTE]
    > **Educational Notice**: This guide provides domain-expert cybersecurity information.
    > The automated ML model evaluates probability patterns, whereas this guide covers operational
    > threat techniques, attacker psychology, and manual verification procedures.
    """)

    # Category Accordion / Tabs
    t_typologies, t_redflags, t_verification, t_reporting = st.tabs([
        "🚨 Scam Typologies",
        "🚩 Warning Signs Checklist",
        "🔍 Technical Verification Guide",
        "⚖️ Reporting & Countermeasures",
    ])

    with t_typologies:
        st.markdown("### Common Recruitment Cyber Threat Typologies")

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("""
            <div class="cyber-card">
                <h4 style="color: #EF4444; margin-top: 0;">1. Fake Equipment / Check Overpayment Scam</h4>
                <p style="color: #94A3B8; font-size: 14px; line-height: 1.5;">
                    <strong>Attack Vector:</strong> The scammer offers an immediate remote position and emails a counterfeit
                    cashier's check ($2,000–$5,000) for "home office equipment." The victim is instructed to deposit the check
                    and immediately wire funds back to a "certified hardware vendor."
                </p>
                <p style="color: #F87171; font-size: 13px;">
                    <strong>Impact:</strong> Banks credit checks provisionally, but the check bounces days later, leaving
                    the victim legally responsible for the entire transferred amount.
                </p>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("""
            <div class="cyber-card">
                <h4 style="color: #F59E0B; margin-top: 0;">2. Telegram / WhatsApp Crypto Task Fraud</h4>
                <p style="color: #94A3B8; font-size: 14px; line-height: 1.5;">
                    <strong>Attack Vector:</strong> Victims are solicited via unsolicited SMS or messaging apps for high-paying
                    "data optimization," "app rating," or "crypto affiliate" roles. After minor initial payouts, victims are
                    locked into tiered "recharge tasks" requiring upfront crypto deposits to release claimed earnings.
                </p>
                <p style="color: #FBBF24; font-size: 13px;">
                    <strong>Impact:</strong> Victims lose substantial cryptocurrency assets with zero recourse.
                </p>
            </div>
            """, unsafe_allow_html=True)

        with col2:
            st.markdown("""
            <div class="cyber-card">
                <h4 style="color: #38BDF8; margin-top: 0;">3. Corporate Impersonation & Phishing ATS</h4>
                <p style="color: #94A3B8; font-size: 14px; line-height: 1.5;">
                    <strong>Attack Vector:</strong> Threat actors scrape legitimate vacancies from Fortune 500 portals, duplicate
                    company logos, and construct look-alike phishing domains (e.g. <code>amazon-careers-verify.com</code>).
                    They conduct text-only interviews via Signal or Skype.
                </p>
                <p style="color: #60A5FA; font-size: 13px;">
                    <strong>Impact:</strong> Harvests Social Security Numbers (SSN), banking routing numbers, and identity documents.
                </p>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("""
            <div class="cyber-card">
                <h4 style="color: #A78BFA; margin-top: 0;">4. Registration & Background Check Fee Fraud</h4>
                <p style="color: #94A3B8; font-size: 14px; line-height: 1.5;">
                    <strong>Attack Vector:</strong> Applicants are congratulated on receiving a job offer without formal interviews,
                    but told they must pay a mandatory $50–$250 fee for a "pre-employment background check" or "software license"
                    via non-reversible methods (Zelle, UPI, gift cards).
                </p>
                <p style="color: #C084FC; font-size: 13px;">
                    <strong>Impact:</strong> Direct financial theft and disclosure of payment card details.
                </p>
            </div>
            """, unsafe_allow_html=True)

    with t_redflags:
        st.markdown("### 🚨 The 8 Critical Red Flags of Recruitment Fraud")

        flags_data = [
            ("Requests for Any Upfront Payment", "Legitimate corporations NEVER charge candidates for interviews, software licenses, uniforms, or background checks.", "CRITICAL"),
            ("Interviews Conducted Exclusively via Chat", "Legitimate employers conduct video calls (Teams/Zoom/Google Meet) or in-person interviews, never text-only chats on Telegram or WhatsApp.", "HIGH"),
            ("Unsolicited Job Offers Without Application", "Receiving an offer for a job you never applied for is almost always a mass-phishing campaign.", "HIGH"),
            ("Free Public Email Domains for Corporate Hiring", "Recruiters claiming to represent enterprise companies using <code>@gmail.com</code> or <code>@yahoo.com</code> rather than corporate domains.", "HIGH"),
            ("Unrealistic Salary for Entry-Level Qualifications", "Promises of $40–$100/hr for simple data entry or virtual typing with zero required experience.", "MEDIUM"),
            ("Extreme Urgency & High-Pressure Tactics", "Demands to accept an offer within hours or make an immediate deposit before vacancies close.", "HIGH"),
            ("Requests for Sensitive PII Prior to Formal Offer", "Asking for SSN, passport scans, or banking details during the initial screening stage.", "CRITICAL"),
            ("Application Hosted on Generic Form Builders", "Using free Google Forms or Typeform links rather than an enterprise Applicant Tracking System (ATS).", "MEDIUM"),
        ]

        for flag, desc, severity in flags_data:
            badge_color = "#EF4444" if severity == "CRITICAL" else "#F59E0B" if severity == "HIGH" else "#3B82F6"
            st.markdown(f"""
            <div style="background: #111827; border: 1px solid #1E293B; border-radius: 8px; padding: 14px; margin-bottom: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <strong style="color: #F8FAFC; font-size: 15px;">{flag}</strong>
                    <span style="background: rgba(239, 68, 68, 0.15); color: {badge_color}; border: 1px solid {badge_color}; border-radius: 12px; font-size: 11px; padding: 2px 8px; font-weight: 700;">
                        {severity}
                    </span>
                </div>
                <p style="color: #94A3B8; font-size: 13px; margin: 6px 0 0 0;">{desc}</p>
            </div>
            """, unsafe_allow_html=True)

    with t_verification:
        st.markdown("### 🔍 Technical Verification SOP (Standard Operating Procedure)")
        st.markdown("""
        Follow this 4-step checklist before responding to suspicious recruiters:

        1. **Cross-Check the Official Company Careers Portal:**
           - Do not use the link in the message. Open a browser and navigate to the company's official domain directly.
           - Search their career listings for the exact Requisition ID. If it does not exist, contact HR via their public phone directory.

        2. **Inspect Email Headers (SPF, DKIM, DMARC):**
           - Check the full headers of the recruiter's email.
           - Ensure the *From* address matches the authenticated *Return-Path* domain. Scammers frequently spoof the display name.

        3. **Domain Age & WHOIS Lookup:**
           - Use tools like ICANN WHOIS to check domain registration date.
           - Domains registered within the past 1–90 days claiming to represent established brands are primary indicators of fraud.

        4. **Verify Recruiter Profiles on LinkedIn:**
           - Search the recruiter's full name and verify their tenure, connection count, and mutual network connections.
           - Be wary of accounts created recently with fewer than 50 connections and stock photo avatars.
        """)

    with t_reporting:
        st.markdown("### ⚖️ Incident Escalation & Reporting Channels")
        st.markdown("""
        If you have encountered or fallen victim to a recruitment scam, report the incident immediately:

        - **United States:** [FBI Internet Crime Complaint Center (IC3)](https://www.ic3.gov) & [FTC Report Fraud](https://reportfraud.ftc.gov)
        - **India:** [National Cyber Crime Reporting Portal](https://cybercrime.gov.in) (Call 1930)
        - **United Kingdom:** [Action Fraud](https://www.actionfraud.police.uk)
        - **Hosting Platforms:** Flag fraudulent job postings on LinkedIn, Indeed, Glassdoor, or the domain registrar abused by the scammer.
        - **Financial Institutions:** If you provided bank details or deposited a suspicious check, contact your bank's fraud department immediately to freeze accounts.
        """)
