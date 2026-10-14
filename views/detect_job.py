"""
Detect Job Page:
Core inspection interface supporting manual entry, pasted job description, and URL inspection.
Executes complete threat pipeline and displays transparent explainable results.
"""

import time
import streamlit as st

from database.json_db import get_db
from models.predictor import get_predictor
from modules.company_verifier import CompanyVerifier
from modules.explainability import ExplainabilityEngine
from modules.nlp_analyzer import NLPAnalyzer
from modules.risk_engine import RiskEngine
from modules.scam_classifier import ScamClassifier
from modules.url_analyzer import URLSecurityAnalyzer
from utils.helpers import generate_pdf_report, render_risk_badge_html
from utils.styles import render_cyber_header
from utils.validators import validate_job_submission


def render_detect_job():
    """Renders Job Analysis interface and runs threat detection pipeline."""
    render_cyber_header(
        title="Job Posting Threat Detection Engine",
        subtitle="Submit a job vacancy or recruiting campaign to initiate comprehensive cybersecurity analysis.",
        badge="HEURISTIC & ML SCANNERS ONLINE"
    )

    db = get_db()
    predictor = get_predictor()
    nlp_analyzer = NLPAnalyzer()
    url_analyzer = URLSecurityAnalyzer()
    company_verifier = CompanyVerifier()
    scam_classifier = ScamClassifier()
    risk_engine = RiskEngine()
    explainability_engine = ExplainabilityEngine(
        vectorizer=predictor.vectorizer, model=predictor.model
    )

    # Input Mode Tabs
    tab_manual, tab_paste, tab_sample = st.tabs([
        "📝 Detailed Form Submission",
        "📋 Quick Pasted Description",
        "🧪 Test Sample Scenarios",
    ])

    job_input = {
        "title": "",
        "company": "",
        "location": "Remote / Nationwide",
        "salary": "",
        "employment_type": "Full-time",
        "experience": "Mid-Senior level",
        "education": "Bachelor's Degree",
        "description": "",
        "requirements": "",
        "benefits": "",
        "email": "",
        "website": "",
        "url": "",
    }

    # -------------------------------------------------------------
    # Tab 1: Detailed Form
    # -------------------------------------------------------------
    with tab_manual:
        st.markdown("#### Enter Job Details")
        c1, c2 = st.columns(2)
        with c1:
            form_title = st.text_input("Job Title *", placeholder="e.g. Senior Security Analyst", key="f_title")
            form_company = st.text_input("Company Name", placeholder="e.g. Apex Cyber Systems", key="f_comp")
            form_location = st.text_input("Location", value="Remote", key="f_loc")
            form_salary = st.text_input("Salary / Compensation", placeholder="e.g. $95,000 - $115,000 / year", key="f_sal")
        with c2:
            form_emp_type = st.selectbox("Employment Type", ["Full-time", "Part-time", "Contract", "Temporary", "Other"], key="f_emp")
            form_exp = st.selectbox("Experience Level", ["Entry level", "Associate", "Mid-Senior level", "Director", "Not Applicable"], key="f_exp")
            form_edu = st.selectbox("Education Level", ["High School", "Bachelor's Degree", "Master's Degree", "Doctorate", "Unspecified"], key="f_edu")
            form_email = st.text_input("Recruiter Email", placeholder="e.g. hr@company.com", key="f_email")

        c3, c4 = st.columns(2)
        with c3:
            form_website = st.text_input("Company Website", placeholder="e.g. https://apexcybersystems.com", key="f_web")
        with c4:
            form_url = st.text_input("Application / Submission Link", placeholder="e.g. https://careers.company.com/apply/102", key="f_url")

        form_desc = st.text_area("Job Description *", height=150, placeholder="Paste detailed job role and responsibilities...", key="f_desc")
        form_req = st.text_area("Requirements / Qualifications", height=90, placeholder="Required skills, certifications, and experience...", key="f_req")
        form_ben = st.text_area("Benefits / Compensation Package", height=70, placeholder="Health insurance, 401k, PTO...", key="f_ben")

        if st.button("🚀 Analyze Job (Form)", type="primary", use_container_width=True, key="btn_form"):
            job_input = {
                "title": form_title,
                "company": form_company,
                "location": form_location,
                "salary": form_salary,
                "employment_type": form_emp_type,
                "experience": form_exp,
                "education": form_edu,
                "description": form_desc,
                "requirements": form_req,
                "benefits": form_ben,
                "email": form_email,
                "website": form_website,
                "url": form_url,
            }
            st.session_state["trigger_analysis"] = True
            st.session_state["active_job_input"] = job_input

    # -------------------------------------------------------------
    # Tab 2: Quick Paste
    # -------------------------------------------------------------
    with tab_paste:
        st.markdown("#### Quick Job Description Ingestion")
        st.caption("Paste the full job posting text below. Our preprocessor will analyze it directly.")
        p_title = st.text_input("Job Title", placeholder="e.g. Data Entry Assistant", key="p_title")
        p_company = st.text_input("Claimed Company (Optional)", placeholder="e.g. Global Tech", key="p_comp")
        p_text = st.text_area("Pasted Posting Text *", height=220, placeholder="Paste email, message, or entire job description here...", key="p_text")
        p_url = st.text_input("Application Link (Optional)", placeholder="e.g. http://bit.ly/quick-apply", key="p_url")

        if st.button("🚀 Analyze Job (Pasted)", type="primary", use_container_width=True, key="btn_paste"):
            job_input = {
                "title": p_title or "Unspecified Position",
                "company": p_company or "Unspecified Employer",
                "location": "Unspecified",
                "salary": "Unspecified",
                "employment_type": "Other",
                "experience": "Not Applicable",
                "education": "Unspecified",
                "description": p_text,
                "requirements": "",
                "benefits": "",
                "email": "",
                "website": "",
                "url": p_url,
            }
            st.session_state["trigger_analysis"] = True
            st.session_state["active_job_input"] = job_input

    # -------------------------------------------------------------
    # Tab 3: Sample Test Scenarios
    # -------------------------------------------------------------
    with tab_sample:
        st.markdown("#### Load Preset Evaluation Scenarios")
        st.caption("Test the system against representative benchmark cases.")
        sample_choice = st.radio(
            "Select Scenario:",
            [
                "🚨 Fake Check & Wire Transfer Equipment Scam",
                "🚨 High-Paying Telegram Crypto Task Scam",
                "⚠️ Free-Email Recruiter Discrepancy (Impersonation)",
                "✅ Legitimate Enterprise Cloud Software Engineer",
            ]
        )

        if st.button("📥 Load Selected Scenario", key="btn_load_sample"):
            if "Fake Check" in sample_choice:
                sample_data = {
                    "title": "Data Entry Clerk - Remote - Immediate Hire",
                    "company": "FastLogistics Global",
                    "location": "Remote / Anywhere",
                    "salary": "$45.00 / hour guaranteed",
                    "employment_type": "Part-time",
                    "experience": "Not Applicable",
                    "education": "High School",
                    "description": "Urgent hiring! Earn $45/hour working simple data entry from home. No interview required! We will mail you a cashier check for $3,500 to purchase home office hardware. Deposit this check into your personal bank account, keep your advance payment, and immediately wire transfer the rest via Western Union to our vendor. Send bank details and passport copy to start.",
                    "requirements": "Must have active bank account for check deposit. No experience necessary. Hurry limited spots!",
                    "benefits": "Guaranteed daily payout, free laptop provided after $120 registration fee.",
                    "email": "hr.fastlogistics@gmail.com",
                    "website": "https://fastlogistics-careers-portal.xyz",
                    "url": "http://bit.ly/fastlogistics-apply-now",
                }
            elif "Telegram Crypto" in sample_choice:
                sample_data = {
                    "title": "Part-Time Media Rater - Earn $500 Daily",
                    "company": "Decentralized Marketing Group",
                    "location": "Online / Mobile",
                    "salary": "$300 - $800 daily",
                    "employment_type": "Temporary",
                    "experience": "Not Applicable",
                    "education": "Unspecified",
                    "description": "Earn $300 to $800 daily simply rating mobile applications on your phone! 100% financial freedom. Payouts distributed immediately in USDT cryptocurrency. Contact our recruiter on Telegram @easy_payouts_hr right now to receive your registration code and start working immediately.",
                    "requirements": "Smartphone with Telegram app and cryptocurrency wallet.",
                    "benefits": "Instant crypto commissions, daily withdraws.",
                    "email": "recruiting@yahoo.com",
                    "website": "",
                    "url": "https://t.me/easy_payouts_hr",
                }
            elif "Free-Email" in sample_choice:
                sample_data = {
                    "title": "Executive Marketing Assistant",
                    "company": "Amazon Inc",
                    "location": "Seattle, WA / Remote",
                    "salary": "$75,000 / year",
                    "employment_type": "Full-time",
                    "experience": "Mid-Senior level",
                    "education": "Bachelor's Degree",
                    "description": "Seeking motivated assistant to coordinate marketing campaigns. We are hiring on behalf of Amazon corporate. Submit your resume and contact information.",
                    "requirements": "Bachelor's degree and 2 years marketing experience.",
                    "benefits": "Medical and dental insurance.",
                    "email": "amazon.recruiting.dept99@gmail.com",
                    "website": "https://amazon-staffing-agency.click",
                    "url": "https://amazon-staffing-agency.click/apply",
                }
            else:
                sample_data = {
                    "title": "Senior Cloud Infrastructure Engineer",
                    "company": "CloudScale Systems Inc",
                    "location": "San Francisco, CA (Hybrid)",
                    "salary": "$140,000 - $165,000 / year",
                    "employment_type": "Full-time",
                    "experience": "Mid-Senior level",
                    "education": "Bachelor's Degree",
                    "description": "We are seeking a Senior Cloud Infrastructure Engineer to design, deploy, and monitor our AWS Kubernetes clusters. You will collaborate with software engineering teams to improve CI/CD pipelines, ensure compliance with SOC 2 standards, and implement infrastructure as code using Terraform.",
                    "requirements": "5+ years of Linux system administration; 3+ years AWS architecture; Proficient with Terraform, Docker, and Kubernetes; Bachelor's degree in Computer Science or equivalent work experience.",
                    "benefits": "Comprehensive medical, dental, and vision; 401(k) with 5% employer match; 4 weeks PTO; $2,500 annual professional training allowance.",
                    "email": "careers@cloudscalesystems.com",
                    "website": "https://cloudscalesystems.com",
                    "url": "https://cloudscalesystems.com/careers/senior-infrastructure-engineer",
                }

            st.session_state["trigger_analysis"] = True
            st.session_state["active_job_input"] = sample_data
            st.success("Loaded sample scenario! Analysis starting...")

    # -------------------------------------------------------------
    # Execution & Threat Assessment Pipeline
    # -------------------------------------------------------------
    if st.session_state.get("trigger_analysis") and st.session_state.get("active_job_input"):
        active_job = st.session_state["active_job_input"]

        valid, errs = validate_job_submission(active_job)
        if not valid:
            for err in errs:
                st.error(f"⚠️ Validation Error: {err}")
            st.session_state["trigger_analysis"] = False
            return

        # Progress animation
        with st.status("Executing Multi-Layered Cybersecurity Threat Pipeline...", expanded=True) as status:
            st.write("1. 🧹 Sanitizing inputs and standardizing textual payloads...")
            time.sleep(0.15)

            st.write("2. 🔠 Extracting TF-IDF n-grams & linguistic urgency features...")
            composite_text = nlp_analyzer.build_composite_text(active_job)
            nlp_features = nlp_analyzer.extract_linguistic_features(composite_text)
            time.sleep(0.15)

            st.write("3. 🤖 Running Machine Learning textual deception classification...")
            ml_result = predictor.predict(composite_text)
            time.sleep(0.15)

            st.write("4. 🌐 Safely probing URL structure and TLS certificate integrity...")
            url_res = url_analyzer.analyze_url(active_job.get("url"), active_job.get("company"))
            time.sleep(0.15)

            st.write("5. 🏢 Cross-validating claimed company identity vs email/web domains...")
            comp_res = company_verifier.verify_consistency(
                active_job.get("company"), active_job.get("website"), active_job.get("email")
            )
            time.sleep(0.15)

            st.write("6. 🚨 Classifying recruitment fraud typologies and calculating risk score...")
            scam_cats = scam_classifier.classify_scam_categories(active_job, url_res, comp_res)
            risk_result = risk_engine.calculate_risk(
                active_job, ml_result, nlp_features, url_res, comp_res, scam_cats
            )
            time.sleep(0.1)

            st.write("7. 💡 Generating explainable AI factor attribution...")
            explanation_res = explainability_engine.explain_prediction(
                active_job,
                risk_result["prediction"],
                ml_result["fraud_probability"],
                nlp_features,
                risk_result["red_flags"],
                risk_result["trust_indicators"],
                scam_cats,
            )

            status.update(label="Threat Assessment Complete!", state="complete", expanded=False)

        # Build analysis record
        current_user = st.session_state.get("user") or {}
        user_id = current_user.get("id", "anonymous")

        analysis_record = {
            "user_id": user_id,
            "job_data": active_job,
            "prediction": risk_result["prediction"],
            "risk_score": risk_result["risk_score"],
            "risk_level": risk_result["risk_level"],
            "confidence": risk_result["confidence"],
            "scam_categories": scam_cats,
            "red_flags": risk_result["red_flags"],
            "trust_indicators": risk_result["trust_indicators"],
            "score_breakdown": risk_result["score_breakdown"],
            "recommended_action": risk_result["recommended_action"],
            "ml_result": ml_result,
            "url_analysis": url_res,
            "company_verification": comp_res,
            "explanation": explanation_res,
        }

        # Auto-persist analysis to DB
        saved_analysis = db.insert("analyses", analysis_record)
        st.session_state["latest_analysis"] = saved_analysis
        st.session_state["trigger_analysis"] = False

    # -------------------------------------------------------------
    # Display Latest Threat Assessment Report
    # -------------------------------------------------------------
    if "latest_analysis" in st.session_state and st.session_state["latest_analysis"]:
        res = st.session_state["latest_analysis"]
        st.markdown("---")
        st.markdown("## 🛡️ Executive Threat Assessment Findings")

        # Top Banner
        pred = res.get("prediction", "UNKNOWN")
        score = float(res.get("risk_score", 0))
        level = res.get("risk_level", "LOW")
        conf = float(res.get("confidence", 0))

        v1, v2, v3 = st.columns([1.5, 1, 1])
        with v1:
            st.markdown(render_risk_badge_html(level, score), unsafe_allow_html=True)
            st.markdown(f"<h3 style='margin-top: 8px;'>Verdict: <span style='color: {'#EF4444' if pred == 'FAKE' else '#F59E0B' if pred == 'SUSPICIOUS' else '#10B981'};'>{pred}</span></h3>", unsafe_allow_html=True)

        with v2:
            st.metric("Threat Score", f"{score:.0f} / 100", delta=f"{level} Risk", delta_color="inverse" if level in ("HIGH", "CRITICAL") else "normal")

        with v3:
            st.metric("Model Confidence", f"{conf:.1f}%")

        # Scam Typologies Pills
        scam_cats = res.get("scam_categories", [])
        if scam_cats:
            st.markdown("**Identified Scam Typologies:**")
            pills_html = "".join([f"<span class='cyber-pill'>⚠️ {cat}</span>" for cat in scam_cats])
            st.markdown(pills_html, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Tabbed Inspection Dossier
        t_flags, t_score, t_xai, t_url, t_comp, t_advisory = st.tabs([
            "🚩 Red Flags & Trust Indicators",
            "📊 Threat Score Decomposition",
            "🧠 Explainable AI Insights",
            "🌐 URL Security Probe",
            "🏢 Company Domain Audit",
            "🛡️ Cybersecurity Advisory",
        ])

        with t_flags:
            rf_col, tf_col = st.columns(2)
            with rf_col:
                st.markdown("##### 🚨 Detected Red Flags")
                flags = res.get("red_flags", [])
                if flags:
                    for f in flags:
                        st.markdown(f"<div class='flag-item'>✖ {f}</div>", unsafe_allow_html=True)
                else:
                    st.success("No critical red flags identified.")

            with tf_col:
                st.markdown("##### ✅ Positive Trust Indicators")
                trust = res.get("trust_indicators", [])
                if trust:
                    for t in trust:
                        st.markdown(f"<div class='trust-item'>✔ {t}</div>", unsafe_allow_html=True)
                else:
                    st.warning("No significant positive trust indicators identified.")

        with t_score:
            st.markdown("##### Transparent Risk Score Breakdown")
            breakdown = res.get("score_breakdown", [])
            if breakdown:
                for item in breakdown:
                    pts = item["points"]
                    color = "#EF4444" if pts > 0 else "#10B981"
                    sign = "+" if pts > 0 else ""
                    st.markdown(f"""
                    <div style="background: #111827; border: 1px solid #1E293B; border-radius: 8px; padding: 12px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <strong style="color: #F8FAFC;">{item['component']}</strong>
                            <div style="color: #94A3B8; font-size: 12px; margin-top: 3px;">{item['details']}</div>
                        </div>
                        <span style="font-weight: 800; font-size: 16px; color: {color}; font-family: monospace;">
                            {sign}{pts} pts
                        </span>
                    </div>
                    """, unsafe_allow_html=True)
            st.markdown(f"**Final Clamped Risk Score: `{score:.1f} / 100`**")

        with t_xai:
            st.markdown("##### Explainable Feature Attribution")
            exp = res.get("explanation", {})
            st.info(f"**Analysis Summary:** {exp.get('summary')}")

            c_risk, c_trust = st.columns(2)
            with c_risk:
                st.markdown("###### Top Fraud-Influencing Terms:")
                risk_tokens = exp.get("top_risk_tokens", [])
                if risk_tokens:
                    for tok, weight in risk_tokens:
                        st.markdown(f"- **`{tok}`** (Attribution: `+{weight}`)")
                else:
                    st.caption("No individual high-risk keywords isolated.")

            with c_trust:
                st.markdown("###### Top Authenticity-Influencing Terms:")
                trust_tokens = exp.get("top_trust_tokens", [])
                if trust_tokens:
                    for tok, weight in trust_tokens:
                        st.markdown(f"- **`{tok}`** (Attribution: `+{weight}`)")
                else:
                    st.caption("Standard neutral terminology.")

            st.caption(exp.get("disclaimer", ""))

        with t_url:
            st.markdown("##### Application URL Inspection")
            url_info = res.get("url_analysis", {})
            if url_info and url_info.get("analyzed"):
                u1, u2, u3 = st.columns(3)
                u1.metric("TLS/HTTPS Active", "Yes" if url_info.get("https_active") else "No Insecure")
                u2.metric("URL Shortened", "Yes (Masked)" if url_info.get("is_shortened") else "No")
                u3.metric("Free Form Service", "Yes (High Risk)" if url_info.get("is_free_form") else "No")

                st.write(f"**Target Domain:** `{url_info.get('domain')}`")
                st.write(f"**Safe Probe Status:** `{url_info.get('network_status')}`")
                if url_info.get("flags"):
                    for uf in url_info["flags"]:
                        st.markdown(f"<div class='flag-item'>⚠️ {uf}</div>", unsafe_allow_html=True)
            else:
                st.write("`URL analysis unavailable` (No valid URL provided or probe skipped)")

        with t_comp:
            st.markdown("##### Company & Recruiter Identity Cross-Check")
            comp_info = res.get("company_verification", {})
            st.write(f"**Claimed Company:** {comp_info.get('company_name') or 'N/A'}")
            st.write(f"**Website Domain:** `{comp_info.get('website_domain') or 'None'}`")
            st.write(f"**Recruiter Email Domain:** `{comp_info.get('email_domain') or 'None'}`")
            st.info(f"**Auditor Summary:** {comp_info.get('summary')}")

            if comp_info.get("flags"):
                for cf in comp_info["flags"]:
                    st.markdown(f"<div class='flag-item'>⚠️ {cf}</div>", unsafe_allow_html=True)
            if comp_info.get("trust_signals"):
                for ct in comp_info["trust_signals"]:
                    st.markdown(f"<div class='trust-item'>✔ {ct}</div>", unsafe_allow_html=True)

        with t_advisory:
            st.markdown("##### Recommended Cybersecurity Action")
            action = res.get("recommended_action", "")
            if pred == "FAKE":
                st.error(f"🛑 **ACTION REQUIRED:** {action}")
            elif pred == "SUSPICIOUS":
                st.warning(f"⚠️ **ACTION REQUIRED:** {action}")
            else:
                st.success(f"✅ **GUIDANCE:** {action}")

        st.markdown("<br>", unsafe_allow_html=True)

        # Export & Save Options
        act_col1, act_col2 = st.columns(2)
        with act_col1:
            pdf_bytes = generate_pdf_report(res)
            if pdf_bytes:
                st.download_button(
                    label="📄 Download Threat Dossier (PDF)",
                    data=pdf_bytes,
                    file_name=f"Threat_Report_{res.get('id', 'job')[:8]}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )
            else:
                st.caption("PDF generation library unavailable.")

        with act_col2:
            if st.button("💾 Save as Formal Incident Report", use_container_width=True):
                # Save into reports collection
                report_entry = {
                    "analysis_id": res.get("id"),
                    "title": res.get("job_data", {}).get("title"),
                    "company": res.get("job_data", {}).get("company"),
                    "prediction": res.get("prediction"),
                    "risk_score": res.get("risk_score"),
                    "risk_level": res.get("risk_level"),
                    "full_analysis": res,
                }
                db.insert("reports", report_entry)
                st.success("✅ Threat report permanently saved to Saved Reports repository!")
