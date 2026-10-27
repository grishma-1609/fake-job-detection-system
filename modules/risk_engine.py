"""
Cybersecurity Risk Engine:
Aggregates ML predictions, NLP features, URL security scans, company verification,
and heuristic indicator rules into a unified transparent 0-100 Risk Score.
Applies rigorous 3-outcome decision rules:
  1. 'Likely Genuine' - sufficient positive evidence and low risk.
  2. 'Suspicious — Further Verification Required' - credible fraud indicators or conflicting evidence.
  3. 'Insufficient Evidence' - not enough reliable information to conclude.
"""

import re
from typing import Any, Dict, List, Tuple


OUTCOME_LIKELY_GENUINE = "Likely Genuine"
OUTCOME_SUSPICIOUS = "Suspicious — Further Verification Required"
OUTCOME_INSUFFICIENT = "Insufficient Evidence"

ALL_OUTCOMES = [OUTCOME_LIKELY_GENUINE, OUTCOME_SUSPICIOUS, OUTCOME_INSUFFICIENT]


class RiskEngine:
    """Evaluates combined cybersecurity risk for job postings."""

    def __init__(self):
        pass

    def calculate_risk(
        self,
        job_data: Dict[str, Any],
        ml_result: Dict[str, Any],
        nlp_features: Dict[str, Any],
        url_analysis: Dict[str, Any],
        company_analysis: Dict[str, Any],
        scam_categories: List[str],
    ) -> Dict[str, Any]:
        """
        Calculates transparent risk score (0-100), risk level, red flags,
        trust indicators, confidence, and recommended safe action across 3 distinct outcomes.
        """
        red_flags: List[str] = []
        trust_indicators: List[str] = []
        score_breakdown: List[Dict[str, Any]] = []

        total_risk_points = 0.0

        # ---------------------------------------------------------
        # 1. Base ML Text Component (0 - 25 points weight)
        # ---------------------------------------------------------
        ml_prob = float(ml_result.get("fraud_probability", 0.0))
        ml_pred = ml_result.get("prediction", "GENUINE")
        ml_points = round(ml_prob * 25.0, 1)
        total_risk_points += ml_points
        score_breakdown.append({
            "component": "ML Linguistic Fraud Probability",
            "points": ml_points,
            "max": 25,
            "details": f"Model probability of fraudulent text: {ml_prob*100:.1f}% (linguistic style indicator only)",
        })

        if ml_prob >= 0.60 or ml_pred == "FAKE":
            red_flags.append(f"ML textual model noted linguistic similarity to known scam corpora ({ml_prob*100:.1f}%)")
        elif ml_prob <= 0.25:
            trust_indicators.append(f"ML model noted authentic professional vocabulary ({(1.0-ml_prob)*100:.1f}% genuine confidence)")

        # ---------------------------------------------------------
        # 2. High-Risk Rule Checks (+10 to +35 points each)
        # ---------------------------------------------------------
        desc_lower = str(job_data.get("description", "")).lower()
        reqs_lower = str(job_data.get("requirements", "")).lower()
        benefits_lower = str(job_data.get("benefits", "")).lower()
        salary_str = str(job_data.get("salary", "")).lower()
        title_str = str(job_data.get("title", "")).lower()
        combined_text = f"{title_str} {desc_lower} {reqs_lower} {benefits_lower} {salary_str}"

        # 2a. Requests Money/Payment (Documented indicator)
        payment_matches = re.findall(
            r"\b(?:registration\s+fee|application\s+fee|processing\s+fee|deposit|training\s+fee|background\s+check\s+fee|software\s+license\s+fee|courier\s+fee|wire\s+transfer|moneygram|western\s+union|gift\s+card|crypto|cashier\s+check|check\s+cashing)\b",
            combined_text,
        )
        if payment_matches:
            pts = 35
            total_risk_points += pts
            red_flags.append(f"Requests money or payment from applicant ({', '.join(set(payment_matches))})")
            score_breakdown.append({
                "component": "Upfront Payment/Fee Demand",
                "points": pts,
                "max": 35,
                "details": f"Applicant asked for financial outlay: {payment_matches[0]}",
            })

        # 2b. Requests Banking/Sensitive Details Upfront (Documented indicator)
        bank_matches = re.findall(
            r"\b(?:bank\s+account|routing\s+number|credit\s+card|debit\s+card|ssn|social\s+security|passport\s+copy|national\s+id)\b",
            combined_text,
        )
        if bank_matches:
            pts = 30
            total_risk_points += pts
            red_flags.append(f"Requests sensitive financial or identity details upfront ({', '.join(set(bank_matches))})")
            score_breakdown.append({
                "component": "Sensitive Credential/PII Request",
                "points": pts,
                "max": 30,
                "details": f"Demands personal credentials: {bank_matches[0]}",
            })

        # 2c. Unrealistic Salary / Exaggerated Claims (Documented indicator)
        unrealistic_salary = False
        if any(w in salary_str for w in ["$5000/week", "$1000/day", "$100/hr", "guaranteed income", "50000 daily"]):
            unrealistic_salary = True
        elif any(p in combined_text for p in ["earn $500 daily", "make thousands weekly", "earn $1000 daily", "100% guaranteed income", "$4500 monthly"]):
            unrealistic_salary = True

        if unrealistic_salary:
            pts = 20
            total_risk_points += pts
            red_flags.append("Unrealistically high compensation claim for entry-level work")
            score_breakdown.append({
                "component": "Unrealistic Compensation Claim",
                "points": pts,
                "max": 20,
                "details": "Salary claims far exceed industry benchmarks for role requirements.",
            })

        # 2d. Urgent / High-pressure language (Documented indicator)
        if nlp_features.get("urgency_score", 0) >= 0.4:
            pts = 10
            total_risk_points += pts
            red_flags.append("High-pressure urgency language and excessive punctuation detected")
            score_breakdown.append({
                "component": "Urgency & Psychological Coercion",
                "points": pts,
                "max": 10,
                "details": "Urgency cues intended to rush applicant into uncritical action.",
            })

        # ---------------------------------------------------------
        # 3. URL Security Component (Evaluated & labeled separately)
        # ---------------------------------------------------------
        url_validity = "No URL Provided"
        is_reserved_url = False
        is_unreachable_url = False
        url_is_live_valid = False

        if url_analysis and url_analysis.get("analyzed"):
            url_validity = url_analysis.get("url_validity", "Analyzed")
            is_reserved_url = bool(url_analysis.get("is_reserved_domain"))
            url_is_live_valid = bool(url_analysis.get("is_live_valid"))
            net_stat = str(url_analysis.get("network_status", "")).lower()
            is_unreachable_url = "unreachable" in net_stat or "timeout" in net_stat

            # Only actual security hazard points are added (shortener, IP literal, free form host, mismatch)
            # Reserved domains (.example) and unreachable URLs do NOT add raw fraud risk points
            url_pts = float(url_analysis.get("risk_points", 0)) * 0.35
            if is_reserved_url:
                red_flags.append(f"URL: {url_analysis.get('url_validity_details')}")
            elif is_unreachable_url:
                red_flags.append(f"URL: {url_analysis.get('url_validity_details')}")
            elif url_pts > 0:
                total_risk_points += url_pts
                score_breakdown.append({
                    "component": "URL Security Hazards",
                    "points": round(url_pts, 1),
                    "max": 35,
                    "details": f"{len(url_analysis.get('flags', []))} URL anomaly flags detected.",
                })
                for flag in url_analysis.get("flags", []):
                    red_flags.append(f"URL: {flag}")
            elif url_analysis.get("https_active") and url_is_live_valid:
                trust_indicators.append("Application URL utilizes secure TLS/HTTPS on an active, established domain")

        # ---------------------------------------------------------
        # 4. Company & Domain Verification Component
        # ---------------------------------------------------------
        comp_status = "UNVERIFIED"
        if company_analysis:
            comp_status = company_analysis.get("verification_status", "UNVERIFIED")
            comp_pts = float(company_analysis.get("risk_points", 0)) * 0.30

            # Only add points if there is an active discrepancy/impersonation (not if merely unverified)
            if comp_status == "DISCREPANCY" and comp_pts > 0:
                total_risk_points += comp_pts
                score_breakdown.append({
                    "component": "Company & Domain Inconsistency",
                    "points": round(comp_pts, 1),
                    "max": 30,
                    "details": f"{len(company_analysis.get('flags', []))} domain discrepancy flags.",
                })
                for flag in company_analysis.get("flags", []):
                    red_flags.append(f"Domain/Identity: {flag}")
            elif comp_status == "UNVERIFIED":
                summary_text = company_analysis.get("summary", "Company information unverified.")
                if not any("Company information" in f or "Company domain" in f for f in red_flags):
                    red_flags.append(f"Domain/Identity: {summary_text}")

            for trust in company_analysis.get("trust_signals", []):
                trust_indicators.append(f"Domain: {trust}")

        # ---------------------------------------------------------
        # 5. Out-of-band Messaging & Structural Factors
        # ---------------------------------------------------------
        chat_matches = [app for app in ["telegram", "whatsapp", "signal app", "t.me", "wa.me"] if app in combined_text]
        if chat_matches:
            pts = 20
            total_risk_points += pts
            red_flags.append("Directs candidate to encrypted chat platforms (Telegram/WhatsApp) for interviews")
            score_breakdown.append({
                "component": "Out-of-Band Messaging Channel",
                "points": pts,
                "max": 20,
                "details": f"Recruiter conducts hiring over anonymous messaging platforms ({chat_matches[0]}).",
            })

        word_count = nlp_features.get("word_count", 0)
        if word_count < 25 and comp_status == "UNVERIFIED":
            score_breakdown.append({
                "component": "Brief Posting Payload",
                "points": 5,
                "max": 5,
                "details": "Posting text is relatively brief; requires closer review.",
            })
            total_risk_points += 5
        elif word_count > 80 and not payment_matches and not bank_matches and not chat_matches:
            trust_indicators.append("Comprehensive, detailed job responsibilities and qualification criteria")

        # ---------------------------------------------------------
        # 6. Trust Mitigations (Subtract points for verified authentic signals)
        # Trust discount MUST NEVER apply if red flags, discrepancies, or scams exist
        # ---------------------------------------------------------
        has_threat_flags = bool(
            payment_matches or
            bank_matches or
            chat_matches or
            (comp_status == "DISCREPANCY") or
            (url_analysis and not url_analysis.get("is_safe", True)) or
            scam_categories or
            ml_prob >= 0.40
        )

        trust_discount = 0.0
        if trust_indicators and not has_threat_flags:
            trust_discount = min(20.0, len(trust_indicators) * 5.0)
            total_risk_points = max(0.0, total_risk_points - trust_discount)
            score_breakdown.append({
                "component": "Authenticity Trust Credits",
                "points": -round(trust_discount, 1),
                "max": 0,
                "details": f"Deducted for {len(trust_indicators)} verified authentic trust attributes.",
            })

        # Final Risk Score clamped to [0, 100]
        final_risk_score = min(100.0, max(0.0, round(total_risk_points, 1)))

        # ---------------------------------------------------------
        # 7. Final Classification (3 Distinct Outcomes)
        # 1. Likely Genuine
        # 2. Suspicious — Further Verification Required
        # 3. Insufficient Evidence
        # ---------------------------------------------------------
        has_critical_indicators = bool(
            payment_matches or
            bank_matches or
            (comp_status == "DISCREPANCY") or
            (chat_matches and (unrealistic_salary or ml_prob > 0.35)) or
            any(cat in scam_categories for cat in [
                "Payment/Registration Fee Scam",
                "Phishing/Information Harvesting",
                "Personal Information Scam",
                "Company Impersonation"
            ])
        )

        has_conflicting_evidence = bool(
            # Valid company name but suspicious recruitment URL (shortened, free form, IP, or mismatch)
            (comp_status == "VERIFIED" and url_analysis.get("analyzed") and (
                url_analysis.get("is_shortened") or
                url_analysis.get("is_free_form") or
                url_analysis.get("is_ip_literal") or
                url_analysis.get("company_mismatch") or
                not url_analysis.get("is_safe")
            )) or
            # Fabricated / unregistered domain paired with elevated ML fraud score or scam features
            (is_unreachable_url and ml_prob >= 0.45) or
            # Suspicious application link typology
            "Suspicious Application Link" in scam_categories or
            (url_analysis.get("analyzed") and (url_analysis.get("is_shortened") or url_analysis.get("is_free_form") or url_analysis.get("is_ip_literal")))
        )

        has_ml_fraud_alert = bool(
            ml_prob >= 0.60 or
            (ml_pred == "FAKE" and (chat_matches or unrealistic_salary or not url_analysis.get("is_safe", True)))
        )

        is_suspicious = (
            has_critical_indicators or
            has_conflicting_evidence or
            has_ml_fraud_alert or
            final_risk_score >= 40.0
        )

        if is_suspicious:
            prediction = OUTCOME_SUSPICIOUS
            if final_risk_score >= 65.0 or payment_matches or bank_matches:
                risk_level = "CRITICAL"
            else:
                risk_level = "HIGH"

        elif (
            comp_status == "VERIFIED" and
            not is_reserved_url and
            not is_unreachable_url and
            ml_prob < 0.35 and
            final_risk_score < 25.0 and
            len(trust_indicators) >= 2 and
            len(scam_categories) == 0 and
            not any("Insecure HTTP" in f for f in red_flags)
        ):
            prediction = OUTCOME_LIKELY_GENUINE
            risk_level = "LOW"

        else:
            # Insufficient verifiable corporate evidence or unverified AI draft,
            # but no definitive fraud indicators detected
            prediction = OUTCOME_INSUFFICIENT
            risk_level = "LOW" if final_risk_score < 25.0 else "MEDIUM"

        # Calculate Confidence
        if prediction == OUTCOME_SUSPICIOUS:
            confidence = min(98.5, max(75.0, 55.0 + (final_risk_score * 0.45)))
        elif prediction == OUTCOME_LIKELY_GENUINE:
            confidence = min(96.0, max(75.0, 55.0 + ((100.0 - final_risk_score) * 0.40)))
        else:
            confidence = min(75.0, max(50.0, 50.0 + abs(30.0 - final_risk_score)))

        # ---------------------------------------------------------
        # 8. Actionable Recommended Safe Action & Disclaimer
        # ---------------------------------------------------------
        disclaimer = (
            "Notice: This assessment is a cybersecurity decision-support evaluation based on documented "
            "indicators and available data. None of the outcomes (Likely Genuine, Suspicious — Further Verification Required, "
            "Insufficient Evidence) is an absolute legal guarantee of authenticity or fraud."
        )

        if prediction == OUTCOME_SUSPICIOUS:
            recommended_action = (
                "DO NOT ENGAGE: Cease all communication immediately. Never send money, pay registration or equipment "
                "fees, deposit checks, or disclose banking, UPI, or passport details. Legitimate employers will never "
                "ask for upfront payments. Report this posting to cybercrime authorities and the host platform. "
                "(Note: Assessment is decision-support, not an absolute guarantee)."
            )
        elif prediction == OUTCOME_INSUFFICIENT:
            recommended_action = (
                "INDEPENDENT VERIFICATION REQUIRED: Posting does not display explicit fraud demands, but lacks verifiable "
                "corporate contact channels or live application infrastructure. Before submitting resumes or personal information, "
                "independently locate and verify the employer via official corporate directories or primary websites. "
                "Do not treat this posting as guaranteed authentic or fraudulent."
            )
        else:
            recommended_action = (
                "SAFE TO PROCEED WITH STANDARD CARE: Posting displays consistent corporate identity, authentic domain verification, "
                "and low risk indicators. Follow standard job application safety: verify interview links and apply via official "
                "company portals. (Note: Even for likely genuine postings, remain vigilant against phishing)."
            )

        return {
            "prediction": prediction,
            "prediction_label": prediction,
            "risk_score": final_risk_score,
            "risk_level": risk_level,
            "confidence": round(confidence, 1),
            "red_flags": list(dict.fromkeys(red_flags)),
            "trust_indicators": list(dict.fromkeys(trust_indicators)),
            "score_breakdown": score_breakdown,
            "recommended_action": recommended_action,
            "disclaimer": disclaimer,
            "ml_fraud_probability": ml_prob,
            "url_validity": url_validity,
            "company_verification_status": comp_status,
        }
