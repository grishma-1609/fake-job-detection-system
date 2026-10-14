"""
Cybersecurity Risk Engine:
Aggregates ML predictions, NLP features, URL security scans, company verification,
and heuristic indicator rules into a unified transparent 0-100 Risk Score.
"""

import re
from typing import Any, Dict, List, Tuple


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
        trust indicators, confidence, and recommended safe action.
        """
        red_flags: List[str] = []
        trust_indicators: List[str] = []
        score_breakdown: List[Dict[str, Any]] = []

        total_risk_points = 0.0

        # ---------------------------------------------------------
        # 1. Base ML Component (0 - 35 points weight)
        # ---------------------------------------------------------
        ml_prob = float(ml_result.get("fraud_probability", 0.0))
        ml_points = round(ml_prob * 35.0, 1)
        total_risk_points += ml_points
        score_breakdown.append({
            "component": "ML Linguistic Fraud Probability",
            "points": ml_points,
            "max": 35,
            "details": f"Model probability of fraudulent text: {ml_prob*100:.1f}%",
        })

        if ml_prob > 0.65:
            red_flags.append(f"ML textual fraud classifier flagged high similarity to known scams ({ml_prob*100:.1f}%)")
        elif ml_prob < 0.25:
            trust_indicators.append(f"ML model confirmed authentic professional vocabulary ({ (1.0-ml_prob)*100:.1f}% confidence)")

        # ---------------------------------------------------------
        # 2. High-Risk Rule Checks (+15 to +35 points each)
        # ---------------------------------------------------------
        desc_lower = str(job_data.get("description", "")).lower()
        reqs_lower = str(job_data.get("requirements", "")).lower()
        salary_str = str(job_data.get("salary", "")).lower()
        combined_text = f"{desc_lower} {reqs_lower} {salary_str}"

        # 2a. Requests Money/Payment
        payment_matches = re.findall(
            r"\b(?:registration\s+fee|application\s+fee|processing\s+fee|deposit|training\s+fee|wire\s+transfer|moneygram|gift\s+card|crypto)\b",
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

        # 2b. Requests Banking/Sensitive Details
        bank_matches = re.findall(
            r"\b(?:bank\s+account|routing\s+number|credit\s+card|debit\s+card|ssn|social\s+security|passport\s+copy)\b",
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

        # 2c. Unrealistic Salary / Exaggerated Claims
        unrealistic_salary = False
        if any(w in salary_str for w in ["$5000/week", "$1000/day", "$100/hr", "guaranteed income", "50000 daily"]):
            unrealistic_salary = True
        elif any(p in combined_text for p in ["earn $500 daily", "make thousands weekly", "no experience required $80/hr"]):
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

        # 2d. Urgent / High-pressure language
        if nlp_features.get("urgency_score", 0) >= 0.5:
            pts = 15
            total_risk_points += pts
            red_flags.append("High-pressure urgency language and excessive punctuation detected")
            score_breakdown.append({
                "component": "Urgency & Psychological Coercion",
                "points": pts,
                "max": 15,
                "details": "Urgency cues intended to rush applicant into uncritical action.",
            })

        # ---------------------------------------------------------
        # 3. URL Security Component
        # ---------------------------------------------------------
        if url_analysis and url_analysis.get("analyzed"):
            url_pts = url_analysis.get("risk_points", 0) * 0.30  # Scale down
            if url_pts > 0:
                total_risk_points += url_pts
                score_breakdown.append({
                    "component": "URL Security Hazards",
                    "points": round(url_pts, 1),
                    "max": 30,
                    "details": f"{len(url_analysis.get('flags', []))} URL anomaly flags detected.",
                })
                for flag in url_analysis.get("flags", []):
                    red_flags.append(f"URL: {flag}")
            elif url_analysis.get("https_active") and url_analysis.get("is_safe"):
                trust_indicators.append("Application URL utilizes secure TLS/HTTPS on established domain")

        # ---------------------------------------------------------
        # 4. Company & Domain Verification Component
        # ---------------------------------------------------------
        if company_analysis:
            comp_pts = company_analysis.get("risk_points", 0) * 0.25
            if comp_pts > 0:
                total_risk_points += comp_pts
                score_breakdown.append({
                    "component": "Company & Domain Inconsistency",
                    "points": round(comp_pts, 1),
                    "max": 25,
                    "details": f"{len(company_analysis.get('flags', []))} domain consistency flags.",
                })
                for flag in company_analysis.get("flags", []):
                    red_flags.append(f"Domain/Identity: {flag}")

            for trust in company_analysis.get("trust_signals", []):
                trust_indicators.append(f"Domain: {trust}")

        # ---------------------------------------------------------
        # 5. Medium-Risk Structural Factors
        # ---------------------------------------------------------
        word_count = nlp_features.get("word_count", 0)
        if word_count < 30:
            pts = 10
            total_risk_points += pts
            red_flags.append("Suspiciously sparse job description (under 30 words)")
            score_breakdown.append({
                "component": "Vague/Sparse Posting Structure",
                "points": pts,
                "max": 10,
                "details": "Lacks typical role scope, deliverables, or corporate context.",
            })
        elif word_count > 120 and not payment_matches and not bank_matches:
            trust_indicators.append("Comprehensive, detailed job responsibilities and qualification criteria")

        # Check for contact via unauthorized messaging apps (Telegram, WhatsApp)
        if any(app in combined_text for app in ["telegram", "whatsapp", "signal app", "t.me", "wa.me"]):
            pts = 20
            total_risk_points += pts
            red_flags.append("Directs candidate to encrypted chat platforms (Telegram/WhatsApp) for interviews")
            score_breakdown.append({
                "component": "Out-of-Band Messaging Channel",
                "points": pts,
                "max": 20,
                "details": "Recruiter conducts hiring over anonymous messaging platforms.",
            })

        # ---------------------------------------------------------
        # 6. Trust Mitigations (Subtract points for authentic signals)
        # ---------------------------------------------------------
        trust_discount = 0.0
        if trust_indicators and not payment_matches and not bank_matches:
            trust_discount = min(25.0, len(trust_indicators) * 6.0)
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
        # 7. Risk Level & Classification
        # ---------------------------------------------------------
        if final_risk_score >= 75.0 or payment_matches or bank_matches:
            risk_level = "CRITICAL"
            prediction = "FAKE"
        elif final_risk_score >= 50.0:
            risk_level = "HIGH"
            prediction = "FAKE"
        elif final_risk_score >= 25.0:
            risk_level = "MEDIUM"
            prediction = "SUSPICIOUS"
        else:
            risk_level = "LOW"
            prediction = "GENUINE"

        # Calculate Confidence
        if prediction == "FAKE":
            confidence = min(98.5, max(72.0, 50.0 + (final_risk_score * 0.48)))
        elif prediction == "GENUINE":
            confidence = min(96.0, max(70.0, 50.0 + ((100.0 - final_risk_score) * 0.45)))
        else:
            confidence = min(85.0, max(60.0, 55.0 + abs(50.0 - final_risk_score)))

        # ---------------------------------------------------------
        # 8. Actionable Recommended Safe Action
        # ---------------------------------------------------------
        if prediction == "FAKE" or risk_level in ("HIGH", "CRITICAL"):
            recommended_action = (
                "DO NOT ENGAGE: Cease all communication immediately. Never send money, deposit checks, "
                "or disclose banking, UPI, or passport details. Legitimate employers will never ask for "
                "upfront payments. Report this posting to cybercrime authorities and the host platform."
            )
        elif prediction == "SUSPICIOUS":
            recommended_action = (
                "PROCEED WITH CAUTION: Cross-verify this position directly on the company's official careers portal. "
                "Do not click unverified external links or conduct interviews over Telegram/WhatsApp. "
                "Request an official company email confirmation before sharing personal information."
            )
        else:
            recommended_action = (
                "SAFE TO PROCEED: Posting displays consistent authentic indicators and low fraud probability. "
                "Follow standard job application safety: verify interview links and apply via official company portals."
            )

        return {
            "prediction": prediction,
            "risk_score": final_risk_score,
            "risk_level": risk_level,
            "confidence": round(confidence, 1),
            "red_flags": list(dict.fromkeys(red_flags)),  # Unique preserving order
            "trust_indicators": list(dict.fromkeys(trust_indicators)),
            "score_breakdown": score_breakdown,
            "recommended_action": recommended_action,
        }
