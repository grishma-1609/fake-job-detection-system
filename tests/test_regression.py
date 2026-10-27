"""
Automated Regression Test Suite for Fake Job Detection Pipeline.

Note: All test cases in this file use clearly labelled synthetic test fixtures
designed to validate regression boundaries, decision rules, uncertainty handling,
and class-label mapping. Synthetic fixtures validate pipeline logic and do not
claim to prove real-world statistical accuracy. External HTTP and network probes
are mocked to ensure deterministic, safe offline execution.
"""

import unittest
from unittest.mock import MagicMock, patch
import requests

from models.predictor import MLPredictor
from modules.company_verifier import CompanyVerifier
from modules.nlp_analyzer import NLPAnalyzer
from modules.risk_engine import (
    RiskEngine,
    OUTCOME_LIKELY_GENUINE,
    OUTCOME_SUSPICIOUS,
    OUTCOME_INSUFFICIENT,
)
from modules.scam_classifier import ScamClassifier
from modules.url_analyzer import URLSecurityAnalyzer


# =====================================================================
# Synthetic Test Fixtures
# (Clearly labelled synthetic test scenarios for pipeline verification)
# =====================================================================

SYNTHETIC_FIXTURE_LEGITIMATE_JOB = {
    "title": "Senior Cloud Infrastructure Engineer",
    "company": "CloudScale Systems Inc",
    "location": "San Francisco, CA (Hybrid)",
    "salary": "$145,000 - $165,000 / year",
    "employment_type": "Full-time",
    "experience": "Mid-Senior level",
    "education": "Bachelor's Degree",
    "description": (
        "CloudScale Systems Inc is seeking an experienced engineer to design, deploy, and "
        "manage AWS Kubernetes clusters. Responsibilities include maintaining CI/CD pipelines, "
        "monitoring latency with Prometheus, and ensuring SOC 2 Type II compliance. "
        "Collaborate with distributed software engineering teams in agile sprints."
    ),
    "requirements": "Bachelor's degree in Computer Science; 5+ years Linux/AWS; Proficiency with Terraform and Kubernetes.",
    "benefits": "Comprehensive medical, dental, and vision; 401(k) with 5% employer match; 20 days PTO; $2,500 training stipend.",
    "email": "careers@cloudscalesystems.com",
    "website": "https://cloudscalesystems.com",
    "url": "https://cloudscalesystems.com/careers/senior-infrastructure-engineer",
}

SYNTHETIC_FIXTURE_FABRICATED_COMPANY_UNREGISTERED_DOMAIN = {
    "title": "Remote Data Entry Clerk - Immediate Start",
    "company": "TotallyFabricatedHoldingCorp2026",
    "location": "Remote / Nationwide",
    "salary": "$45.00 / hour",
    "employment_type": "Part-time",
    "experience": "Not Applicable",
    "education": "High School",
    "description": (
        "Urgent hiring for online data entry typist. Work from home 2 hours daily processing simple records. "
        "Earn guaranteed $4,500 monthly. No interview required! We will mail you a check for home office setup. "
        "Deposit the cashier check and wire the remaining funds back to our vendor via Western Union."
    ),
    "requirements": "Personal bank account able to deposit checks; Basic internet access.",
    "benefits": "Guaranteed income, daily payouts.",
    "email": "hr@totallyfabricatedholdingcorp2026.biz",
    "website": "https://totallyfabricatedholdingcorp2026.biz",
    "url": "https://totallyfabricatedholdingcorp2026.biz/careers/apply-now",
}

SYNTHETIC_FIXTURE_OFFICIAL_NAME_UNRELATED_SITE = {
    "title": "Corporate Executive Assistant",
    "company": "Microsoft Corporation",
    "location": "Redmond, WA",
    "salary": "$85,000 / year",
    "employment_type": "Full-time",
    "experience": "Associate",
    "education": "Bachelor's Degree",
    "description": (
        "Support senior executive directors with scheduling, travel arrangements, and corporate correspondence. "
        "Direct point of contact for external partners."
    ),
    "requirements": "Prior executive office experience; Proficiency with Microsoft 365.",
    "benefits": "Standard corporate healthcare and benefits.",
    "email": "microsoft.corporate.recruitment.department@gmail.com",
    "website": "https://microsoft-career-portal-apply.com",
    "url": "https://microsoft-career-portal-apply.com/job/1048",
}

SYNTHETIC_FIXTURE_UPFRONT_FEE_DEMAND = {
    "title": "Medical Billing & Coding Trainee",
    "company": "Apex Healthcare Solutions",
    "location": "Remote",
    "salary": "$35.00 / hour",
    "employment_type": "Contract",
    "experience": "Entry level",
    "education": "High School",
    "description": (
        "Immediate placement for remote medical billing clerks. All hired candidates must complete mandatory HIPAA "
        "compliance training. A one-time non-refundable training fee of $175 and background check fee must be wired via "
        "Zelle or PayPal before your official orientation date."
    ),
    "requirements": "Must submit $175 registration fee prior to first training session; Computer with high-speed internet.",
    "benefits": "Flexible hours, medical billing software provided upon payment of registration fee.",
    "email": "hr@apexhealthcaresolutions.com",
    "website": "https://apexhealthcaresolutions.com",
    "url": "https://apexhealthcaresolutions.com/apply",
}

SYNTHETIC_FIXTURE_UNVERIFIED_COMPANY_INSUFFICIENT_INFO = {
    "title": "Junior Content Editor",
    "company": "Starlight Creative Hub",
    "location": "Remote",
    "salary": "Competitive",
    "employment_type": "Contract",
    "experience": "Entry level",
    "education": "Unspecified",
    "description": "Looking for a content editor to proofread articles, format blog posts, and upload drafted copy.",
    "requirements": "Familiarity with WordPress; Good English grammar.",
    "benefits": "Flexible hours.",
    "email": "",
    "website": "",
    "url": "",
}

SYNTHETIC_FIXTURE_VALID_COMPANY_SUSPICIOUS_URL = {
    "title": "Cloud Solutions Architect",
    "company": "Amazon",
    "location": "Seattle, WA",
    "salary": "$160,000 - $185,000 / year",
    "employment_type": "Full-time",
    "experience": "Mid-Senior level",
    "education": "Bachelor's Degree",
    "description": (
        "Design distributed architecture on AWS. Collaborate with cloud enterprise partners to ensure scalability, "
        "security, and high availability."
    ),
    "requirements": "AWS Certified Solutions Architect Professional; 5+ years distributed systems architecture.",
    "benefits": "Competitive compensation, Amazon stock units, comprehensive health coverage, 401(k) match.",
    "email": "recruiting-team@amazon.com",
    "website": "https://amazon.com",
    "url": "http://bit.ly/amazon-immediate-hire-fast-apply-2026",
}


class TestPipelineRegression(unittest.TestCase):
    """
    Automated regression suite verifying:
    - 3 final outcomes (Likely Genuine, Suspicious — Further Verification Required, Insufficient Evidence)
    - Dynamic class label mapping
    - Risk score calculation & indicator transparency
    - Uncertainty warnings for unverified services
    - Offline mocked network execution
    """

    def setUp(self):
        self.predictor = MLPredictor()
        self.nlp = NLPAnalyzer()
        self.url_sec = URLSecurityAnalyzer(timeout=1.0)
        self.comp = CompanyVerifier(check_dns=False)
        self.scam = ScamClassifier()
        self.risk = RiskEngine()

    def run_pipeline(self, job_data, mock_reachable=True, mock_status_code=200):
        """Helper to execute complete multi-layer pipeline with deterministic network mocking."""
        composite_text = self.nlp.build_composite_text(job_data)
        nlp_res = self.nlp.extract_linguistic_features(composite_text)
        ml_res = self.predictor.predict(composite_text)

        # Mock network probe for URL analyzer
        with patch.object(self.url_sec.session, "head") as mock_head:
            if mock_reachable:
                mock_resp = MagicMock()
                mock_resp.status_code = mock_status_code
                mock_resp.history = []
                mock_resp.url = job_data.get("url") or ""
                mock_head.return_value = mock_resp
            else:
                mock_head.side_effect = requests.exceptions.ConnectionError("Domain unresolvable")

            url_res = self.url_sec.analyze_url(job_data.get("url"), job_data.get("company"))

        comp_res = self.comp.verify_consistency(
            job_data.get("company"), job_data.get("website"), job_data.get("email")
        )
        scam_cats = self.scam.classify_scam_categories(job_data, url_res, comp_res)
        risk_res = self.risk.calculate_risk(
            job_data, ml_res, nlp_res, url_res, comp_res, scam_cats
        )

        return {
            "ml_res": ml_res,
            "nlp_res": nlp_res,
            "url_res": url_res,
            "comp_res": comp_res,
            "scam_cats": scam_cats,
            "risk_res": risk_res,
        }

    # =================================================================
    # Regression Case 1: Legitimate Job from Verifiable Company
    # =================================================================
    def test_case_1_legitimate_verifiable_job(self):
        """
        Case 1: Legitimate job from a verifiable company with a valid official careers URL.
        Must classify as 'Likely Genuine' with low risk and authentic trust signals.
        """
        res = self.run_pipeline(SYNTHETIC_FIXTURE_LEGITIMATE_JOB, mock_reachable=True)
        risk_res = res["risk_res"]

        self.assertEqual(
            risk_res["prediction"],
            OUTCOME_LIKELY_GENUINE,
            "Legitimate job with verified channels must produce 'Likely Genuine' outcome."
        )
        self.assertEqual(risk_res["risk_level"], "LOW")
        self.assertLess(risk_res["risk_score"], 25.0)
        self.assertGreaterEqual(len(risk_res["trust_indicators"]), 2)
        self.assertIn("SAFE TO PROCEED", risk_res["recommended_action"])

    # =================================================================
    # Regression Case 2: Fabricated Company & Unregistered Domain
    # =================================================================
    def test_case_2_fabricated_company_unregistered_domain(self):
        """
        Case 2: Fake job using a fabricated company and an unregistered domain.
        Must classify as 'Suspicious — Further Verification Required' with uncertainty warning
        for domain reachability, rather than inventing corporate verification.
        """
        res = self.run_pipeline(
            SYNTHETIC_FIXTURE_FABRICATED_COMPANY_UNREGISTERED_DOMAIN,
            mock_reachable=False
        )
        risk_res = res["risk_res"]
        url_res = res["url_res"]

        self.assertEqual(
            risk_res["prediction"],
            OUTCOME_SUSPICIOUS,
            "Fabricated company with dead/unregistered domain and scam text must be flagged Suspicious."
        )
        self.assertIn(risk_res["risk_level"], ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(risk_res["risk_score"], 40.0)
        # Verify reachability uncertainty warning was produced without crashing
        self.assertIn("Unreachable", url_res["url_validity"])
        self.assertIsNotNone(url_res.get("uncertainty_warning"))

    # =================================================================
    # Regression Case 3: Official-Looking but Unrelated Website
    # =================================================================
    def test_case_3_impersonation_domain_discrepancy(self):
        """
        Case 3: Job with an official-looking but unrelated website / free email.
        Must detect domain discrepancy / impersonation and classify as 'Suspicious — Further Verification Required'.
        """
        res = self.run_pipeline(SYNTHETIC_FIXTURE_OFFICIAL_NAME_UNRELATED_SITE, mock_reachable=True)
        risk_res = res["risk_res"]
        comp_res = res["comp_res"]

        self.assertEqual(
            risk_res["prediction"],
            OUTCOME_SUSPICIOUS,
            "Impersonation and free-email discrepancy must trigger Suspicious classification."
        )
        self.assertEqual(comp_res["verification_status"], "DISCREPANCY")
        self.assertTrue(comp_res["is_free_email"])
        self.assertIn("Company Impersonation", res["scam_cats"])

    # =================================================================
    # Regression Case 4: Upfront Fee Demand
    # =================================================================
    def test_case_4_upfront_fee_demand(self):
        """
        Case 4: Job demanding an upfront application, training or security fee.
        Must trigger critical fraud indicator, high risk score, and 'Suspicious — Further Verification Required'.
        """
        res = self.run_pipeline(SYNTHETIC_FIXTURE_UPFRONT_FEE_DEMAND, mock_reachable=True)
        risk_res = res["risk_res"]

        self.assertEqual(
            risk_res["prediction"],
            OUTCOME_SUSPICIOUS,
            "Upfront training/application fee demand must trigger Suspicious classification."
        )
        self.assertIn(risk_res["risk_level"], ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(risk_res["risk_score"], 50.0)
        self.assertTrue(any("Payment/Registration Fee" in c for c in res["scam_cats"]))
        self.assertTrue(any("Requests money" in f for f in risk_res["red_flags"]))

    # =================================================================
    # Regression Case 5: Unverified Company with Insufficient Info
    # =================================================================
    def test_case_5_unverified_company_insufficient_information(self):
        """
        Case 5: Job with an unverified company and insufficient information.
        Must classify as 'Insufficient Evidence' and produce an uncertainty warning.
        Must NOT falsely declare the posting as fraudulent or invent verification.
        """
        res = self.run_pipeline(SYNTHETIC_FIXTURE_UNVERIFIED_COMPANY_INSUFFICIENT_INFO)
        risk_res = res["risk_res"]
        comp_res = res["comp_res"]

        self.assertEqual(
            risk_res["prediction"],
            OUTCOME_INSUFFICIENT,
            "Posting lacking corporate verification data must produce 'Insufficient Evidence'."
        )
        self.assertEqual(comp_res["verification_status"], "UNVERIFIED")
        self.assertIn(risk_res["risk_level"], ["LOW", "MEDIUM"])
        self.assertIn("could not be independently verified", comp_res["summary"])
        self.assertIn("INDEPENDENT VERIFICATION REQUIRED", risk_res["recommended_action"])

    # =================================================================
    # Regression Case 6: Valid Company Name but Suspicious Recruitment URL
    # =================================================================
    def test_case_6_valid_company_suspicious_url(self):
        """
        Case 6: Job with a valid company name but a suspicious recruitment URL (shortener).
        Conflicting evidence: valid company name must NOT erase suspicious URL hazard.
        Must classify as 'Suspicious — Further Verification Required'.
        """
        res = self.run_pipeline(SYNTHETIC_FIXTURE_VALID_COMPANY_SUSPICIOUS_URL, mock_reachable=True)
        risk_res = res["risk_res"]
        url_res = res["url_res"]

        self.assertEqual(
            risk_res["prediction"],
            OUTCOME_SUSPICIOUS,
            "Valid company with shortened/obfuscated URL must produce 'Suspicious — Further Verification Required'."
        )
        self.assertTrue(url_res["is_shortened"])
        self.assertFalse(url_res["is_safe"])
        self.assertTrue(any("URL shortener" in f for f in risk_res["red_flags"]))

    # =================================================================
    # Regression Case 7: Fraud Class Mapping & Optimal Threshold Check
    # =================================================================
    def test_fraud_class_mapping_and_threshold(self):
        """
        Verifies that numeric class 1 corresponds to fraudulent jobs,
        and that the predictor dynamically resolves classes from model.classes_.
        """
        self.assertIsNotNone(self.predictor.model)
        self.assertTrue(hasattr(self.predictor.model, "classes_"))
        model_classes = list(self.predictor.model.classes_)
        self.assertIn(1, model_classes, "Model classes must include numeric label 1.")
        self.assertIn(0, model_classes, "Model classes must include numeric label 0.")

        # Verify fraud class index points to class 1
        expected_idx = model_classes.index(1)
        self.assertEqual(self.predictor.fraud_class_idx, expected_idx)

        # Verify optimal threshold is reasonable (between 0.15 and 0.55)
        self.assertGreaterEqual(self.predictor.optimal_threshold, 0.15)
        self.assertLessEqual(self.predictor.optimal_threshold, 0.55)


if __name__ == "__main__":
    unittest.main()
