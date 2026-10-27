"""
Unit tests for Risk Engine and Scam Typology Classifier.
"""

import unittest

from modules.risk_engine import RiskEngine
from modules.scam_classifier import ScamClassifier


class TestRiskEngineAndScamClassifier(unittest.TestCase):

    def setUp(self):
        self.risk_engine = RiskEngine()
        self.scam_classifier = ScamClassifier()

    def test_scam_classifier_detects_categories(self):
        job_data = {
            "title": "Crypto Assistant - Instant Wire Transfer Payout",
            "description": "Send $100 registration fee via Western Union or Bitcoin. Enter SSN and bank account.",
            "requirements": "Telegram required.",
            "salary": "$500 daily guaranteed",
        }
        cats = self.scam_classifier.classify_scam_categories(job_data)
        self.assertTrue(any("Payment/Registration Fee" in c for c in cats))
        self.assertTrue(any("Personal Information" in c for c in cats))
        self.assertTrue(any("Unrealistic Job Offer" in c for c in cats))

    def test_risk_engine_critical_scam(self):
        job_data = {
            "title": "Data Entry Clerk",
            "description": "Deposit this check into your bank account and wire transfer registration fee. Urgent!",
            "salary": "$5,000 weekly guaranteed",
        }
        ml_result = {"fraud_probability": 0.95}
        nlp_features = {"word_count": 25, "urgency_score": 0.8, "detected_phrases": ["wire transfer", "registration fee"]}
        url_analysis = {"analyzed": False, "flags": []}
        company_analysis = {"risk_points": 25, "flags": ["Free email discrepancy"], "trust_signals": []}
        scam_cats = ["Payment/Registration Fee Scam"]

        risk_res = self.risk_engine.calculate_risk(
            job_data, ml_result, nlp_features, url_analysis, company_analysis, scam_cats
        )

        self.assertIn("Suspicious", risk_res["prediction"])
        self.assertIn(risk_res["risk_level"], ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(risk_res["risk_score"], 70.0)
        self.assertGreaterEqual(len(risk_res["red_flags"]), 2)
        self.assertIn("DO NOT ENGAGE", risk_res["recommended_action"])

    def test_risk_engine_genuine_job(self):
        job_data = {
            "title": "Senior Security Analyst",
            "description": (
                "Leading technology organization seeks an experienced security analyst "
                "to triage alerts and monitor network posture. Bachelor's degree required. "
                "401k match and healthcare coverage included. Work with enterprise SIEM."
            ),
            "salary": "$110,000 - $130,000",
        }
        ml_result = {"fraud_probability": 0.05}
        nlp_features = {"word_count": 140, "urgency_score": 0.0, "detected_phrases": []}
        url_analysis = {"analyzed": True, "https_active": True, "is_safe": True, "is_live_valid": True, "risk_points": 0, "flags": []}
        company_analysis = {"verification_status": "VERIFIED", "risk_points": 0, "flags": [], "trust_signals": ["Official corporate domain", "Corporate email matches website"]}
        scam_cats = []

        risk_res = self.risk_engine.calculate_risk(
            job_data, ml_result, nlp_features, url_analysis, company_analysis, scam_cats
        )

        self.assertEqual(risk_res["prediction"], "Likely Genuine")
        self.assertEqual(risk_res["risk_level"], "LOW")
        self.assertLess(risk_res["risk_score"], 30.0)
        self.assertIn("SAFE TO PROCEED", risk_res["recommended_action"])


if __name__ == "__main__":
    unittest.main()
