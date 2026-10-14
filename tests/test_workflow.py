"""
End-to-End Workflow Integration Test:
Validates the complete operational lifecycle:
Registration -> Login -> Dashboard metrics -> Detect Job -> Analysis ->
Save Report -> History -> View Report -> Delete -> Logout.
"""

import unittest
from auth.authentication import AuthService
from database.json_db import get_db
from models.predictor import get_predictor
from modules.company_verifier import CompanyVerifier
from modules.explainability import ExplainabilityEngine
from modules.nlp_analyzer import NLPAnalyzer
from modules.risk_engine import RiskEngine
from modules.scam_classifier import ScamClassifier
from modules.url_analyzer import URLSecurityAnalyzer
from utils.helpers import generate_pdf_report


class TestEndToEndWorkflow(unittest.TestCase):

    def setUp(self):
        self.db = get_db()
        self.auth = AuthService()
        self.predictor = get_predictor()
        self.nlp = NLPAnalyzer()
        self.url_sec = URLSecurityAnalyzer(timeout=1.5)
        self.comp = CompanyVerifier()
        self.scam = ScamClassifier()
        self.risk = RiskEngine()
        self.xai = ExplainabilityEngine(
            vectorizer=self.predictor.vectorizer, model=self.predictor.model
        )

    def test_complete_e2e_lifecycle(self):
        # 1. Registration
        test_username = "audit_officer_99"
        test_email = "audit99@defense-agency.gov"
        test_pw = "ClassifiedSecure@2026"

        # Cleanup if leftover
        existing = self.db.find("users", {"username": test_username})
        for u in existing:
            self.db.delete("users", u["id"])

        reg_ok, reg_msg, reg_user = self.auth.register_user(
            username=test_username,
            full_name="Chief Audit Officer",
            email=test_email,
            password=test_pw,
            role="analyst",
        )
        self.assertTrue(reg_ok, f"Registration failed: {reg_msg}")
        self.assertIsNotNone(reg_user)

        # 2. Login / Authentication
        auth_ok, auth_msg, session_user = self.auth.authenticate_user(test_username, test_pw)
        self.assertTrue(auth_ok, f"Login failed: {auth_msg}")
        self.assertEqual(session_user["username"], test_username)

        # 3. Detect Job - Ingestion & Multi-Layer Threat Scan
        job_payload = {
            "title": "URGENT Data Entry Assistant - Immediate Start",
            "company": "FastLogistics Global",
            "location": "Remote",
            "salary": "$50.00 / hour guaranteed",
            "employment_type": "Part-time",
            "experience": "Not Applicable",
            "education": "High School",
            "description": (
                "Urgent hiring! Earn $50/hour working simple data entry from home. "
                "No interview required! We will mail you a cashier check for $3,500 to purchase home office hardware. "
                "Deposit this check into your personal bank account, keep your advance payment, and immediately wire transfer "
                "the rest via Western Union to our vendor. Send bank details and passport copy to start."
            ),
            "requirements": "Active personal bank account for check deposit. Limited spots, act now!",
            "benefits": "Guaranteed daily payout, free laptop provided after $120 registration fee.",
            "email": "hr.fastlogistics@gmail.com",
            "website": "https://fastlogistics-careers-portal.xyz",
            "url": "http://bit.ly/fastlogistics-apply-now",
        }

        # Step 3a: NLP analysis
        comp_text = self.nlp.build_composite_text(job_payload)
        nlp_res = self.nlp.extract_linguistic_features(comp_text)
        self.assertGreater(nlp_res["urgency_score"], 0.2)

        # Step 3b: ML inference
        ml_res = self.predictor.predict(comp_text)
        self.assertIn(ml_res["prediction"], ["FAKE", "SUSPICIOUS"])

        # Step 3c: URL security audit
        url_res = self.url_sec.analyze_url(job_payload["url"], job_payload["company"])
        self.assertTrue(url_res["analyzed"])
        self.assertTrue(url_res["is_shortened"])

        # Step 3d: Company & domain verification
        comp_res = self.comp.verify_consistency(
            job_payload["company"], job_payload["website"], job_payload["email"]
        )
        self.assertTrue(comp_res["is_free_email"])

        # Step 3e: Scam categorization
        scam_cats = self.scam.classify_scam_categories(job_payload, url_res, comp_res)
        self.assertTrue(len(scam_cats) > 0)
        self.assertTrue(any("Payment/Registration Fee" in c for c in scam_cats))

        # Step 3f: Risk engine
        risk_res = self.risk.calculate_risk(job_payload, ml_res, nlp_res, url_res, comp_res, scam_cats)
        self.assertEqual(risk_res["prediction"], "FAKE")
        self.assertIn(risk_res["risk_level"], ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(risk_res["risk_score"], 70.0)

        # Step 3g: Explainable AI
        xai_res = self.xai.explain_prediction(
            job_payload,
            risk_res["prediction"],
            ml_res["fraud_probability"],
            nlp_res,
            risk_res["red_flags"],
            risk_res["trust_indicators"],
            scam_cats,
        )
        self.assertIsNotNone(xai_res["summary"])

        # 4. Save Analysis Record to DB
        analysis_record = {
            "user_id": session_user["id"],
            "job_data": job_payload,
            "prediction": risk_res["prediction"],
            "risk_score": risk_res["risk_score"],
            "risk_level": risk_res["risk_level"],
            "confidence": risk_res["confidence"],
            "scam_categories": scam_cats,
            "red_flags": risk_res["red_flags"],
            "trust_indicators": risk_res["trust_indicators"],
            "score_breakdown": risk_res["score_breakdown"],
            "recommended_action": risk_res["recommended_action"],
            "ml_result": ml_res,
            "url_analysis": url_res,
            "company_verification": comp_res,
            "explanation": xai_res,
        }
        saved_analysis = self.db.insert("analyses", analysis_record)
        analysis_id = saved_analysis["id"]
        self.assertIsNotNone(analysis_id)

        # 5. Save as Formal Incident Report
        report_record = {
            "analysis_id": analysis_id,
            "title": job_payload["title"],
            "company": job_payload["company"],
            "prediction": risk_res["prediction"],
            "risk_score": risk_res["risk_score"],
            "risk_level": risk_res["risk_level"],
            "full_analysis": saved_analysis,
        }
        saved_report = self.db.insert("reports", report_record)
        report_id = saved_report["id"]
        self.assertIsNotNone(report_id)

        # 6. Verify Dashboard data querying
        all_analyses = self.db.find("analyses")
        self.assertTrue(len(all_analyses) >= 1)

        # 7. Verify History lookup & filtering
        found_analyses = self.db.find("analyses", {"prediction": "FAKE"})
        self.assertTrue(len(found_analyses) >= 1)

        # 8. Verify Report retrieval & PDF generation
        retrieved_report = self.db.get_by_id("reports", report_id)
        self.assertIsNotNone(retrieved_report)
        pdf_bytes = generate_pdf_report(retrieved_report["full_analysis"])
        self.assertIsNotNone(pdf_bytes)
        self.assertGreater(len(pdf_bytes), 1000)

        # 9. Delete Report (CRUD)
        del_report_ok = self.db.delete("reports", report_id)
        self.assertTrue(del_report_ok)
        self.assertIsNone(self.db.get_by_id("reports", report_id))

        # 10. Delete Analysis (CRUD)
        del_analysis_ok = self.db.delete("analyses", analysis_id)
        self.assertTrue(del_analysis_ok)
        self.assertIsNone(self.db.get_by_id("analyses", analysis_id))

        # 11. Cleanup test user
        self.db.delete("users", session_user["id"])


if __name__ == "__main__":
    unittest.main()
