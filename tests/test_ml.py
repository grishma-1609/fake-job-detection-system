"""
Unit tests for Machine Learning prediction pipeline.
"""

import unittest

from models.predictor import get_predictor


class TestMLPredictor(unittest.TestCase):

    def setUp(self):
        self.predictor = get_predictor()

    def test_model_and_vectorizer_loaded(self):
        self.assertIsNotNone(self.predictor.model)
        self.assertIsNotNone(self.predictor.vectorizer)

    def test_fraudulent_inference(self):
        scam_text = (
            "Urgent hiring! Earn $500 daily data entry from home. Deposit cashier check "
            "for equipment and wire transfer registration fee via Western Union. Contact on Telegram."
        )
        res = self.predictor.predict(scam_text)
        self.assertIn(res["prediction"], ["FAKE", "SUSPICIOUS"])
        self.assertGreater(res["fraud_probability"], 0.45)
        self.assertGreaterEqual(res["confidence"], 50.0)

    def test_genuine_inference(self):
        genuine_text = (
            "Senior Cloud Security Engineer. Apex Technologies is seeking an experienced engineer "
            "to design, build, and audit Kubernetes clusters. Requires Bachelor's degree in Computer Science, "
            "5+ years Linux experience, 401(k) matching, health insurance."
        )
        res = self.predictor.predict(genuine_text)
        self.assertEqual(res["prediction"], "GENUINE")
        self.assertLess(res["fraud_probability"], 0.50)

    def test_empty_text_handled_safely(self):
        res = self.predictor.predict("")
        self.assertIn("status", res)
        self.assertIsNotNone(res["prediction"])


if __name__ == "__main__":
    unittest.main()
