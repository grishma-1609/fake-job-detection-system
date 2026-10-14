"""
Unit tests for Company and Domain Consistency Verifier.
"""

import unittest

from modules.company_verifier import CompanyVerifier


class TestCompanyVerifier(unittest.TestCase):

    def setUp(self):
        self.verifier = CompanyVerifier()

    def test_consistent_company_and_domains(self):
        res = self.verifier.verify_consistency(
            company_name="Google LLC",
            company_website="https://www.google.com/careers",
            recruiter_email="recruiter@google.com",
        )
        self.assertTrue(res["verified"])
        self.assertTrue(res["email_web_match"])
        self.assertFalse(res["is_free_email"])
        self.assertEqual(len(res["flags"]), 0)

    def test_free_email_corporate_discrepancy(self):
        res = self.verifier.verify_consistency(
            company_name="Microsoft Corporation",
            company_website="https://microsoft.com",
            recruiter_email="microsoft.recruiting.hr@gmail.com",
        )
        self.assertFalse(res["verified"])
        self.assertTrue(res["is_free_email"])
        self.assertTrue(any("free public email" in f for f in res["flags"]))
        self.assertGreaterEqual(res["risk_points"], 25)

    def test_domain_discrepancy(self):
        res = self.verifier.verify_consistency(
            company_name="Apple",
            company_website="https://apple.com",
            recruiter_email="hiring@apple-secure-jobs.xyz",
        )
        self.assertTrue(any("does not match" in f for f in res["flags"]))

    def test_missing_data_handled_gracefully(self):
        res = self.verifier.verify_consistency(None, None, None)
        self.assertFalse(res["verified"])
        self.assertIn("could not be independently verified", res["summary"])


if __name__ == "__main__":
    unittest.main()
