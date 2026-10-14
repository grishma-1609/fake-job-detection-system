"""
Unit tests for URL and Domain Security Analyzer.
"""

import unittest

from modules.url_analyzer import URLSecurityAnalyzer


class TestURLSecurityAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = URLSecurityAnalyzer(timeout=1.5)

    def test_empty_or_none_url(self):
        res = self.analyzer.analyze_url(None)
        self.assertFalse(res["analyzed"])
        self.assertTrue(res["is_safe"])

    def test_shortened_url_detection(self):
        res = self.analyzer.analyze_url("http://bit.ly/job-vacancy-2026")
        self.assertTrue(res["analyzed"])
        self.assertTrue(res["is_shortened"])
        self.assertGreater(res["risk_points"], 20)

    def test_free_form_host_detection(self):
        res = self.analyzer.analyze_url("https://forms.gle/xyz123abc")
        self.assertTrue(res["analyzed"])
        self.assertTrue(res["is_free_form"])
        self.assertFalse(res["is_safe"])

    def test_ip_address_detection(self):
        res = self.analyzer.analyze_url("http://198.51.100.24/careers/apply")
        self.assertTrue(res["analyzed"])
        self.assertTrue(res["is_ip_literal"])
        self.assertGreaterEqual(res["risk_points"], 35)

    def test_insecure_http_flagged(self):
        res = self.analyzer.analyze_url("http://careers.legitcompany.com")
        self.assertFalse(res["https_active"])
        self.assertTrue(any("Insecure HTTP" in f for f in res["flags"]))


if __name__ == "__main__":
    unittest.main()
