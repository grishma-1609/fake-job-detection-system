"""
Unit tests for NLP Analyzer module.
"""

import unittest

from modules.nlp_analyzer import NLPAnalyzer


class TestNLPAnalyzer(unittest.TestCase):

    def test_clean_text(self):
        raw = "<h1>Urgent Hiring!</h1> Visit http://fake-link.com or email hr@fake.com for $5,000 daily!"
        cleaned = NLPAnalyzer.clean_text(raw)
        self.assertNotIn("<h1>", cleaned)
        self.assertNotIn("http", cleaned)
        self.assertNotIn("@", cleaned)
        self.assertIn("urgent", cleaned)

    def test_tokenize_and_filter(self):
        raw = "We are seeking a senior python developer with cloud skills"
        tokens = NLPAnalyzer.tokenize_and_filter(raw)
        self.assertIn("seeking", tokens)
        self.assertIn("senior", tokens)
        self.assertIn("python", tokens)
        self.assertNotIn("we", tokens)  # Stopword removed
        self.assertNotIn("are", tokens)  # Stopword removed

    def test_extract_linguistic_features(self):
        scam_text = "URGENT HIRING! Wire transfer registration fee immediately via Western Union! Telegram @hr_scam."
        features = NLPAnalyzer.extract_linguistic_features(scam_text)

        self.assertGreater(features["uppercase_ratio"], 0.20)
        self.assertGreaterEqual(features["exclamation_count"], 2)
        self.assertGreaterEqual(len(features["detected_phrases"]), 1)
        self.assertGreater(features["urgency_score"], 0.4)


if __name__ == "__main__":
    unittest.main()
