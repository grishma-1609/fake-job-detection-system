"""
Unit tests for Input Validators.
"""

import unittest

from utils.validators import (
    sanitize_text,
    validate_email_format,
    validate_job_submission,
    validate_url_format,
)


class TestValidators(unittest.TestCase):

    def test_validate_email_format(self):
        ok, _ = validate_email_format("hr@company.com")
        self.assertTrue(ok)

        ok, _ = validate_email_format("invalid-email-string")
        self.assertFalse(ok)

        ok, _ = validate_email_format("")  # Optional
        self.assertTrue(ok)

    def test_validate_url_format(self):
        ok, _ = validate_url_format("https://example.com/careers")
        self.assertTrue(ok)

        # Loopback / SSRF prevention
        ok, msg = validate_url_format("http://127.0.0.1/admin")
        self.assertFalse(ok)
        self.assertIn("disallowed", msg)

        # Private RFC1918 range
        ok, msg = validate_url_format("http://192.168.1.1/dashboard")
        self.assertFalse(ok)
        self.assertIn("disallowed", msg)

    def test_sanitize_text(self):
        dirty = "Hello\x00World\r\nTest"
        clean = sanitize_text(dirty)
        self.assertNotIn("\x00", clean)
        self.assertEqual(clean, "HelloWorld\r\nTest")

    def test_validate_job_submission(self):
        valid_job = {
            "title": "Software Engineer",
            "description": "We are hiring an experienced engineer with Python and AWS skills to join our agile team.",
            "email": "hr@validcompany.com",
            "website": "https://validcompany.com",
            "url": "https://validcompany.com/apply",
        }
        ok, errors = validate_job_submission(valid_job)
        self.assertTrue(ok)
        self.assertEqual(len(errors), 0)

        invalid_job = {
            "title": "",
            "description": "Short",  # under 5 words
            "email": "bademail",
        }
        ok, errors = validate_job_submission(invalid_job)
        self.assertFalse(ok)
        self.assertGreaterEqual(len(errors), 2)


if __name__ == "__main__":
    unittest.main()
