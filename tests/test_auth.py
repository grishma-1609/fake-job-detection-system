"""
Unit tests for Authentication Module.
"""

import os
import shutil
import tempfile
import unittest

from auth.authentication import AuthService
from database.json_db import JSONDatabase


class TestAuthService(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db = JSONDatabase(data_dir=self.test_dir)
        self.auth = AuthService()
        self.auth.db = self.db

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        JSONDatabase(data_dir=os.path.join(base_dir, "data"))

    def test_password_hashing_and_verification(self):
        raw_pw = "SecretP@ssword123"
        hashed = self.auth.hash_password(raw_pw)
        self.assertNotEqual(raw_pw, hashed)
        self.assertTrue(self.auth.verify_password(raw_pw, hashed))
        self.assertFalse(self.auth.verify_password("WrongPassword!", hashed))

    def test_user_registration_success(self):
        success, msg, user = self.auth.register_user(
            username="test_analyst",
            full_name="Test Analyst",
            email="test@analyst.org",
            password="StrongPassword123!",
        )
        self.assertTrue(success)
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "test_analyst")
        self.assertNotIn("password_hash", user)

    def test_duplicate_registration_rejected(self):
        self.auth.register_user(
            username="duplicate_user",
            full_name="Duplicate",
            email="dup@test.org",
            password="Password123!",
        )
        success, msg, user = self.auth.register_user(
            username="duplicate_user",
            full_name="Another",
            email="dup2@test.org",
            password="Password123!",
        )
        self.assertFalse(success)
        self.assertIn("already exists", msg)

    def test_authentication_workflow(self):
        self.auth.register_user(
            username="auth_user",
            full_name="Auth User",
            email="auth@test.org",
            password="CorrectPassword123!",
        )

        # Successful auth by username
        ok, msg, user = self.auth.authenticate_user("auth_user", "CorrectPassword123!")
        self.assertTrue(ok)
        self.assertEqual(user["username"], "auth_user")

        # Successful auth by email
        ok, msg, user = self.auth.authenticate_user("auth@test.org", "CorrectPassword123!")
        self.assertTrue(ok)

        # Invalid password
        ok, msg, user = self.auth.authenticate_user("auth_user", "WrongPassword")
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
