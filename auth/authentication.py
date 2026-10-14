"""
Authentication Module: Handles secure user registration, password hashing,
credential verification, and session state management.
"""

import hashlib
import os
import re
from typing import Any, Dict, Optional, Tuple

try:
    import bcrypt

    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False

from database.json_db import get_db


class AuthService:
    """Manages user authentication, password hashing, and account validation."""

    def __init__(self):
        self.db = get_db()
        self._seed_default_users()

    # ----------------------------------------------------
    # Password Hashing & Verification
    # ----------------------------------------------------

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password securely using bcrypt or PBKDF2 fallback."""
        if HAS_BCRYPT:
            salt = bcrypt.gensalt(rounds=12)
            hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
            return hashed.decode("utf-8")
        else:
            # PBKDF2 SHA-256 fallback
            salt = os.urandom(16)
            key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
            return f"pbkdf2:{salt.hex()}:{key.hex()}"

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify plain password against hashed string."""
        if not hashed:
            return False

        if hashed.startswith("pbkdf2:"):
            try:
                parts = hashed.split(":")
                salt = bytes.fromhex(parts[1])
                expected_key = parts[2]
                computed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000).hex()
                return computed == expected_key
            except Exception:
                return False

        if HAS_BCRYPT:
            try:
                return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
            except Exception:
                return False

        return False

    # ----------------------------------------------------
    # Seed Accounts
    # ----------------------------------------------------

    def _seed_default_users(self):
        """Seed demo analyst and admin users if database is empty."""
        user_count = self.db.count("users")
        if user_count == 0:
            demo_user = {
                "username": "analyst_demo",
                "full_name": "Cybersecurity Analyst",
                "email": "analyst@cybersec.org",
                "password_hash": self.hash_password("Password@123"),
                "role": "analyst",
                "created_at": "2026-01-01T00:00:00Z",
            }
            admin_user = {
                "username": "admin",
                "full_name": "System Administrator",
                "email": "admin@cybersec.org",
                "password_hash": self.hash_password("Admin@123"),
                "role": "admin",
                "created_at": "2026-01-01T00:00:00Z",
            }
            self.db.insert("users", demo_user)
            self.db.insert("users", admin_user)

    # ----------------------------------------------------
    # Validation
    # ----------------------------------------------------

    @staticmethod
    def validate_username(username: str) -> Tuple[bool, str]:
        if not username or len(username.strip()) < 3:
            return False, "Username must be at least 3 characters long."
        if len(username.strip()) > 30:
            return False, "Username must be at most 30 characters."
        if not re.match(r"^[a-zA-Z0-9_-]+$", username):
            return False, "Username can only contain letters, numbers, underscores, and hyphens."
        return True, ""

    @staticmethod
    def validate_email(email: str) -> Tuple[bool, str]:
        if not email:
            return False, "Email address is required."
        pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if not re.match(pattern, email.strip()):
            return False, "Invalid email address format."
        return True, ""

    @staticmethod
    def validate_password(password: str) -> Tuple[bool, str]:
        if not password or len(password) < 6:
            return False, "Password must be at least 6 characters long."
        return True, ""

    # ----------------------------------------------------
    # Account Registration & Login
    # ----------------------------------------------------

    def register_user(
        self, username: str, full_name: str, email: str, password: str, role: str = "analyst"
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Registers a new user account if inputs are valid and unique."""
        username = username.strip().lower()
        email = email.strip().lower()
        full_name = full_name.strip()

        ok, msg = self.validate_username(username)
        if not ok:
            return False, msg, None

        ok, msg = self.validate_email(email)
        if not ok:
            return False, msg, None

        ok, msg = self.validate_password(password)
        if not ok:
            return False, msg, None

        # Check existing username
        existing_user = self.db.find("users", {"username": username})
        if existing_user:
            return False, "Username already exists. Please choose another.", None

        # Check existing email
        existing_email = self.db.find("users", {"email": email})
        if existing_email:
            return False, "Email address is already registered.", None

        # Hash and store
        pw_hash = self.hash_password(password)
        new_user = {
            "username": username,
            "full_name": full_name or username,
            "email": email,
            "password_hash": pw_hash,
            "role": role,
        }

        created = self.db.insert("users", new_user)
        safe_user = {k: v for k, v in created.items() if k != "password_hash"}
        return True, "Registration successful! You can now log in.", safe_user

    def authenticate_user(
        self, username_or_email: str, password: str
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Authenticates user with username/email and password."""
        identifier = username_or_email.strip().lower()
        if not identifier or not password:
            return False, "Please provide both username/email and password.", None

        # Search by username or email
        users = self.db.find("users", {"username": identifier})
        if not users:
            users = self.db.find("users", {"email": identifier})

        if not users:
            return False, "Invalid username or password.", None

        user = users[0]
        hashed = user.get("password_hash", "")
        if not self.verify_password(password, hashed):
            return False, "Invalid username or password.", None

        safe_user = {k: v for k, v in user.items() if k != "password_hash"}
        return True, "Authentication successful.", safe_user

    def change_password(
        self, user_id: str, old_password: str, new_password: str
    ) -> Tuple[bool, str]:
        """Changes a user's password after verifying existing password."""
        user = self.db.get_by_id("users", user_id)
        if not user:
            return False, "User account not found."

        if not self.verify_password(old_password, user.get("password_hash", "")):
            return False, "Current password is incorrect."

        ok, msg = self.validate_password(new_password)
        if not ok:
            return False, msg

        new_hash = self.hash_password(new_password)
        self.db.update("users", user_id, {"password_hash": new_hash})
        return True, "Password updated successfully."

    def get_user_profile(self, user_id: str) -> Optional[Dict[str, Any]]:
        user = self.db.get_by_id("users", user_id)
        if user:
            return {k: v for k, v in user.items() if k != "password_hash"}
        return None
