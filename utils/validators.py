"""
Input Validation and Sanitization Utilities.
Safeguards application against invalid formats, SSRF, injection, and empty fields.
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


def validate_email_format(email: Optional[str]) -> Tuple[bool, str]:
    """Validate format of recruiter email."""
    if not email or not email.strip():
        return True, ""  # Optional field in forms

    email = email.strip()
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not re.match(pattern, email):
        return False, "Invalid recruiter email format."

    return True, ""


def validate_url_format(url: Optional[str]) -> Tuple[bool, str]:
    """
    Validate URL format and ensure it conforms to standard safe web schemes.
    Rejects private IP addresses, loopback, file:// or other SSRF vectors.
    """
    if not url or not url.strip():
        return True, ""  # Optional field

    url = url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, "URL scheme must be http or https."

        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid URL: missing domain hostname."

        # Check for loopback or private IPs to prevent SSRF
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_reserved:
                return False, "Scanning of private/loopback IP addresses is disallowed for security."
        except ValueError:
            # Not an IP literal, standard hostname
            pass

        return True, ""
    except Exception as e:
        return False, f"Malformed URL: {str(e)}"


def sanitize_text(text: Optional[str]) -> str:
    """Sanitizes text by stripping whitespace, removing control characters."""
    if not text:
        return ""
    # Strip null bytes and non-printable control characters except newline/tab
    cleaned = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", str(text))
    return cleaned.strip()


def validate_job_submission(form_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validates job submission inputs before processing.
    Ensures minimum textual content for reliable NLP/ML analysis.
    """
    errors = []

    title = sanitize_text(form_data.get("title", ""))
    company = sanitize_text(form_data.get("company", ""))
    description = sanitize_text(form_data.get("description", ""))
    email = sanitize_text(form_data.get("email", ""))
    website = sanitize_text(form_data.get("website", ""))
    url = sanitize_text(form_data.get("url", ""))

    if not title:
        errors.append("Job Title is required.")
    elif len(title) < 2:
        errors.append("Job Title must be at least 2 characters long.")

    if not description:
        errors.append("Job Description is required for analysis.")
    elif len(description.split()) < 5:
        errors.append("Job Description is too short for meaningful security analysis (minimum 5 words).")

    if email:
        valid_email, email_msg = validate_email_format(email)
        if not valid_email:
            errors.append(email_msg)

    if website:
        valid_web, web_msg = validate_url_format(website)
        if not valid_web:
            errors.append(f"Company Website error: {web_msg}")

    if url:
        valid_url, url_msg = validate_url_format(url)
        if not valid_url:
            errors.append(f"Application URL error: {url_msg}")

    return len(errors) == 0, errors
