"""
Company and Domain Consistency Verifier:
Cross-references stated Company Name, Official Website, and Recruiter Email
to detect domain impersonation, free-mail corporate claims, and inconsistencies.
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


# Popular free / disposable email domains
FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com",
    "mail.com", "zoho.com", "proton.me", "protonmail.com", "yandex.com",
    "aol.com", "gmx.com", "tutanota.com", "tempmail.com", "guerrillamail.com"
}


class CompanyVerifier:
    """Evaluates consistency among company name, website domain, and recruiter contact."""

    def __init__(self):
        pass

    @staticmethod
    def extract_domain_from_url(url: Optional[str]) -> str:
        """Extracts cleaned base domain from a URL."""
        if not url:
            return ""
        clean_url = str(url).strip()
        if not (clean_url.startswith("http://") or clean_url.startswith("https://")):
            clean_url = "https://" + clean_url
        try:
            parsed = urlparse(clean_url)
            hostname = (parsed.hostname or "").lower()
            if hostname.startswith("www."):
                hostname = hostname[4:]
            return hostname
        except Exception:
            return ""

    @staticmethod
    def extract_domain_from_email(email: Optional[str]) -> str:
        """Extracts domain from an email address."""
        if not email or "@" not in str(email):
            return ""
        parts = str(email).strip().lower().split("@")
        return parts[-1] if len(parts) > 1 else ""

    def verify_consistency(
        self,
        company_name: Optional[str],
        company_website: Optional[str],
        recruiter_email: Optional[str],
    ) -> Dict[str, Any]:
        """
        Cross-validates company attributes.
        Uses objective cybersecurity wording.
        """
        company_str = (company_name or "").strip()
        web_domain = self.extract_domain_from_url(company_website)
        email_domain = self.extract_domain_from_email(recruiter_email)

        flags: List[str] = []
        trust_signals: List[str] = []
        risk_points = 0

        # If minimal data provided
        if not company_str and not web_domain and not email_domain:
            return {
                "verified": False,
                "confidence": "Low",
                "risk_points": 10,
                "summary": "Company information could not be independently verified (No data provided).",
                "flags": ["No company name, website, or recruiter email provided"],
                "trust_signals": [],
            }

        # 1. Recruiter Email Analysis
        is_free_email = False
        if email_domain:
            if email_domain in FREE_EMAIL_DOMAINS:
                is_free_email = True
                if company_str and len(company_str) > 2:
                    flags.append(
                        f"Recruiter uses free public email (@{email_domain}) claiming to represent '{company_str}'"
                    )
                    risk_points += 25
                else:
                    flags.append(f"Recruiter email is on free public domain (@{email_domain})")
                    risk_points += 15
            else:
                trust_signals.append(f"Recruiter uses corporate domain email (@{email_domain})")

        # 2. Email Domain vs Website Domain Consistency
        email_web_match = False
        if email_domain and web_domain:
            if not is_free_email:
                if email_domain == web_domain or email_domain.endswith("." + web_domain) or web_domain.endswith("." + email_domain):
                    email_web_match = True
                    trust_signals.append(f"Recruiter email domain (@{email_domain}) matches official website ({web_domain})")
                else:
                    flags.append(
                        f"Recruiter email domain (@{email_domain}) does not match website domain ({web_domain})"
                    )
                    risk_points += 20

        # 3. Company Name vs Website Domain Similarity
        company_web_consistent = False
        if company_str and web_domain:
            # Normalize company name (remove Inc, LLC, Corp, spaces)
            norm_company = re.sub(r"\b(inc|llc|corp|corporation|ltd|limited|technologies|solutions|group)\b", "", company_str.lower())
            norm_company = re.sub(r"[^a-z0-9]", "", norm_company)

            norm_domain = web_domain.split(".")[0]
            norm_domain = re.sub(r"[^a-z0-9]", "", norm_domain)

            if len(norm_company) >= 3 and (norm_company in norm_domain or norm_domain in norm_company):
                company_web_consistent = True
                trust_signals.append(f"Company name aligns with website domain ({web_domain})")
            else:
                flags.append(
                    f"Company name '{company_str}' has noticeable discrepancy with website domain '{web_domain}'"
                )
                risk_points += 15

        # 4. Formulate Summary
        if not flags and trust_signals:
            summary = "High company and domain consistency confirmed across provided channels."
            verified = True
        elif risk_points >= 25:
            summary = "Significant inconsistencies detected between claimed company identity and communication domains."
            verified = False
        else:
            summary = "Company information could not be independently verified."
            verified = False

        return {
            "verified": verified,
            "company_name": company_str,
            "website_domain": web_domain,
            "email_domain": email_domain,
            "is_free_email": is_free_email,
            "email_web_match": email_web_match,
            "company_web_consistent": company_web_consistent,
            "risk_points": min(100, risk_points),
            "summary": summary,
            "flags": flags,
            "trust_signals": trust_signals,
        }
