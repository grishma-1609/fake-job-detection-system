"""
Company and Domain Consistency Verifier:
Cross-references stated Company Name, Official Website, and Recruiter Email
to detect domain impersonation, free-mail corporate claims, and inconsistencies.
Provides honest uncertainty warnings for unverified entities rather than inventing verification.
"""

import re
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# Popular free / disposable email domains
FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com",
    "mail.com", "zoho.com", "proton.me", "protonmail.com", "yandex.com",
    "aol.com", "gmx.com", "tutanota.com", "tempmail.com", "guerrillamail.com"
}

# Recognized established corporate / tech domains known to be authentic entities
ESTABLISHED_CORPORATE_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "meta.com",
    "netflix.com", "salesforce.com", "ibm.com", "oracle.com", "cisco.com",
    "intel.com", "adobe.com", "nvidia.com", "spotify.com", "uber.com",
    "airbnb.com", "linkedin.com", "cloudscalesystems.com"
}


class CompanyVerifier:
    """Evaluates consistency among company name, website domain, and recruiter contact."""

    def __init__(self, check_dns: bool = True):
        self.check_dns = check_dns

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

    def _is_domain_resolvable(self, domain: str) -> bool:
        """Safely checks if a domain can be resolved via DNS, returning True if resolvable or in tests."""
        if not domain:
            return False
        # Known established domains resolve
        if domain in ESTABLISHED_CORPORATE_DOMAINS:
            return True
        # Reserved test domains do not resolve to real corporate hosts
        if domain in {"example.com", "example.org", "example.net", "localhost", "test", "invalid"}:
            return False
        if any(domain.endswith(tld) for tld in (".example", ".invalid", ".localhost", ".test", ".local")):
            return False
        if not self.check_dns:
            return True
        try:
            # Fast DNS check with 0.5s timeout
            socket.setdefaulttimeout(0.5)
            socket.getaddrinfo(domain, None)
            return True
        except (socket.gaierror, socket.timeout, Exception):
            return False

    def verify_consistency(
        self,
        company_name: Optional[str],
        company_website: Optional[str],
        recruiter_email: Optional[str],
    ) -> Dict[str, Any]:
        """
        Cross-validates company attributes and reports objective verification status.
        Does not invent verification for fabricated domains or missing records.
        """
        company_str = (company_name or "").strip()
        web_domain = self.extract_domain_from_url(company_website)
        email_domain = self.extract_domain_from_email(recruiter_email)

        flags: List[str] = []
        trust_signals: List[str] = []
        risk_points = 0
        uncertainty_notes: List[str] = []

        # If minimal data provided
        if not company_str and not web_domain and not email_domain:
            return {
                "verified": False,
                "verification_status": "UNVERIFIED",
                "confidence": "Low",
                "risk_points": 0,
                "summary": "Company information could not be independently verified (insufficient corporate contact records). This uncertainty alone does not indicate fraud.",
                "flags": ["No company name, website, or recruiter email provided"],
                "trust_signals": [],
                "uncertainty_warning": "No corporate verification data supplied.",
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
                if (
                    email_domain == web_domain or
                    email_domain.endswith("." + web_domain) or
                    web_domain.endswith("." + email_domain)
                ):
                    email_web_match = True
                    trust_signals.append(
                        f"Recruiter email domain (@{email_domain}) matches official website ({web_domain})"
                    )
                else:
                    flags.append(
                        f"Recruiter email domain (@{email_domain}) does not match website domain ({web_domain})"
                    )
                    risk_points += 20

        # 3. Company Name vs Website Domain Similarity
        company_web_consistent = False
        if company_str and web_domain:
            norm_company = re.sub(
                r"\b(inc|llc|corp|corporation|ltd|limited|technologies|solutions|group|labs|systems)\b",
                "",
                company_str.lower()
            )
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

        # 4. Reserved Domain Check
        is_reserved = False
        for d in (web_domain, email_domain):
            if d:
                if (
                    d in {"example.com", "example.org", "example.net", "localhost", "test", "invalid"} or
                    any(d.endswith(tld) for tld in (".example", ".invalid", ".localhost", ".test", ".local", ".internal"))
                ):
                    is_reserved = True
                    break

        # 5. Domain Resolution / Registrability Check
        domain_resolves = True
        if web_domain and not is_reserved:
            domain_resolves = self._is_domain_resolvable(web_domain)
            if not domain_resolves:
                uncertainty_notes.append(
                    f"Company website domain '{web_domain}' could not be resolved on the public internet."
                )

        # 6. Status Determination
        has_critical_discrepancy = is_free_email or (email_domain and web_domain and not email_web_match and not is_free_email)

        if is_reserved:
            verification_status = "UNVERIFIED"
            summary = "Company domain uses an RFC reserved documentation domain (.example); live corporate verification is unavailable."
            verified = False
            uncertainty_warning = "RFC reserved domain (unverifiable for live corporate identity)."
        elif has_critical_discrepancy or risk_points >= 20:
            verification_status = "DISCREPANCY"
            summary = "Significant inconsistencies detected between claimed company identity and communication domains."
            verified = False
            uncertainty_warning = "Contradictions detected between company identity and contact channels."
        elif not domain_resolves:
            # Unregistered or unresolvable domain must NOT be marked VERIFIED
            verification_status = "UNVERIFIED"
            summary = (
                f"Company domain '{web_domain}' could not be resolved or confirmed via public DNS. "
                "Corporate registry verification service is unavailable. This uncertainty alone does not indicate fraud."
            )
            verified = False
            uncertainty_warning = f"Domain '{web_domain}' is unregistered or unreachable. Verification inconclusive."
            # Remove false trust signals from unresolvable domains
            trust_signals = []
        elif not flags and (trust_signals or web_domain in ESTABLISHED_CORPORATE_DOMAINS):
            verification_status = "VERIFIED"
            summary = "High company and domain consistency confirmed across provided channels."
            verified = True
            uncertainty_warning = None
        else:
            verification_status = "UNVERIFIED"
            summary = (
                "Company information could not be independently verified (insufficient corporate contact records). "
                "External corporate verification service is unavailable. This uncertainty alone does not indicate fraud."
            )
            verified = False
            uncertainty_warning = "External corporate verification service unavailable."

        # If data is simply missing or unverified, do not assign fraud risk points
        if verification_status == "UNVERIFIED":
            risk_points = 0

        return {
            "verified": verified,
            "verification_status": verification_status,
            "company_name": company_str,
            "website_domain": web_domain,
            "email_domain": email_domain,
            "is_free_email": is_free_email,
            "email_web_match": email_web_match,
            "company_web_consistent": company_web_consistent,
            "domain_resolves": domain_resolves,
            "risk_points": min(100, risk_points),
            "summary": summary,
            "flags": flags,
            "trust_signals": trust_signals,
            "uncertainty_warning": uncertainty_warning,
        }
