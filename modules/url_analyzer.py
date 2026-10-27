"""
URL & Domain Security Analyzer:
Performs safe static and HTTP security checks on application links and job posting URLs.
Adheres strictly to safe, non-intrusive cybersecurity standards (no port scanning, no exploits).
Provides independent URL security indicators and explicit uncertainty warnings.
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests


# Recognized URL shortener domains commonly abused to mask destination
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy"
}

# Free form hosts often used by scammers instead of legitimate ATS portals
FREE_FORM_HOSTS = {
    "forms.gle", "docs.google.com", "formspree.io", "typeform.com",
    "jotform.com", "surveyhero.com", "formsite.com", "wpforms.com"
}

# Recognized Applicant Tracking Systems (ATS) commonly used by authentic employers
AUTHENTIC_ATS_HOSTS = {
    "linkedin.com", "indeed.com", "glassdoor.com", "greenhouse.io",
    "lever.co", "workday.com", "smartrecruiters.com", "icims.com",
    "jobvite.com", "bamboohr.com", "ashbyhq.com", "myworkdayjobs.com"
}

# RFC 2606 / RFC 6761 reserved domains for documentation, testing, and private networks
RESERVED_DOMAINS = {
    "example.com", "example.org", "example.net", "example.edu",
    "localhost", "test", "invalid"
}
RESERVED_TLDS = (".example", ".invalid", ".localhost", ".test", ".local", ".internal")

# Suspicious keywords in URL paths or hostnames
SUSPICIOUS_URL_KEYWORDS = [
    "login", "verify", "secure-account", "wallet", "payout", "payment",
    "careers-verification", "hr-portal-direct", "job-apply-now", "telegram",
    "wa.me", "chat.whatsapp.com", "wire", "invoice"
]


class URLSecurityAnalyzer:
    """Safe URL and domain security inspector for recruitment links."""

    def __init__(self, timeout: float = 1.5):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CyberSecurity-Audit-Bot/1.0 (Job-Verification-Safety-Check)"
        })

    @staticmethod
    def is_reserved_domain(hostname: str) -> bool:
        """Checks if a domain is reserved under RFC 2606 / RFC 6761."""
        h = (hostname or "").lower().strip()
        if h in RESERVED_DOMAINS:
            return True
        for tld in RESERVED_TLDS:
            if h.endswith(tld):
                return True
        return False

    def analyze_url(self, raw_url: Optional[str], company_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Safely inspects URL structure and optionally checks HTTP response headers.
        Returns detailed security indicators, separates URL validity from job authenticity,
        and provides honest uncertainty warnings for unreachable hosts.
        """
        if not raw_url or not str(raw_url).strip():
            return {
                "analyzed": False,
                "status": "No URL provided",
                "url_validity": "No URL Provided",
                "url_validity_details": "No application link was submitted with the job posting.",
                "is_safe": True,
                "is_reserved_domain": False,
                "is_live_valid": False,
                "risk_points": 0,
                "flags": [],
                "uncertainty_warning": "No application URL provided for verification.",
            }

        url = str(raw_url).strip()
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "https://" + url

        try:
            parsed = urlparse(url)
        except Exception as e:
            return {
                "analyzed": False,
                "status": f"URL analysis unavailable (Malformed URL: {str(e)})",
                "url_validity": "Malformed URL",
                "url_validity_details": f"The URL syntax is malformed: {str(e)}",
                "is_safe": False,
                "is_reserved_domain": False,
                "is_live_valid": False,
                "risk_points": 15,
                "flags": [f"Malformed URL syntax: {url}"],
                "uncertainty_warning": "Malformed URL cannot be parsed safely.",
            }

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return {
                "analyzed": False,
                "status": "URL analysis unavailable (Missing hostname)",
                "url_validity": "Missing Hostname",
                "url_validity_details": "The application link lacks a valid network host.",
                "is_safe": False,
                "is_reserved_domain": False,
                "is_live_valid": False,
                "risk_points": 15,
                "flags": ["Missing hostname in application URL"],
                "uncertainty_warning": "Missing network host in application link.",
            }

        flags: List[str] = []
        risk_points = 0
        is_ip_literal = False

        # 1. IP address check (IP used instead of domain)
        try:
            _ = ipaddress.ip_address(hostname)
            is_ip_literal = True
            flags.append(f"Direct IP address used instead of domain name: {hostname}")
            risk_points += 35
        except ValueError:
            is_ip_literal = False

        # 2. HTTPS availability check
        uses_https = parsed.scheme == "https"
        if not uses_https:
            flags.append("Insecure HTTP protocol used (no TLS encryption)")
            risk_points += 20

        # 3. URL Length
        url_length = len(url)
        if url_length > 90:
            flags.append(f"Excessively long URL ({url_length} characters)")
            risk_points += 10

        # 4. Number of Subdomains
        domain_parts = hostname.split(".")
        num_subdomains = max(0, len(domain_parts) - 2)
        if num_subdomains >= 3:
            flags.append(f"High subdomain depth detected ({num_subdomains} subdomains)")
            risk_points += 15

        # 5. Suspicious characters
        if "@" in parsed.netloc:
            flags.append("URL contains '@' credential notation (high phishing risk)")
            risk_points += 40
        if "%" in url:
            flags.append("URL contains encoded hex characters (%)")
            risk_points += 10

        # 6. URL Shortening check
        is_shortened = hostname in SHORTENER_DOMAINS
        if is_shortened:
            flags.append(f"URL shortener detected ({hostname}); destination is obfuscated")
            risk_points += 25

        # 7. Free Form Hosting check
        is_free_form = hostname in FREE_FORM_HOSTS or any(f in url.lower() for f in FREE_FORM_HOSTS)
        if is_free_form:
            flags.append(f"Job application hosted on generic free form service ({hostname})")
            risk_points += 30

        # 8. Suspicious keywords in URL
        url_lower = url.lower()
        for kw in SUSPICIOUS_URL_KEYWORDS:
            if kw in url_lower:
                flags.append(f"Suspicious security keyword in URL: '{kw}'")
                risk_points += 15
                break

        # 9. Company name consistency check against URL domain
        company_mismatch = False
        if company_name and len(company_name.strip()) > 3 and not is_ip_literal and not is_shortened:
            comp_norm = re.sub(
                r"\b(inc|llc|corp|corporation|ltd|limited|technologies|tech|solutions|group|labs|systems|co)\b",
                "",
                company_name.lower()
            )
            comp_clean = re.sub(r"[^a-zA-Z0-9]", "", comp_norm)
            domain_clean = re.sub(r"[^a-zA-Z0-9]", "", hostname.split(".")[0])
            is_ats = any(hostname == ats or hostname.endswith("." + ats) for ats in AUTHENTIC_ATS_HOSTS)
            if len(comp_clean) >= 3 and not is_ats:
                if comp_clean not in hostname and domain_clean not in comp_clean:
                    company_mismatch = True
                    flags.append(f"Application link host '{hostname}' does not match claimed employer '{company_name}'")
                    risk_points += 20

        # 10. Reserved Domain and Safe Network Probe
        is_reserved = self.is_reserved_domain(hostname)
        network_status = "Not probed"
        redirect_count = 0
        final_url = url
        is_live_valid = False
        uncertainty_warning = None

        if is_reserved:
            flags.append(f"Reserved domain ({hostname}) under RFC 2606 / RFC 6761 (invalid for live application submission)")
            network_status = "Reserved RFC 2606 domain (network probe skipped)"
            url_validity = "Reserved Domain (Invalid for live applications)"
            url_validity_details = f"The domain '{hostname}' is an RFC 2606 / RFC 6761 reserved domain for documentation/testing. It cannot receive live job applications."
            is_live_valid = False
            uncertainty_warning = "Application link uses an RFC reserved documentation domain."
        elif is_ip_literal:
            network_status = "Direct IP address (probe skipped)"
            url_validity = "Suspicious URL Structure (Direct IP)"
            url_validity_details = "Direct IP addresses are abnormal for legitimate career portals."
        else:
            try:
                resp = self.session.head(
                    url,
                    allow_redirects=True,
                    timeout=self.timeout,
                    verify=True,
                )
                redirect_count = len(resp.history)
                final_url = resp.url
                if redirect_count >= 4:
                    flags.append(f"Suspicious redirect chain detected ({redirect_count} redirects)")
                    risk_points += 20
                network_status = f"HTTP {resp.status_code} reachable"
                if risk_points < 25 and uses_https:
                    url_validity = "Valid Live URL (Reachable & Secure)"
                    url_validity_details = "Application link is reachable, uses TLS encryption, and resolves to an established domain."
                    is_live_valid = True
                else:
                    url_validity = "Suspicious URL Structure"
                    url_validity_details = "Application link exhibits risk indicators or insecure transport."
            except requests.exceptions.SSLError:
                flags.append("SSL/TLS certificate verification failed or self-signed")
                risk_points += 20
                network_status = "TLS Certificate Error"
                url_validity = "TLS Certificate Error"
                url_validity_details = "SSL/TLS certificate verification failed or domain uses self-signed certificate."
                uncertainty_warning = "TLS certificate could not be validated."
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                network_status = "Connection timeout or domain unreachable"
                url_validity = "Unreachable (Network timeout / Domain inactive)"
                url_validity_details = "Application link could not be reached. Domain may be inactive, behind an intranet, or expired. This uncertainty alone is not evidence of fraud."
                uncertainty_warning = "Application link could not be reached on the public internet. Connectivity verification inconclusive."
            except Exception as e:
                network_status = f"URL probe skipped: {str(e)[:40]}"
                url_validity = "Probe Inconclusive"
                url_validity_details = f"URL probe could not be completed: {str(e)[:50]}"
                uncertainty_warning = f"URL probe inconclusive: {str(e)[:50]}"

        # Safety evaluation (flags excluding the non-malicious reserved domain notice)
        threat_flags = [f for f in flags if "Reserved domain" not in f]
        is_safe = (
            risk_points < 25 and
            len(threat_flags) == 0 and
            not is_shortened and
            not is_free_form and
            not is_ip_literal
        )

        return {
            "analyzed": True,
            "status": "Analysis completed",
            "url": url,
            "domain": hostname,
            "url_validity": url_validity,
            "url_validity_details": url_validity_details,
            "is_reserved_domain": is_reserved,
            "is_live_valid": is_live_valid,
            "https_active": uses_https,
            "url_length": url_length,
            "subdomain_count": num_subdomains,
            "is_ip_literal": is_ip_literal,
            "is_shortened": is_shortened,
            "is_free_form": is_free_form,
            "company_mismatch": company_mismatch,
            "network_status": network_status,
            "redirect_count": redirect_count,
            "final_url": final_url,
            "risk_points": min(100, risk_points),
            "is_safe": is_safe,
            "flags": flags,
            "uncertainty_warning": uncertainty_warning,
        }
