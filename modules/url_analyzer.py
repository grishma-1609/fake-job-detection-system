"""
URL & Domain Security Analyzer:
Performs safe static and HTTP security checks on application links and job posting URLs.
Adheres strictly to safe, non-intrusive cybersecurity standards (no port scanning, no exploits).
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

# Suspicious keywords in URL paths or hostnames
SUSPICIOUS_URL_KEYWORDS = [
    "login", "verify", "secure-account", "wallet", "payout", "payment",
    "careers-verification", "hr-portal-direct", "job-apply-now", "telegram",
    "wa.me", "chat.whatsapp.com", "wire", "invoice"
]


class URLSecurityAnalyzer:
    """Safe URL and domain security inspector for recruitment links."""

    def __init__(self, timeout: float = 2.5):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CyberSecurity-Audit-Bot/1.0 (Job-Verification-Safety-Check)"
        })

    def analyze_url(self, raw_url: Optional[str], company_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Safely inspects URL structure and optionally checks HTTP response headers.
        Returns detailed security indicators or explicit 'URL analysis unavailable' status.
        """
        if not raw_url or not str(raw_url).strip():
            return {
                "analyzed": False,
                "status": "No URL provided",
                "is_safe": True,
                "risk_points": 0,
                "flags": [],
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
                "is_safe": False,
                "risk_points": 20,
                "flags": [f"Malformed URL syntax: {url}"],
            }

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return {
                "analyzed": False,
                "status": "URL analysis unavailable (Missing hostname)",
                "is_safe": False,
                "risk_points": 20,
                "flags": ["Missing hostname in application URL"],
            }

        flags: List[str] = []
        risk_points = 0
        is_ip_literal = False

        # 1. IP address check (IP used instead of domain)
        try:
            ip_obj = ipaddress.ip_address(hostname)
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
        if company_name and len(company_name.strip()) > 3 and not is_ip_literal:
            comp_clean = re.sub(r"[^a-zA-Z0-9]", "", company_name.lower())
            if comp_clean not in hostname and hostname not in ["linkedin.com", "indeed.com", "glassdoor.com", "greenhouse.io", "lever.co", "workday.com"]:
                # If neither the domain mentions company nor common ATS
                company_mismatch = True

        # 10. Safe Network Probe (HTTP HEAD check with redirect detection)
        network_status = "Not probed"
        redirect_count = 0
        final_url = url

        # Only probe if not a raw IP or private host
        if not is_ip_literal:
            try:
                resp = self.session.head(
                    url,
                    allow_redirects=True,
                    timeout=self.timeout,
                    verify=True,
                )
                redirect_count = len(resp.history)
                final_url = resp.url
                if redirect_count >= 3:
                    flags.append(f"Suspicious redirect chain detected ({redirect_count} redirects)")
                    risk_points += 20
                network_status = f"HTTP {resp.status_code} reachable"
            except requests.exceptions.SSLError:
                flags.append("SSL/TLS certificate verification failed or self-signed")
                risk_points += 25
                network_status = "TLS Certificate Error"
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                network_status = "Connection timeout or domain unreachable"
            except Exception as e:
                network_status = f"URL probe skipped: {str(e)[:40]}"

        is_safe = risk_points < 30 and len(flags) <= 1

        return {
            "analyzed": True,
            "status": "Analysis completed",
            "url": url,
            "domain": hostname,
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
        }
