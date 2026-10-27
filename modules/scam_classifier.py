"""
Recruitment Scam Multi-Category Classifier:
Identifies specific threat typologies and scam patterns (multi-label).
"""

import re
from typing import Any, Dict, List, Optional


class ScamClassifier:
    """Classifies recruitment threats into standard cybersecurity fraud typologies."""

    CATEGORIES = {
        "Payment/Registration Fee Scam": [
            r"\b(?:registration|application|training|processing|background\s+check|software|equipment)\s+fee\b",
            r"\b(?:deposit|upfront\s+cost|pay\s+first|advance\s+payment|security\s+deposit)\b",
            r"\b(?:wire\s+transfer|moneygram|western\s+union|gift\s+card|bitcoin|crypto|usdt)\b",
            r"\b(?:reimburse\s+you\s+later|cash\s+this\s+check|check\s+deposit)\b",
        ],
        "Phishing/Information Harvesting": [
            r"\b(?:login|verify\s+your\s+account|credentials|password|otp|verification\s+code)\b",
            r"\b(?:docs\.google\.com|forms\.gle|formspree|typeform)\b",
            r"\b(?:confirm\s+identity\s+link|click\s+here\s+to\s+verify)\b",
        ],
        "Personal Information Scam": [
            r"\b(?:social\s+security\s+number|ssn|passport|national\s+id|driving\s+license)\b",
            r"\b(?:bank\s+account\s+number|routing\s+number|credit\s+card|debit\s+card|cvv)\b",
            r"\b(?:send\s+photo\s+of\s+id|id\s+verification\s+before\s+interview)\b",
        ],
        "Company Impersonation": [
            r"\b(?:hiring\s+on\s+behalf\s+of|representing)\b",
            r"@(?:gmail|yahoo|hotmail|outlook|mail)\.com",
        ],
        "Unrealistic Job Offer": [
            r"\b(?:no\s+(?:prior\s+)?experience\s+(?:needed|required)\s+(?:to\s+earn|\$\d+)|no\s+interview\s+required|instant\s+hire|guaranteed\s+job|guaranteed\s+payout|guaranteed\s+income)\b",
            r"(?:(?:earn\s+)?\$\d{2,3}(?:,\d{3})*\s*(?:per\s+day|daily|weekly|a\s+day|hourly|per\s+hour))\b",
            r"\b(?:make\s+thousands\s+weekly|financial\s+freedom|work\s+1\s+hour\s+a\s+day)\b",
            r"\b(?:100%\s+guaranteed\s+income|risk\s+free\s+income)\b",
        ],
        "Suspicious Application Link": [
            r"\b(?:bit\.ly|tinyurl\.com|t\.co|shorturl)\b",
            r"\b(?:telegram|t\.me|whatsapp|wa\.me|signal)\b",
        ],
    }

    def classify_scam_categories(
        self,
        job_data: Dict[str, Any],
        url_analysis: Optional[Dict[str, Any]] = None,
        company_analysis: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        Analyzes textual content and metadata to identify all applicable scam typologies.
        Returns a list of matching scam category strings.
        Does not falsely classify entry-level graduate roles or reserved domains as scams.
        """
        composite_text = " ".join([
            str(job_data.get("title", "")),
            str(job_data.get("description", "")),
            str(job_data.get("requirements", "")),
            str(job_data.get("benefits", "")),
            str(job_data.get("salary", "")),
            str(job_data.get("email", "")),
            str(job_data.get("url", "")),
        ]).lower()

        matched_categories: List[str] = []

        # 1. Text pattern checks
        for cat_name, patterns in self.CATEGORIES.items():
            for pat in patterns:
                if re.search(pat, composite_text):
                    if cat_name not in matched_categories:
                        matched_categories.append(cat_name)
                    break

        # 2. URL analysis cross-checks
        if url_analysis and url_analysis.get("analyzed"):
            # Obfuscated or free form hosts are suspicious application links
            if url_analysis.get("is_shortened") or url_analysis.get("is_ip_literal"):
                if "Suspicious Application Link" not in matched_categories:
                    matched_categories.append("Suspicious Application Link")
            if url_analysis.get("is_free_form"):
                if "Phishing/Information Harvesting" not in matched_categories:
                    matched_categories.append("Phishing/Information Harvesting")

        # 3. Company consistency cross-checks
        if company_analysis:
            if company_analysis.get("is_free_email") or company_analysis.get("flags"):
                if any("discrepancy" in f.lower() or "free public email" in f.lower() for f in company_analysis.get("flags", [])):
                    if "Company Impersonation" not in matched_categories:
                        matched_categories.append("Company Impersonation")

        # 4. Fallback categorization if flagged but no specific typology
        if not matched_categories and (
            (url_analysis and not url_analysis.get("is_safe") and not url_analysis.get("is_reserved_domain") and url_analysis.get("risk_points", 0) >= 30) or
            (company_analysis and company_analysis.get("risk_points", 0) >= 25)
        ):
            matched_categories.append("Other Suspicious Recruitment Activity")

        # If multiple scam types are present, mark baseline threat
        if len(matched_categories) >= 2 and "Suspicious Recruitment Threat Pattern" not in matched_categories:
            matched_categories.insert(0, "Suspicious Recruitment Threat Pattern")

        return matched_categories
