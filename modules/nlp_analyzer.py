"""
NLP Analyzer: Text preprocessing, linguistic feature extraction,
and recruitment scam token pattern analysis.
"""

import re
from typing import Any, Dict, List, Set


# Common English stopwords list (built-in fallback so no missing NLTK download crashes)
STOPWORDS: Set[str] = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are",
    "aren't", "as", "at", "be", "because", "been", "before", "being", "below", "between", "both",
    "but", "by", "can't", "cannot", "could", "couldn't", "did", "didn't", "do", "does", "doesn't",
    "doing", "don't", "down", "during", "each", "few", "for", "from", "further", "had", "hadn't",
    "has", "hasn't", "have", "haven't", "having", "he", "he'd", "he'll", "he's", "her", "here",
    "here's", "hers", "herself", "him", "himself", "his", "how", "how's", "i", "i'd", "i'll",
    "i'm", "i've", "if", "in", "into", "is", "isn't", "it", "it's", "its", "itself", "let's",
    "me", "more", "most", "mustn't", "my", "myself", "no", "nor", "not", "of", "off", "on",
    "once", "only", "or", "other", "ought", "our", "ours", "ourselves", "out", "over", "own",
    "same", "shan't", "she", "she'd", "she'll", "she's", "should", "shouldn't", "so", "some",
    "such", "than", "that", "that's", "the", "their", "theirs", "them", "themselves", "then",
    "there", "there's", "these", "they", "they'd", "they'll", "they're", "they've", "this",
    "those", "through", "to", "too", "under", "until", "up", "very", "was", "wasn't", "we",
    "we'd", "we'll", "we're", "we've", "were", "weren't", "what", "what's", "when", "when's",
    "where", "where's", "which", "while", "who", "who's", "whom", "why", "why's", "with",
    "won't", "would", "wouldn't", "you", "you'd", "you'll", "you're", "you've", "your",
    "yours", "yourself", "yourselves"
}


# High-risk recruitment scam phrase patterns
SCAM_PHRASES = [
    r"\b(?:wire\s+transfer|western\s+union|moneygram)\b",
    r"\b(?:registration\s+fee|processing\s+fee|application\s+fee|training\s+fee)\b",
    r"\b(?:bank\s+account|routing\s+number|credit\s+card|debit\s+card|upi\s+id)\b",
    r"\b(?:ssn|social\s+security\s+number|passport\s+copy|id\s+proof)\b",
    r"\b(?:crypto|bitcoin|usdt|ethereum|wallet\s+address)\b",
    r"\b(?:telegram|whatsapp|signal\s+app|hangouts)\b",
    r"\b(?:no\s+interview|immediate\s+start|guaranteed\s+income|earn\s+\$\d{3,}\s+daily)\b",
    r"\b(?:work\s+from\s+home\s+data\s+entry|envelope\s+stuffing|mystery\s+shopper)\b",
    r"\b(?:gift\s+card|check\s+cashing|package\s+forwarding|reshipment)\b",
    r"\b(?:urgent\s+hiring|urgently\s+needed|limited\s+slots)\b",
]


class NLPAnalyzer:
    """Performs lexical, syntactic, and semantic preprocessing for job posting text."""

    def __init__(self):
        pass

    @staticmethod
    def clean_text(text: str) -> str:
        """Standardizes text, removes HTML tags, URLs, special characters."""
        if not text:
            return ""

        # Remove HTML tags
        text = re.sub(r"<[^>]+>", " ", text)
        # Remove URLs
        text = re.sub(r"http[s]?://\S+", " ", text)
        # Remove emails
        text = re.sub(r"\S+@\S+", " ", text)
        # Remove non-alphanumeric except spaces
        text = re.sub(r"[^a-zA-Z\s]", " ", text)
        # Lowercase
        text = text.lower()
        # Collapse whitespace
        text = re.sub(r"\s+", " ", text).strip()
        return text

    @staticmethod
    def tokenize_and_filter(text: str) -> List[str]:
        """Cleans and extracts non-stopword tokens."""
        cleaned = NLPAnalyzer.clean_text(text)
        tokens = cleaned.split()
        return [t for t in tokens if t not in STOPWORDS and len(t) > 2]

    @staticmethod
    def extract_linguistic_features(raw_text: str) -> Dict[str, Any]:
        """
        Extracts structural and stylistic features:
        - Uppercase ratio (excessive capitalization is common in scam postings)
        - Exclamation frequency
        - Word count
        - Average word length
        - Detected suspicious scam phrase triggers
        """
        if not raw_text:
            return {
                "word_count": 0,
                "uppercase_ratio": 0.0,
                "exclamation_count": 0,
                "detected_phrases": [],
                "urgency_score": 0.0,
            }

        words = raw_text.split()
        word_count = len(words)
        uppercase_chars = sum(1 for c in raw_text if c.isupper())
        total_letters = sum(1 for c in raw_text if c.isalpha()) or 1
        uppercase_ratio = uppercase_chars / total_letters

        exclamation_count = raw_text.count("!")

        # Scan for scam phrases
        detected_phrases = []
        raw_lower = raw_text.lower()
        for pattern in SCAM_PHRASES:
            matches = re.findall(pattern, raw_lower)
            if matches:
                detected_phrases.extend(matches)

        # Urgency calculation
        urgency_terms = ["urgent", "immediately", "hurry", "instant", "act now", "limited spots", "exclusive"]
        urgency_hits = sum(1 for term in urgency_terms if term in raw_lower)
        urgency_score = min(1.0, (urgency_hits * 0.25) + (1.0 if exclamation_count > 4 else 0.0))

        return {
            "word_count": word_count,
            "uppercase_ratio": round(uppercase_ratio, 3),
            "exclamation_count": exclamation_count,
            "detected_phrases": list(set(detected_phrases)),
            "urgency_score": round(urgency_score, 2),
        }

    @staticmethod
    def build_composite_text(job_data: Dict[str, Any]) -> str:
        """Combines all textual fields into a unified representation for TF-IDF."""
        parts = [
            str(job_data.get("title", "")),
            str(job_data.get("company", "")),
            str(job_data.get("location", "")),
            str(job_data.get("employment_type", "")),
            str(job_data.get("experience", "")),
            str(job_data.get("education", "")),
            str(job_data.get("description", "")),
            str(job_data.get("requirements", "")),
            str(job_data.get("benefits", "")),
            str(job_data.get("salary", "")),
        ]
        return " ".join([p for p in parts if p]).strip()
