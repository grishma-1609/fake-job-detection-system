"""
Explainable AI (XAI) Module:
Decomposes predictions into interpretable feature contributions,
lexical weight attributions, and human-readable cybersecurity rationales.
"""

from typing import Any, Dict, List, Optional, Tuple


class ExplainabilityEngine:
    """Provides transparent, interpretable factor analysis for job classification."""

    def __init__(self, vectorizer=None, model=None):
        self.vectorizer = vectorizer
        self.model = model

    def explain_prediction(
        self,
        job_data: Dict[str, Any],
        ml_prediction: str,
        ml_probability: float,
        nlp_features: Dict[str, Any],
        red_flags: List[str],
        trust_indicators: List[str],
        scam_categories: List[str],
    ) -> Dict[str, Any]:
        """
        Synthesizes ML feature contributions, detected heuristics, and NLP signals
        into a clear 'Why this posting was flagged' explainability report.
        """
        top_risk_tokens: List[Tuple[str, float]] = []
        top_trust_tokens: List[Tuple[str, float]] = []

        # 1. Feature Attribution via TF-IDF and Model Coefficients (if model and vectorizer are available)
        if self.vectorizer and self.model and hasattr(self.model, "coef_"):
            try:
                composite_text = " ".join([
                    str(job_data.get("title", "")),
                    str(job_data.get("description", "")),
                    str(job_data.get("requirements", "")),
                    str(job_data.get("benefits", "")),
                ])
                feature_names = self.vectorizer.get_feature_names_out()
                tfidf_vec = self.vectorizer.transform([composite_text])

                # Get active features
                cx = tfidf_vec.tocoo()
                coefs = self.model.coef_[0]

                contributions = []
                for idx, val in zip(cx.col, cx.data):
                    feat_name = feature_names[idx]
                    weight = val * coefs[idx]
                    contributions.append((feat_name, weight))

                # Sort by weight
                contributions.sort(key=lambda x: x[1], reverse=True)

                # Positive weights push toward Fake (label 1)
                for word, weight in contributions[:8]:
                    if weight > 0.05:
                        top_risk_tokens.append((word, round(float(weight), 3)))

                # Negative weights push toward Genuine (label 0)
                contributions.sort(key=lambda x: x[1])
                for word, weight in contributions[:8]:
                    if weight < -0.05:
                        top_trust_tokens.append((word, round(float(abs(weight)), 3)))
            except Exception:
                pass

        # 2. Extract detected NLP phrase triggers if model tokens empty
        if not top_risk_tokens:
            for phrase in nlp_features.get("detected_phrases", []):
                top_risk_tokens.append((phrase, 0.45))

        # 3. Construct natural language explanations ("Why this posting was flagged")
        narrative_points: List[str] = []

        if ml_probability >= 0.70:
            narrative_points.append(
                f"Machine Learning text classifier assigned a high fraud probability ({ml_probability*100:.1f}%) "
                "based on linguistic patterns learned from historical recruitment scam corpora."
            )
        elif ml_probability <= 0.30:
            narrative_points.append(
                f"Machine Learning classifier identified authentic job structure and vocabulary "
                f"with { (1.0 - ml_probability)*100:.1f}% genuine probability."
            )

        if nlp_features.get("detected_phrases"):
            phrases_str = ", ".join([f"'{p}'" for p in nlp_features["detected_phrases"][:4]])
            narrative_points.append(f"Identified high-risk recruitment fraud phrases: {phrases_str}.")

        if nlp_features.get("uppercase_ratio", 0) > 0.25:
            narrative_points.append("Abnormally high capitalization frequency detected, typical of spam/urgency hooks.")

        if scam_categories:
            cats_str = ", ".join(scam_categories[:3])
            narrative_points.append(f"Behavioral rules matched known scam profiles: {cats_str}.")

        if red_flags:
            top_flags = "; ".join(red_flags[:3])
            narrative_points.append(f"Critical security discrepancies: {top_flags}.")

        if trust_indicators:
            top_trust = "; ".join(trust_indicators[:2])
            narrative_points.append(f"Verifiable integrity elements: {top_trust}.")

        if not narrative_points:
            narrative_points.append(
                "No strong fraudulent indicators detected. Job posting vocabulary conforms to standard corporate postings."
            )

        summary_explanation = " ".join(narrative_points)

        return {
            "summary": summary_explanation,
            "narrative_points": narrative_points,
            "top_risk_tokens": top_risk_tokens,
            "top_trust_tokens": top_trust_tokens,
            "disclaimer": (
                "Notice: Feature importance and risk scores represent probabilistic decision-support "
                "insights based on machine learning and heuristic cybersecurity rules. "
                "They should not be construed as absolute legal proof of fraudulent intent."
            ),
        }
