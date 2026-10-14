"""
ML Predictor Module:
Loads serialized ML model and vectorizer, handles text vectorization,
and executes real-time inference for job postings.
"""

import os
import sys
from typing import Any, Dict, Optional, Tuple
import joblib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from modules.nlp_analyzer import NLPAnalyzer


class MLPredictor:
    """Manages model loading and prediction inference."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(MLPredictor, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if getattr(self, "_initialized", False):
            return

        self.models_dir = os.path.join(BASE_DIR, "models")
        self.model_path = os.path.join(self.models_dir, "model.pkl")
        self.vectorizer_path = os.path.join(self.models_dir, "vectorizer.pkl")
        self.metrics_path = os.path.join(self.models_dir, "metrics.json")

        self.model = None
        self.vectorizer = None
        self._load_or_train_pipeline()
        self._initialized = True

    def _load_or_train_pipeline(self):
        """Loads serialized model artifacts, training them if absent."""
        if not os.path.exists(self.model_path) or not os.path.exists(self.vectorizer_path):
            print("[!] Model artifacts missing. Auto-triggering model training pipeline...")
            from models.train_model import train_and_evaluate_models
            train_and_evaluate_models()

        try:
            self.model = joblib.load(self.model_path)
            self.vectorizer = joblib.load(self.vectorizer_path)
            print("[+] Successfully loaded trained ML model and TF-IDF vectorizer.")
        except Exception as e:
            print(f"[-] Error loading model artifacts: {e}")
            self.model = None
            self.vectorizer = None

    def predict(self, raw_text: str) -> Dict[str, Any]:
        """
        Executes ML prediction on raw job posting text.
        Returns prediction label, fraud probability, and status.
        """
        if self.model is None or self.vectorizer is None:
            # Re-attempt load
            self._load_or_train_pipeline()

        cleaned = NLPAnalyzer.clean_text(raw_text)
        if not cleaned:
            return {
                "prediction": "SUSPICIOUS",
                "fraud_probability": 0.50,
                "confidence": 50.0,
                "status": "Insufficient text for ML inference",
            }

        try:
            vec = self.vectorizer.transform([cleaned])
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(vec)[0]
                fraud_prob = float(probs[1])
            else:
                pred_raw = self.model.predict(vec)[0]
                fraud_prob = 0.90 if pred_raw == 1 else 0.10

            pred_label = "FAKE" if fraud_prob >= 0.50 else "GENUINE"
            confidence = round(abs(fraud_prob - 0.50) * 200.0, 1)  # 0 to 100% certainty scale

            return {
                "prediction": pred_label,
                "fraud_probability": round(fraud_prob, 4),
                "confidence": max(50.0, confidence),
                "status": "Inference successful",
            }
        except Exception as e:
            return {
                "prediction": "UNKNOWN",
                "fraud_probability": 0.50,
                "confidence": 0.0,
                "status": f"Inference error: {str(e)}",
            }

    def get_metrics_data(self) -> Optional[Dict[str, Any]]:
        """Reads evaluated model metrics generated during training."""
        if os.path.exists(self.metrics_path):
            try:
                import json
                with open(self.metrics_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return None
        return None


# Singleton accessor
_predictor_instance = None


def get_predictor() -> MLPredictor:
    global _predictor_instance
    if _predictor_instance is None:
        _predictor_instance = MLPredictor()
    return _predictor_instance
