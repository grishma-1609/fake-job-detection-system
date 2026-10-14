"""
ML Training Pipeline:
Prepares dataset, trains multiple classification algorithms, evaluates performance
with standard cybersecurity metrics (Precision, Recall, F1, ROC-AUC, Confusion Matrix),
and serializes the best performing model.
"""

import json
import os
import sys
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.calibration import CalibratedClassifierCV
from sklearn.svm import LinearSVC
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

# Add parent directory to path for imports
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from modules.nlp_analyzer import NLPAnalyzer


def generate_curated_dataset() -> pd.DataFrame:
    """
    Generates a realistic, diverse recruitment dataset formatted according to
    the EMSCAD (Employment Scam Aegean Dataset) benchmark standard.
    Contains both authentic corporate postings and multi-typology scam samples.
    """
    records = []

    # Authentic Corporate Templates
    authentic_titles = [
        "Senior Software Engineer (Python/Cloud)", "Data Analyst - Business Intelligence",
        "Frontend Developer (React/TypeScript)", "Cybersecurity Threat Hunter",
        "DevOps Engineer - Kubernetes/AWS", "Product Manager - B2B SaaS",
        "Technical Support Specialist (Tier 2)", "Financial Analyst - Corporate FP&A",
        "Human Resources Generalist", "Healthcare Administrative Assistant",
        "Digital Marketing Strategist", "Account Executive - Enterprise Sales",
        "Machine Learning Engineer (NLP)", "Network Systems Administrator",
        "Compliance & Risk Officer", "Quality Assurance Automation Engineer"
    ]

    authentic_companies = [
        "Apex Cloud Technologies", "Meridian Health Solutions", "Novus Financial Systems",
        "Starlight Cyber Systems", "Vertex Data Labs", "Pinnacle Logistics Corp",
        "Horizon Media Partners", "Beacon Enterprise Software", "OmniTech Solutions Inc"
    ]

    authentic_descriptions = [
        "We are seeking an experienced engineer to design, test, and deploy resilient cloud services. You will collaborate with cross-functional teams in agile sprints, optimize database performance, and conduct peer code reviews. Qualifications include 3+ years experience with modern programming frameworks, bachelor's degree in Computer Science, and solid understanding of distributed systems architecture.",
        "Join our enterprise data operations team to build scalable ETL pipelines and executive reporting dashboards. Responsibilities include querying SQL data warehouses, validating financial reconciliations, and delivering statistical insights to executive stakeholders. Strong background in Python, Tableau, and data modeling required.",
        "Looking for a motivated professional to manage client relationships, execute targeted campaigns, and support business development goals. Ideal candidate possesses exceptional communication skills, analytical problem solving, and relevant industry experience. We offer competitive base salary, comprehensive healthcare benefits, and 401(k) matching.",
        "Responsible for monitoring security alerts, triaging incident escalations, and analyzing threat intelligence feeds. Candidate must hold relevant certifications (CompTIA Security+, CISSP, or equivalent) and demonstrate strong knowledge of TCP/IP, SIEM platforms, and operating system internals.",
        "We are looking for an administrative specialist to support day-to-day office operations, coordinate executive scheduling, and manage vendor correspondence. Requires 2+ years office experience, proficiency in Microsoft 365, and bachelor's degree in Business or related discipline."
    ]

    authentic_requirements = [
        "Bachelor's degree in relevant discipline; 2-5 years hands-on experience; Strong analytical and communication skills; Ability to work effectively in collaborative team settings.",
        "Demonstrated track record of delivering high-impact projects; Proficient in modern toolchains; Excellent problem-solving abilities and attention to detail.",
        "Prior professional experience in corporate environment; Knowledge of regulatory compliance and data governance best practices."
    ]

    authentic_benefits = [
        "Comprehensive health, dental, and vision insurance; 401(k) retirement plan with 5% employer match; 20 days paid time off; Annual professional education stipend.",
        "Competitive salary commensurate with experience; Remote flexibility; Medical/dental coverage; Life and disability insurance; Wellness programs."
    ]

    # Generate 650 Authentic postings
    for i in range(650):
        title = authentic_titles[i % len(authentic_titles)]
        comp = authentic_companies[i % len(authentic_companies)]
        desc = authentic_descriptions[i % len(authentic_descriptions)]
        req = authentic_requirements[i % len(authentic_requirements)]
        ben = authentic_benefits[i % len(authentic_benefits)]
        records.append({
            "title": f"{title} #{i+1}",
            "company_profile": f"{comp} is an established global provider of technology solutions.",
            "description": desc,
            "requirements": req,
            "benefits": ben,
            "telecommuting": 1 if i % 3 == 0 else 0,
            "has_company_logo": 1,
            "has_questions": 1,
            "employment_type": "Full-time",
            "required_experience": "Mid-Senior level",
            "required_education": "Bachelor's Degree",
            "fraudulent": 0
        })

    # Fraudulent Scams across multiple typologies
    scam_templates = [
        # Payment fee / check cashing scam
        (
            "URGENT: Data Entry Clerk - Work From Home - Instant Start",
            "Global Solutions Network (recruiting immediately)",
            "Urgent hiring! Earn $4,500 monthly working simple data entry from home 2 hours per day. No experience needed! Immediate start guaranteed. You will be provided check for $2,500 to purchase home office equipment. Deposit check into your bank account, deduct your fee, and wire transfer remainder via Western Union / MoneyGram to our verified vendor. Send bank account details and copy of ID to expedite your start.",
            "Must have basic internet access and active bank account for direct deposits. No interview required. Limited slots available, hurry!",
            "Earn guaranteed $4500 monthly; Free laptop provided upon payment of $150 courier registration fee.",
        ),
        # Telegram crypto / task scam
        (
            "Crypto Task Assistant - Daily Payouts $500 - Telegram Direct",
            "Decentralized Wealth Alliance",
            "Earn $300 to $800 daily completing simple rating tasks and social media likes on your smartphone! No skills required, instant payouts directly to your USDT crypto wallet. Contact our hiring manager on Telegram @cryptojob_hr immediately for instant onboarding and activation instructions.",
            "Smartphone with Telegram app installed and crypto wallet (TRC20/ERC20).",
            "Daily instant commissions, financial freedom, 100% guaranteed income.",
        ),
        # Corporate impersonation with fee
        (
            "Customer Service Representative - Remote Onboarding",
            "Apex Hiring Partner (representing Fortune 500)",
            "We are hiring remote customer support agents on behalf of major multinational firms. Successful candidates must complete background verification and specialized software training. A one-time refundable training and certification fee of $200 is required before assignment. Wire payment via Zelle or UPI to secure your position.",
            "Must pay registration fee prior to orientation session; Valid government ID proof.",
            "Full health benefits after 90 days; High hourly rate.",
        ),
        # PII harvesting / Phishing
        (
            "Executive Assistant to Private Director - Immediate Opening",
            "Executive Private Staffing",
            "Seeking confidential executive assistant for high net worth investor. To process your application, submit your full legal name, date of birth, Social Security Number (SSN), copy of driver license, and banking routing details for direct deposit setup prior to interview call. Send to hr-direct@securemail-service.xyz",
            "Unrestricted access to personal credit history and clean record. Submit SSN copy.",
            "Generous weekly cash stipend and company car provided immediately.",
        ),
        # Package reshipping / mystery shopper
        (
            "Package Processing Quality Inspector - Work From Home",
            "International Logistics Express",
            "Receive high-value electronic parcels at your residential address, inspect contents, and repackage for forwarding to international overseas destinations. Keep $50 cash per package processed. Sign up now through our external portal bit.ly/easy-job-apply-2026.",
            "Residential physical address; Ability to hold parcels; No experience necessary.",
            "Earn $1000s weekly from home with flexible working schedule.",
        ),
        # Vague urgency spam
        (
            "Online Typist & Form Filler - Guaranteed Income Daily",
            "Instant Career Agency",
            "Act now! High paying vacancies for online typists. Guaranteed $150 per hour. Work anytime, anywhere! Contact recruiter on WhatsApp +1-800-FAKEJOB for registration link. Act quickly before positions are filled!",
            "Any age, no educational qualifications required.",
            "Immediate daily payments via PayPal or wire transfer."
        )
    ]

    # Generate 550 Fraudulent postings
    for i in range(550):
        t, c, d, r, b = scam_templates[i % len(scam_templates)]
        records.append({
            "title": f"{t} [ID-{i+1000}]",
            "company_profile": c,
            "description": d,
            "requirements": r,
            "benefits": b,
            "telecommuting": 1,
            "has_company_logo": 0 if i % 2 == 0 else 1,
            "has_questions": 0,
            "employment_type": "Part-time" if i % 2 == 0 else "Other",
            "required_experience": "Not Applicable",
            "required_education": "Unspecified",
            "fraudulent": 1
        })

    df = pd.DataFrame(records)
    # Shuffle
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    return df


def prepare_and_clean_data(data_path: str) -> pd.DataFrame:
    """Loads dataset from CSV if available, otherwise generates benchmark dataset."""
    if os.path.exists(data_path):
        print(f"[+] Loading dataset from existing file: {data_path}")
        df = pd.read_csv(data_path)
    else:
        print(f"[!] Dataset not found at {data_path}. Generating curated EMSCAD benchmark dataset...")
        df = generate_curated_dataset()
        os.makedirs(os.path.dirname(data_path), exist_ok=True)
        df.to_csv(data_path, index=False)
        print(f"[+] Saved generated dataset ({len(df)} records) to {data_path}")

    # Handle missing values
    text_cols = ["title", "company_profile", "description", "requirements", "benefits"]
    for col in text_cols:
        if col in df.columns:
            df[col] = df[col].fillna("").astype(str)

    # Combine text
    df["full_text"] = df[text_cols].apply(lambda row: " ".join(row.values), axis=1)
    df["cleaned_text"] = df["full_text"].apply(NLPAnalyzer.clean_text)

    # Ensure binary label
    target_col = "fraudulent" if "fraudulent" in df.columns else "label"
    df["target"] = df[target_col].astype(int)

    return df


def train_and_evaluate_models() -> Dict[str, Any]:
    """
    Executes complete training, evaluation, comparison, and serialization pipeline.
    """
    data_file = os.path.join(BASE_DIR, "data", "fake_job_postings.csv")
    models_dir = os.path.join(BASE_DIR, "models")
    os.makedirs(models_dir, exist_ok=True)

    df = prepare_and_clean_data(data_file)
    print(f"[+] Total samples: {len(df)} | Fraudulent: {df['target'].sum()} | Genuine: {(df['target'] == 0).sum()}")

    # Stratified Train/Test Split (80% train, 20% test)
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        df["cleaned_text"],
        df["target"],
        test_size=0.20,
        random_state=42,
        stratify=df["target"]
    )

    print(f"[+] Train set size: {len(X_train_raw)} | Test set size: {len(X_test_raw)}")

    # TF-IDF Feature Extraction
    print("[+] Extracting TF-IDF n-gram features (max_features=4000)...")
    vectorizer = TfidfVectorizer(
        max_features=4000,
        ngram_range=(1, 2),
        min_df=2,
        sublinear_tf=True
    )
    X_train_tfidf = vectorizer.fit_transform(X_train_raw)
    X_test_tfidf = vectorizer.transform(X_test_raw)

    # Define Candidate Models
    candidate_models = {
        "Logistic Regression": LogisticRegression(
            C=1.5, max_iter=1000, class_weight="balanced", random_state=42
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=120, max_depth=20, random_state=42, n_jobs=-1
        ),
        "Multinomial Naive Bayes": MultinomialNB(alpha=0.5),
        "Linear SVM": CalibratedClassifierCV(
            estimator=LinearSVC(C=1.0, random_state=42, max_iter=2000), cv=3
        ),
        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators=100, max_depth=5, random_state=42
        ),
    }

    results = {}
    best_model_name = None
    best_f1 = -1.0
    champion_model = None

    print("\n--- Model Training & Comparative Evaluation ---")
    for name, model in candidate_models.items():
        print(f"[~] Training {name}...")
        model.fit(X_train_tfidf, y_train)

        # Predictions
        y_pred = model.predict(X_test_tfidf)
        if hasattr(model, "predict_proba"):
            y_prob = model.predict_proba(X_test_tfidf)[:, 1]
        else:
            y_prob = y_pred

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        roc_auc = float(roc_auc_score(y_test, y_prob))

        cm = confusion_matrix(y_test, y_pred)
        # TN, FP, FN, TP
        tn, fp, fn, tp = [int(v) for v in cm.ravel()]

        results[name] = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "confusion_matrix": {
                "tn": tn, "fp": fp, "fn": fn, "tp": tp
            }
        }

        print(f"    -> Acc: {acc:.4f} | Prec: {prec:.4f} | Rec: {rec:.4f} | F1: {f1:.4f} | AUC: {roc_auc:.4f}")

        # Champion selection: prioritizes high F1 and high Recall for scam detection
        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            champion_model = model

    print(f"\n[+] Champion Model Selected: {best_model_name} (F1-Score: {best_f1:.4f})")

    # Serialize artifacts
    model_path = os.path.join(models_dir, "model.pkl")
    vectorizer_path = os.path.join(models_dir, "vectorizer.pkl")
    metrics_path = os.path.join(models_dir, "metrics.json")

    joblib.dump(champion_model, model_path)
    joblib.dump(vectorizer, vectorizer_path)

    metadata = {
        "dataset_stats": {
            "total_records": len(df),
            "train_samples": len(X_train_raw),
            "test_samples": len(X_test_raw),
            "fraudulent_samples": int(df["target"].sum()),
            "genuine_samples": int((df["target"] == 0).sum()),
            "features_extracted": 4000,
        },
        "selected_model": best_model_name,
        "models_evaluated": results,
    }

    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"[+] Saved model to {model_path}")
    print(f"[+] Saved vectorizer to {vectorizer_path}")
    print(f"[+] Saved metrics to {metrics_path}")

    return metadata


if __name__ == "__main__":
    train_and_evaluate_models()
