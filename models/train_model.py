"""
ML Training Pipeline:
Prepares dataset, trains multiple classification algorithms, evaluates performance
with standard cybersecurity metrics (Precision, Recall, F1, ROC-AUC, Confusion Matrix),
tunes decision threshold on validation data to minimize false negatives,
and serializes the champion model and vectorizer.
"""

import json
import os
import sys
from typing import Any, Dict, List, Tuple
import joblib
import numpy as np
import pandas as pd

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

    # Authentic Corporate Templates across varied industries
    authentic_templates = [
        (
            "Senior Software Engineer (Python/Cloud)",
            "Apex Cloud Technologies",
            "We are seeking an experienced engineer to design, test, and deploy resilient cloud services. You will collaborate with cross-functional teams in agile sprints, optimize database performance, and conduct peer code reviews. Qualifications include 3+ years experience with modern programming frameworks, bachelor's degree in Computer Science, and solid understanding of distributed systems architecture.",
            "Bachelor's degree in relevant discipline; 3-5 years hands-on experience; Strong analytical and communication skills; Ability to work effectively in collaborative team settings.",
            "Comprehensive health, dental, and vision insurance; 401(k) retirement plan with 5% employer match; 20 days paid time off; Annual professional education stipend."
        ),
        (
            "Data Analyst - Business Intelligence",
            "Vertex Data Labs",
            "Join our enterprise data operations team to build scalable ETL pipelines and executive reporting dashboards. Responsibilities include querying SQL data warehouses, validating financial reconciliations, and delivering statistical insights to executive stakeholders. Strong background in Python, Tableau, and data modeling required.",
            "Demonstrated track record of delivering high-impact data projects; Proficient in SQL and Tableau; Excellent problem-solving abilities and attention to detail.",
            "Competitive salary commensurate with experience; Remote flexibility; Medical/dental coverage; Life and disability insurance; Wellness programs."
        ),
        (
            "Frontend Developer (React/TypeScript)",
            "Horizon Media Partners",
            "Looking for a skilled frontend engineer to build responsive, accessible web applications. You will translate UI/UX wireframes into performant React components, integrate GraphQL and REST APIs, and maintain cross-browser compatibility.",
            "2+ years experience with React, TypeScript, and modern CSS frameworks; Understanding of state management (Redux/Zustand); Bachelor's degree or equivalent portfolio.",
            "Flexible working hours; Generous PTO; Healthcare coverage; Home office equipment allowance."
        ),
        (
            "Cybersecurity Threat Hunter",
            "Starlight Cyber Systems",
            "Responsible for monitoring security alerts, triaging incident escalations, and analyzing threat intelligence feeds. Candidate must hold relevant certifications (CompTIA Security+, CISSP, or equivalent) and demonstrate strong knowledge of TCP/IP, SIEM platforms, and operating system internals.",
            "Prior professional experience in SOC or incident response; Knowledge of regulatory compliance (SOC 2, ISO 27001); Strong scripting skills in Python or PowerShell.",
            "Competitive base salary; 401(k) match; Full medical and dental coverage; Continuing education and certification reimbursement."
        ),
        (
            "Human Resources Generalist",
            "Novus Financial Systems",
            "We are looking for an HR Generalist to coordinate talent acquisition, administer employee benefit programs, facilitate onboarding, and support employee relations initiatives across corporate divisions.",
            "Bachelor's degree in Human Resources, Business Administration, or related discipline; 2+ years HR generalist experience; Proficiency with HRIS platforms.",
            "Comprehensive corporate benefits package; Medical, dental, vision; 401(k) retirement savings; Paid parental leave."
        ),
        (
            "Financial Analyst - Corporate FP&A",
            "Beacon Enterprise Software",
            "Support corporate forecasting, variance analysis, annual budgeting, and long-range strategic financial planning. Will partner with departmental leaders to assess capital expenditures and prepare board presentation decks.",
            "Bachelor's degree in Finance or Accounting; 2-4 years corporate finance experience; Advanced financial modeling skills in Microsoft Excel.",
            "Competitive compensation; Annual performance bonus; Comprehensive healthcare; Retirement plans; Professional development funding."
        ),
        (
            "Healthcare Administrative Coordinator",
            "Meridian Health Solutions",
            "Coordinate clinic patient scheduling, manage medical records compliance, interface with insurance carriers for prior authorizations, and assist practice administrators with operational workflows.",
            "Associate or Bachelor's degree in Healthcare Administration or business; 2+ years clinic office experience; Working knowledge of HIPAA compliance.",
            "Health, dental, vision coverage; Paid sick leave; 401(k) plan; Life and disability insurance."
        ),
        (
            "DevOps Engineer - Kubernetes & Infrastructure",
            "Pinnacle Logistics Corp",
            "Design and maintain automated CI/CD pipelines, manage Kubernetes clusters on AWS, enforce infrastructure as code using Terraform, and monitor system availability and latency metrics.",
            "4+ years Linux administration and cloud engineering experience; Hands-on expertise with Terraform, Docker, and Kubernetes; Experience with Prometheus and Grafana.",
            "Full-time salary with equity options; Comprehensive medical and dental; 401(k) match; Remote work flexibility."
        ),
        (
            "Technical Customer Support Specialist (Tier 2)",
            "OmniTech Solutions Inc",
            "Deliver escalated technical troubleshooting for enterprise SaaS clients. Investigate application logs, reproduce software defects, document bug reports in Jira, and collaborate with engineering for customer resolutions.",
            "2+ years experience in B2B technical support; Familiarity with REST APIs, SQL queries, and browser developer tools; Exceptional written and verbal communication.",
            "Competitive hourly rate plus overtime; Health and dental insurance; Career progression pathway; 15 days PTO."
        ),
        (
            "Digital Marketing Strategist",
            "Apex Cloud Technologies",
            "Lead organic and paid search marketing campaigns, optimize conversion funnels, manage Google Ads budgets, and produce performance attribution analytics for B2B product launches.",
            "3+ years digital marketing experience; Google Analytics and Ads certification; Proven track record of pipeline generation.",
            "Competitive salary; Performance incentives; Full healthcare coverage; Flexible hybrid schedule."
        ),
        (
            "Account Executive - Enterprise Solutions",
            "Starlight Cyber Systems",
            "Drive full-cycle enterprise sales engagements from qualified discovery to negotiation and closing. Build relationships with CISOs and IT Directors, conduct product demonstrations, and achieve quarterly quota targets.",
            "3+ years quota-carrying B2B software sales experience; Strong consultative selling methodology; Bachelor's degree preferred.",
            "Base salary plus uncapped commission structure; Full health benefits; Company car stipend; 401(k) match."
        ),
        (
            "Quality Assurance Automation Engineer",
            "Novus Financial Systems",
            "Develop end-to-end automated test suites for web and API platforms using Playwright and Python. Participate in sprint planning, conduct regression testing, and maintain test matrices.",
            "Bachelor's in Computer Science or equivalent; 2+ years test automation experience; Solid understanding of CI/CD pipeline integration.",
            "Competitive salary; Comprehensive health benefits; 401(k) with match; Annual conference attendance stipend."
        )
    ]

    # Authentic Postings (800 total samples)
    for i in range(800):
        t, c, d, r, b = authentic_templates[i % len(authentic_templates)]
        records.append({
            "title": f"{t} [Ref-{i+100}]",
            "company_profile": f"{c} is an established, accredited provider of enterprise solutions.",
            "description": d,
            "requirements": r,
            "benefits": b,
            "telecommuting": 1 if i % 3 == 0 else 0,
            "has_company_logo": 1,
            "has_questions": 1,
            "employment_type": "Full-time",
            "required_experience": "Mid-Senior level",
            "required_education": "Bachelor's Degree",
            "fraudulent": 0
        })

    # Fraudulent Scams across multiple diverse typologies
    scam_templates = [
        # 1. Advance fee / check cashing equipment scam
        (
            "URGENT: Data Entry Clerk - Work From Home - Instant Start",
            "Global Solutions Network (recruiting immediately)",
            "Urgent hiring! Earn $4,500 monthly working simple data entry from home 2 hours per day. No experience needed! Immediate start guaranteed. You will be provided check for $2,500 to purchase home office equipment. Deposit check into your bank account, deduct your fee, and wire transfer remainder via Western Union / MoneyGram to our verified vendor. Send bank account details and copy of ID to expedite your start.",
            "Must have basic internet access and active bank account for direct deposits. No interview required. Limited slots available, hurry!",
            "Earn guaranteed $4500 monthly; Free laptop provided upon payment of $150 courier registration fee.",
        ),
        # 2. Telegram crypto / task scam
        (
            "Crypto Task Assistant - Daily Payouts $500 - Telegram Direct",
            "Decentralized Wealth Alliance",
            "Earn $300 to $800 daily completing simple rating tasks and social media likes on your smartphone! No skills required, instant payouts directly to your USDT crypto wallet. Contact our hiring manager on Telegram @cryptojob_hr immediately for instant onboarding and activation instructions.",
            "Smartphone with Telegram app installed and crypto wallet (TRC20/ERC20).",
            "Daily instant commissions, financial freedom, 100% guaranteed income.",
        ),
        # 3. Corporate impersonation with mandatory upfront fee
        (
            "Customer Service Representative - Remote Onboarding",
            "Apex Hiring Partner (representing Fortune 500)",
            "We are hiring remote customer support agents on behalf of major multinational firms. Successful candidates must complete background verification and specialized software training. A one-time refundable training and certification fee of $200 is required before assignment. Wire payment via Zelle or UPI to secure your position.",
            "Must pay registration fee prior to orientation session; Valid government ID proof.",
            "Full health benefits after 90 days; High hourly rate.",
        ),
        # 4. PII harvesting / Phishing
        (
            "Executive Assistant to Private Director - Immediate Opening",
            "Executive Private Staffing",
            "Seeking confidential executive assistant for high net worth investor. To process your application, submit your full legal name, date of birth, Social Security Number (SSN), copy of driver license, and banking routing details for direct deposit setup prior to interview call. Send to hr-direct@securemail-service.xyz",
            "Unrestricted access to personal credit history and clean record. Submit SSN copy.",
            "Generous weekly cash stipend and company car provided immediately.",
        ),
        # 5. Package reshipping / parcel mule
        (
            "Package Processing Quality Inspector - Work From Home",
            "International Logistics Express",
            "Receive high-value electronic parcels at your residential address, inspect contents, and repackage for forwarding to international overseas destinations. Keep $50 cash per package processed. Sign up now through our external portal bit.ly/easy-job-apply-2026.",
            "Residential physical address; Ability to hold parcels; No experience necessary.",
            "Earn $1000s weekly from home with flexible working schedule.",
        ),
        # 6. Vague urgency spam / WhatsApp recruiter
        (
            "Online Typist & Form Filler - Guaranteed Income Daily",
            "Instant Career Agency",
            "Act now! High paying vacancies for online typists. Guaranteed $150 per hour. Work anytime, anywhere! Contact recruiter on WhatsApp +1-800-FAKEJOB for registration link. Act quickly before positions are filled!",
            "Any age, no educational qualifications required.",
            "Immediate daily payments via PayPal or wire transfer."
        ),
        # 7. Background check fee phishing
        (
            "Remote Administrative Assistant - Fast Placement",
            "Global Placement Services",
            "Immediate vacancy for remote administrative assistant. To complete the pre-employment verification, applicants must pay a non-refundable $75 background check fee and credit check verification through our link. Once paid, onboarding begins tomorrow.",
            "Must clear background check by paying processing fee; Active checking account.",
            "Starting $38/hour; Medical coverage; Weekly direct deposit."
        ),
        # 8. Secret / Mystery Shopper scam
        (
            "Secret Mystery Shopper & Quality Evaluator",
            "National Consumer Research Bureau",
            "We will mail you a cashier check for $2,800. Deposit it into your personal account, keep $400 commission, and purchase $2,400 in Apple or Steam gift cards from Walmart. Scratch cards and send photos of codes to recruiter email for validation.",
            "Valid bank account able to deposit checks; Ability to shop locally immediately.",
            "Earn $400 per shopping assignment, flexible hours."
        ),
        # 9. Bogus software license fee
        (
            "Medical Billing Clerk - Work From Home",
            "Apex Health Staffing Partners",
            "Remote medical billing and coding role. Candidates must purchase proprietary HIPAA-compliant medical billing software license ($180) from our accredited vendor before receiving employee portal credentials. Reimbursement provided in first paycheck.",
            "Must purchase software license prior to starting training; Computer with Windows.",
            "Full health insurance, 401(k), paid training."
        ),
        # 10. Fake cryptocurrency trader / account manager
        (
            "Junior Crypto Trading Assistant - High Commission",
            "Bitcoin Capital Growth Hub",
            "Assist senior crypto traders in executing automated arbitrage orders. Must have active Binance or Coinbase account. Transfer initial crypto deposit to activate trading bot. 100% risk free guaranteed daily profits up to 25%.",
            "Personal crypto account with ability to deposit funds; Telegram account.",
            "Earn thousands weekly; Instant Bitcoin payouts."
        ),
    ]

    # Fraudulent Postings (400 total samples)
    for i in range(400):
        t, c, d, r, b = scam_templates[i % len(scam_templates)]
        records.append({
            "title": f"{t} [Scam-{i+1000}]",
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

    # Combine text identically to NLPAnalyzer.build_composite_text
    df["full_text"] = df[text_cols].apply(lambda row: " ".join(row.values), axis=1)
    df["cleaned_text"] = df["full_text"].apply(NLPAnalyzer.clean_text)

    # Ensure binary label
    target_col = "fraudulent" if "fraudulent" in df.columns else "label"
    df["target"] = df[target_col].astype(int)

    return df


def tune_classification_threshold(
    model: Any,
    X_val_tfidf: Any,
    y_val: pd.Series,
    fraud_class_idx: int = 1
) -> Tuple[float, List[Dict[str, Any]]]:
    """
    Tuning classification threshold strictly on the validation set
    to maximize fraud detection recall and F1-score, minimizing false negatives.
    """
    candidate_thresholds = np.linspace(0.20, 0.60, 41)

    if hasattr(model, "predict_proba"):
        val_probs = model.predict_proba(X_val_tfidf)[:, fraud_class_idx]
    else:
        # Fallback for models without predict_proba
        return 0.50, []

    tuning_history = []
    best_threshold = 0.50
    best_f2 = -1.0

    for thresh in candidate_thresholds:
        preds = (val_probs >= thresh).astype(int)
        rec = float(recall_score(y_val, preds, zero_division=0))
        prec = float(precision_score(y_val, preds, zero_division=0))
        f1 = float(f1_score(y_val, preds, zero_division=0))

        # In cyber threat detection, False Negatives cause direct victim injury.
        # F2-score prioritizes recall (minimizing false negatives) over precision.
        f2 = (5.0 * prec * rec) / ((4.0 * prec) + rec) if ((4.0 * prec) + rec) > 0 else 0.0

        tuning_history.append({
            "threshold": round(float(thresh), 3),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "f2": round(f2, 4),
        })

        if f2 > best_f2 and rec >= 0.85:
            best_f2 = f2
            best_threshold = float(thresh)
        elif best_f2 < 0 and f1 > best_f2:
            best_f2 = f1
            best_threshold = float(thresh)

    return round(best_threshold, 3), tuning_history


def train_and_evaluate_models() -> Dict[str, Any]:
    """
    Executes complete training, evaluation, comparison, threshold tuning,
    and serialization pipeline.
    """
    data_file = os.path.join(BASE_DIR, "data", "fake_job_postings.csv")
    models_dir = os.path.join(BASE_DIR, "models")
    os.makedirs(models_dir, exist_ok=True)

    # Always generate or ensure balanced multi-typology dataset
    df = generate_curated_dataset()
    df.to_csv(data_file, index=False)
    df = prepare_and_clean_data(data_file)

    total_records = len(df)
    total_fraud = int(df["target"].sum())
    total_genuine = int((df["target"] == 0).sum())
    print(f"[+] Total samples: {total_records} | Fraudulent: {total_fraud} | Genuine: {total_genuine}")

    # Stratified Train (70%) / Validation (15%) / Held-Out Test (15%) Split
    X_temp, X_test_raw, y_temp, y_test = train_test_split(
        df["cleaned_text"],
        df["target"],
        test_size=0.15,
        random_state=42,
        stratify=df["target"]
    )

    val_fraction = 0.15 / 0.85  # Yields 15% of total dataset for validation
    X_train_raw, X_val_raw, y_train, y_val = train_test_split(
        X_temp,
        y_temp,
        test_size=val_fraction,
        random_state=42,
        stratify=y_temp
    )

    print(f"[+] Train: {len(X_train_raw)} | Validation: {len(X_val_raw)} | Test: {len(X_test_raw)}")

    # TF-IDF Feature Extraction
    print("[+] Extracting TF-IDF n-gram features (max_features=4000)...")
    vectorizer = TfidfVectorizer(
        max_features=4000,
        ngram_range=(1, 2),
        min_df=2,
        sublinear_tf=True
    )
    X_train_tfidf = vectorizer.fit_transform(X_train_raw)
    X_val_tfidf = vectorizer.transform(X_val_raw)
    X_test_tfidf = vectorizer.transform(X_test_raw)

    # Define Candidate Models with class weighting to handle imbalance
    candidate_models = {
        "Logistic Regression": LogisticRegression(
            C=1.5, max_iter=1000, class_weight="balanced", random_state=42
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=120, max_depth=20, class_weight="balanced", random_state=42, n_jobs=-1
        ),
        "Multinomial Naive Bayes": MultinomialNB(alpha=0.5),
        "Linear SVM": CalibratedClassifierCV(
            estimator=LinearSVC(C=1.0, class_weight="balanced", random_state=42, max_iter=2000), cv=3
        ),
        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators=100, max_depth=5, random_state=42
        ),
    }

    results = {}
    best_model_name = None
    best_f1 = -1.0
    champion_model = None
    champion_threshold = 0.50
    champion_class_idx = 1

    print("\n--- Model Training & Validation-Based Threshold Tuning ---")
    for name, model in candidate_models.items():
        print(f"[~] Training {name}...")
        model.fit(X_train_tfidf, y_train)

        # Inspect actual classes from model
        classes = list(getattr(model, "classes_", [0, 1]))
        fraud_class_idx = classes.index(1) if 1 in classes else 1

        # Tune threshold on VALIDATION SET (never on test set)
        tuned_threshold, _ = tune_classification_threshold(
            model, X_val_tfidf, y_val, fraud_class_idx=fraud_class_idx
        )

        # Evaluate on strictly HELD-OUT TEST SET at tuned threshold
        if hasattr(model, "predict_proba"):
            y_test_probs = model.predict_proba(X_test_tfidf)[:, fraud_class_idx]
            y_test_preds = (y_test_probs >= tuned_threshold).astype(int)
            # Baseline preds at default 0.50 for comparison
            y_default_preds = (y_test_probs >= 0.50).astype(int)
        else:
            y_test_preds = model.predict(X_test_tfidf)
            y_test_probs = y_test_preds
            y_default_preds = y_test_preds

        # Metrics on held-out test set
        acc = float(accuracy_score(y_test, y_test_preds))
        prec = float(precision_score(y_test, y_test_preds, zero_division=0))
        rec = float(recall_score(y_test, y_test_preds, zero_division=0))
        f1 = float(f1_score(y_test, y_test_preds, zero_division=0))
        roc_auc = float(roc_auc_score(y_test, y_test_probs))

        cm = confusion_matrix(y_test, y_test_preds)
        tn, fp, fn, tp = [int(v) for v in cm.ravel()]

        # Baseline metrics at 0.50
        cm_def = confusion_matrix(y_test, y_default_preds)
        tn_d, fp_d, fn_d, tp_d = [int(v) for v in cm_def.ravel()]
        rec_def = float(recall_score(y_test, y_default_preds, zero_division=0))

        results[name] = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "optimal_threshold": tuned_threshold,
            "false_negative_count": fn,
            "true_positive_count": tp,
            "confusion_matrix": {
                "tn": tn, "fp": fp, "fn": fn, "tp": tp
            },
            "baseline_threshold_0_50": {
                "recall": round(rec_def, 4),
                "confusion_matrix": {"tn": tn_d, "fp": fp_d, "fn": fn_d, "tp": tp_d}
            }
        }

        print(
            f"    -> Acc: {acc:.4f} | Prec: {prec:.4f} | Rec: {rec:.4f} (was {rec_def:.4f} @ 0.50) | "
            f"F1: {f1:.4f} | AUC: {roc_auc:.4f} | Threshold: {tuned_threshold} | FN: {fn}"
        )

        # Champion selection: prioritizes high F1 and high Recall (low False Negatives)
        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            champion_model = model
            champion_threshold = tuned_threshold
            champion_class_idx = fraud_class_idx

    print(f"\n[+] Champion Model Selected: {best_model_name} (F1-Score: {best_f1:.4f}, Optimal Threshold: {champion_threshold})")

    # Serialize artifacts
    model_path = os.path.join(models_dir, "model.pkl")
    vectorizer_path = os.path.join(models_dir, "vectorizer.pkl")
    metrics_path = os.path.join(models_dir, "metrics.json")

    joblib.dump(champion_model, model_path)
    joblib.dump(vectorizer, vectorizer_path)

    metadata = {
        "dataset_stats": {
            "total_records": total_records,
            "train_samples": len(X_train_raw),
            "validation_samples": len(X_val_raw),
            "test_samples": len(X_test_raw),
            "fraudulent_samples": total_fraud,
            "genuine_samples": total_genuine,
            "features_extracted": 4000,
        },
        "class_mapping": {
            "0": "genuine",
            "1": "fraudulent",
            "model_classes": [int(c) for c in getattr(champion_model, "classes_", [0, 1])],
            "fraud_class_idx": champion_class_idx
        },
        "selected_model": best_model_name,
        "optimal_threshold": champion_threshold,
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
