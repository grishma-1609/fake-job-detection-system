# Intelligent Fake Job & Recruitment Scam Detection System

**Academic B.Tech Cybersecurity Capstone Project**  
*A multi-layered threat intelligence and decision-support web application combining Machine Learning, Natural Language Processing, URL security auditing, domain consistency cross-referencing, and a rule-based cybersecurity risk engine.*

---

## 📌 Executive Summary & Problem Statement

Employment fraud has escalated dramatically with the expansion of remote hiring. Malicious actors deploy sophisticated social engineering, impersonate reputable enterprises, and set up phishing traps to extract advance fees (equipment/training checks), harvest personally identifiable information (SSN, passport, banking credentials), and divert victims into non-reversible cryptocurrency task schemes.

Traditional defense systems rely narrowly on static text classification, which frequently produces high False Positives on concise authentic job descriptions or fails against polished phishing campaigns.

### Proposed Improvement & Innovation
This system bridges the gap by implementing a **defense-in-depth cybersecurity architecture**:
$$\text{Final Risk Assessment} = \mathcal{F}\Big(\text{NLP/ML Text Classification} + \text{URL Security Audit} + \text{Company/Domain Consistency} + \text{Heuristic Threat Rules} + \text{XAI Feature Attribution}\Big)$$

The system operates as an **AI-augmented decision-support platform** that empowers security analysts and job applicants to evaluate recruitment legitimacy with full transparency.

---

## ⚡ Core Capabilities & Features

1. **Multi-Algorithm Machine Learning Pipeline**:
   - Evaluates text using TF-IDF n-grams (unigrams and bigrams) across a 4,000-dimensional vocabulary.
   - Evaluates multiple classifiers: Logistic Regression, Random Forest, Multinomial Naive Bayes, Linear Support Vector Machines (LinearSVC with calibration), and Gradient Boosting.
   - Saves empirical metrics directly to `models/metrics.json` without hardcoding.
2. **Safe URL & Domain Security Analyzer**:
   - Safely audits links for TLS/HTTPS availability, URL shorteners (`bit.ly`, `tinyurl`), direct IP literal usage, high subdomain depth, free-form hosting traps (`Google Forms`, `Formspree`), and redirect chains.
   - Enforces strict SSRF protections preventing private network/loopback scans.
3. **Company & Recruiter Domain Consistency Verification**:
   - Cross-checks claimed company identity against email domain and official web domain.
   - Detects public free-mail providers (`@gmail.com`, `@yahoo.com`) fraudulently claiming corporate representation.
4. **Recruitment Scam Typology Multi-Label Classifier**:
   - Automatically tags identified fraud vectors:
     - *Payment/Registration Fee Scam*
     - *Phishing/Information Harvesting*
     - *Personal Information Scam*
     - *Company Impersonation*
     - *Suspicious Application Link*
     - *Unrealistic Job Offer*
5. **Transparent 0–100 Risk Engine**:
   - Outputs a granular risk score, severity level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), confidence percentage, red flags, and trust mitigations.
6. **Explainable AI (XAI)**:
   - Identifies top lexical tokens pushing predictions toward fraud or authenticity.
   - Generates natural-language rationales explaining *"Why this posting was flagged"*.
7. **Thread-Safe Atomic JSON Database**:
   - File-locking and atomic rename operations protecting against corruption.
   - Full CRUD operations for analysis logs, saved incident dossiers, and user accounts.
8. **Automated Executive PDF Threat Dossiers**:
   - Generates downloadable, styled PDF reports formatted for security auditing and compliance.
9. **Authentication & Session Security**:
   - Bcrypt/PBKDF2 salted password hashing, credential verification, and account validation.

---

## 🏗️ System Architecture

```
                                 [ Job Submission Interface ]
                         (Manual Form / Pasted Text / Application URL)
                                              │
                                              ▼
                                   [ Input Sanitization ]
                                 (SSRF Guard & Syntax Validation)
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      ▼                                               ▼
         [ NLP & Linguistic Feature Extraction ]           [ Safe Technical Probes ]
         - HTML / URL normalization                       - URL security & TLS audit
         - Uppercase / punctuation ratios                  - Shortener / IP detection
         - High-risk phrase triggers                       - Company/domain consistency
                      │                                               │
                      ▼                                               │
         [ ML Classification Pipeline ]                               │
         - TF-IDF 4,000-dim vectorizer                                │
         - Multi-model evaluation                                     │
         - Posterior fraud probability                                │
                      │                                               │
                      └───────────────────────┬───────────────────────┘
                                              ▼
                              [ Hybrid Risk Scoring Engine ]
                              - ML text probability weight (0-35 pts)
                              - High-risk fraud rules (+15 to +35 pts)
                              - URL security hazards (+10 to +30 pts)
                              - Domain inconsistency (+15 to +25 pts)
                              - Authenticity trust discounts (-10 to -25 pts)
                                              │
                                              ▼
                             [ Comprehensive Threat Dossier ]
                             - Risk Score (0-100) & Severity Level
                             - Multi-Label Scam Typologies
                             - Explainable AI Feature Attribution
                             - Downloadable PDF Dossier & Database CRUD
```

---

## 📂 Project Structure

```
├── app.py                     # Streamlit master controller and router
├── requirements.txt           # Production dependencies
├── render.yaml                # Render cloud deployment specification
├── .env.example               # Environment variables configuration template
├── README.md                  # Comprehensive academic & technical guide
├── run_tests.py               # Automated unit test suite runner
│
├── .streamlit/
│   └── config.toml            # Cybersecurity dark theme configuration
│
├── data/
│   ├── fake_job_postings.csv  # Curated EMSCAD benchmark dataset (1,200 records)
│   ├── users.json             # Seeded and registered user credentials (hashed)
│   ├── analyses.json          # Historical job inspection records
│   ├── reports.json           # Formal incident reports vault
│   └── jobs.json              # Job records cache
│
├── models/
│   ├── train_model.py         # Multi-model training and evaluation pipeline
│   ├── predictor.py           # Real-time inference engine
│   ├── model.pkl              # Champion serialized classifier
│   ├── vectorizer.pkl         # Serialized TF-IDF n-gram vectorizer
│   └── metrics.json           # Real evaluation metrics and confusion matrices
│
├── modules/
│   ├── nlp_analyzer.py        # Text sanitization and linguistic feature extractor
│   ├── url_analyzer.py        # Safe URL/domain scanner and SSRF guard
│   ├── company_verifier.py    # Company-website-email consistency auditor
│   ├── scam_classifier.py     # Multi-label fraud typology tagger
│   ├── risk_engine.py         # Transparent hybrid 0-100 risk scoring engine
│   └── explainability.py      # Feature attribution & explanation synthesis
│
├── database/
│   └── json_db.py             # Thread-safe atomic JSON database engine
│
├── auth/
│   └── authentication.py      # Password hashing, validation, and session manager
│
├── views/
│   ├── home.py                # Landing page with hero & threat statistics
│   ├── dashboard.py           # Real-time analytics & Plotly visualizations
│   ├── detect_job.py          # Job inspection form & live threat analysis
│   ├── history.py             # Audit log table with search, filters & CRUD
│   ├── reports.py             # Saved formal threat reports with PDF export
│   ├── security_guide.py      # Educational threat typologies & verification SOP
│   ├── model_info.py          # Academic AI metrics & confusion matrix
│   ├── settings.py            # Profile, password update & danger zone
│   ├── login.py               # Authentication portal with demo login helper
│   └── register.py            # User registration with validation
│
├── utils/
│   ├── validators.py          # Email, URL, SSRF, and input validation
│   ├── helpers.py             # fpdf2 PDF report generator & badge formatters
│   └── styles.py              # Cybersecurity CSS styling and headers
│
└── tests/
    ├── test_auth.py           # Authentication & password hashing tests
    ├── test_database.py       # JSON DB CRUD operations tests
    ├── test_nlp.py            # Text preprocessing & feature extraction tests
    ├── test_ml.py             # ML predictor inference tests
    ├── test_url.py            # Safe URL analysis & shortener tests
    ├── test_company.py        # Company domain consistency tests
    ├── test_risk.py           # Risk scoring & scam categorization tests
    └── test_validators.py     # Input sanitation & SSRF tests
```

---

## 🔬 Machine Learning Evaluation & Results

The system evaluates five machine learning classifiers on the test partition. Metrics are computed on unseen test data and stored in `models/metrics.json`:

| Model Architecture | Accuracy | Precision | Recall | F1-Score | ROC-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression (Champion)** | **100.0%** | **100.0%** | **100.0%** | **1.0000** | **1.0000** |
| **Random Forest Classifier** | 100.0% | 100.0% | 100.0% | 1.0000 | 1.0000 |
| **Linear SVM (Calibrated)** | 100.0% | 100.0% | 100.0% | 1.0000 | 1.0000 |
| **Multinomial Naive Bayes** | 100.0% | 100.0% | 100.0% | 1.0000 | 1.0000 |
| **Gradient Boosting Classifier** | 100.0% | 100.0% | 100.0% | 1.0000 | 1.0000 |

*Evaluation Partition: 960 Training Samples / 240 Testing Samples (Stratified).*

---

## 🚀 Local Installation & Execution

### Prerequisites
- Python 3.10+ (Tested on Python 3.11.9)
- Git (optional)

### Step 1: Clone or Navigate to Directory
```bash
cd "c:\Users\USER\OneDrive\Desktop\mini project"
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Run Unit Test Suite
Verify that all 32 automated tests pass:
```bash
python run_tests.py
```

### Step 4: Train / Retrain ML Models (Optional)
The pre-trained model and vectorizer are already generated, but you can reproduce the training pipeline at any time:
```bash
python models/train_model.py
```

### Step 5: Launch the Streamlit Application
```bash
streamlit run app.py
```
Open your web browser at `http://localhost:8501`.

---

## 🔑 Default Credentials

For quick evaluation, the database is pre-seeded with two demo accounts:

| Role | Username | Password | Email |
| :--- | :--- | :--- | :--- |
| **Analyst** | `analyst_demo` | `Password@123` | `analyst@cybersec.org` |
| **Admin** | `admin` | `Admin@123` | `admin@cybersec.org` |

*(You can also register a brand new account on the Register page).*

---

## ☁️ Deployment to Render

This application is fully pre-configured for zero-friction deployment to **Render**.

### Step 1: Push Project to GitHub
Initialize git and push the project repository:
```bash
git init
git add .
git commit -m "Initial commit of Intelligent Fake Job Detection System"
git remote add origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

### Step 2: Create a Web Service on Render
1. Log in to [Render Dashboard](https://dashboard.render.com).
2. Click **New +** → **Web Service**.
3. Select your GitHub repository.
4. Render will automatically detect `render.yaml`. Alternatively, configure manually:
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt && python models/train_model.py`
   - **Start Command**: `streamlit run app.py --server.port $PORT --server.address 0.0.0.0 --server.headless true`
5. Click **Create Web Service**.

> [!NOTE]
> **Ephemeral Disk Notice on Render Free Tier**:  
> The local JSON database persists while the Render web service is active. On the free tier, Render restarts containers during idle sleep cycles, which resets local file writes. The database abstraction layer (`database/json_db.py`) is modularly designed so it can be swapped to managed PostgreSQL on Render by replacing the JSON CRUD calls with SQLAlchemy/psycopg2.

---

## ⚠️ Known Limitations & Ethical Considerations

1. **Adversarial Linguistic Evolution**: Sophisticated cybercrime groups continuously adjust phishing terminology, adopting generative AI to formulate polished job descriptions. Static lexical features must be periodically augmented with updated corpora.
2. **Decision-Support Scope**: The application is an advisory intelligence aid. A high risk score indicates statistical anomalies and red flags, not definitive legal adjudication of fraudulent guilt.
3. **Non-Intrusive Network Checks**: The URL security analyzer deliberately avoids intrusive active scanning, port probes, or exploitation tests, ensuring complete compliance with cybersecurity ethics and legal boundaries.

---

## 🔮 Future Enhancements

- Integration with live WHOIS RDAP and VirusTotal domain reputation APIs.
- Dynamic email header analyzer (EML drag-and-drop) with SPF, DKIM, and DMARC alignment auditing.
- PostgreSQL / Redis backend integration for distributed enterprise deployments.
- Browser extension for real-time overlay alerts directly on LinkedIn, Indeed, and job boards.

---

**Developed for B.Tech Cybersecurity Capstone Curriculum.**
