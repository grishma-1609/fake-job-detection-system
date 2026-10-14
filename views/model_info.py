"""
Model Information Page:
Presents academic AI research methodology, model comparison metrics,
confusion matrix analysis, and system limitations.
"""

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from models.predictor import get_predictor
from utils.styles import render_cyber_header


def render_model_info():
    """Renders academic machine learning documentation and real evaluation metrics."""
    render_cyber_header(
        title="Machine Learning Architecture & Evaluation Metrics",
        subtitle="Empirical performance evaluation across multiple classification algorithms on the EMSCAD benchmark.",
        badge="ACADEMIC RESEARCH"
    )

    predictor = get_predictor()
    metrics_data = predictor.get_metrics_data()

    if not metrics_data:
        st.warning("⚠️ Model metrics have not been generated yet. Please run `python models/train_model.py` to train and evaluate models.")
        return

    # Dataset Statistics Overview
    stats = metrics_data.get("dataset_stats", {})
    selected_model = metrics_data.get("selected_model", "Logistic Regression")

    st.markdown("### 📊 Dataset & Pipeline Overview")
    d1, d2, d3, d4, d5 = st.columns(5)
    d1.metric("Total Samples", f"{stats.get('total_records', 0):,}")
    d2.metric("Training Samples", f"{stats.get('train_samples', 0):,}")
    d3.metric("Test Samples (20%)", f"{stats.get('test_samples', 0):,}")
    d4.metric("Extracted Features", f"{stats.get('features_extracted', 0):,}")
    d5.metric("Champion Model", selected_model)

    st.markdown("<br>", unsafe_allow_html=True)

    # Multi-Model Comparative Evaluation Table
    st.markdown("### 🏆 Multi-Model Comparative Evaluation")
    st.caption("Models evaluated on the unseen test partition using stratified holdout validation.")

    models_eval = metrics_data.get("models_evaluated", {})
    comparison_rows = []

    for name, m in models_eval.items():
        is_champ = name == selected_model
        comparison_rows.append({
            "Algorithm": f"{'⭐ ' if is_champ else ''}{name}",
            "Accuracy": f"{m.get('accuracy', 0)*100:.2f}%",
            "Precision": f"{m.get('precision', 0)*100:.2f}%",
            "Recall": f"{m.get('recall', 0)*100:.2f}%",
            "F1-Score": f"{m.get('f1_score', 0):.4f}",
            "ROC-AUC": f"{m.get('roc_auc', 0):.4f}",
            "Selected": "Yes (Champion)" if is_champ else "No",
        })

    df_comp = pd.DataFrame(comparison_rows)
    st.dataframe(df_comp, use_container_width=True, hide_index=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Comparative Visualizations
    col_chart, col_cm = st.columns(2)

    with col_chart:
        st.markdown("### 📈 F1-Score & Recall Comparison")
        # Extract for bar chart
        model_names = list(models_eval.keys())
        f1_scores = [models_eval[m]["f1_score"] for m in model_names]
        recalls = [models_eval[m]["recall"] for m in model_names]

        fig_compare = go.Figure(data=[
            go.Bar(name="F1-Score", x=model_names, y=f1_scores, marker_color="#00F0FF"),
            go.Bar(name="Recall", x=model_names, y=recalls, marker_color="#3B82F6"),
        ])
        fig_compare.update_layout(
            barmode="group",
            template="plotly_dark",
            paper_bgcolor="rgba(17, 24, 39, 0.9)",
            plot_bgcolor="rgba(0,0,0,0)",
            yaxis=dict(range=[0.8, 1.02]),
            margin=dict(t=30, b=20, l=20, r=20),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        )
        st.plotly_chart(fig_compare, use_container_width=True)

    with col_cm:
        st.markdown(f"### 🎯 Confusion Matrix ({selected_model})")
        # Extract CM for selected model
        champ_cm = models_eval.get(selected_model, {}).get("confusion_matrix", {})
        tn = champ_cm.get("tn", 0)
        fp = champ_cm.get("fp", 0)
        fn = champ_cm.get("fn", 0)
        tp = champ_cm.get("tp", 0)

        z_data = [[tn, fp], [fn, tp]]
        x_labels = ["Predicted Genuine", "Predicted Fraudulent"]
        y_labels = ["Actual Genuine", "Actual Fraudulent"]

        fig_cm = px.imshow(
            z_data,
            x=x_labels,
            y=y_labels,
            color_continuous_scale="Viridis",
            text_auto=True,
            title=f"Test Partition Confusion Matrix (N={tn+fp+fn+tp})"
        )
        fig_cm.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(17, 24, 39, 0.9)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(t=40, b=20, l=20, r=20),
        )
        st.plotly_chart(fig_cm, use_container_width=True)

    # Methodology and Limitations Tabs
    st.markdown("### 🔬 Technical Methodology & Limitations")
    m_tab1, m_tab2, m_tab3 = st.tabs([
        "⚙️ NLP Feature Engineering",
        "⚖️ Model Selection Rationale",
        "⚠️ Ethical & System Limitations",
    ])

    with m_tab1:
        st.markdown("""
        - **Preprocessing:** All textual fields (`title`, `company_profile`, `description`, `requirements`, `benefits`) are normalized by stripping HTML markup, URLs, email addresses, and punctuation.
        - **Tokenization & Stopwords:** Custom English stopword elimination with length thresholding.
        - **Vectorization:** TF-IDF n-grams (unigrams and bigrams) with sublinear term-frequency scaling (`sublinear_tf=True`) across a 4,000-dimensional vocabulary.
        - **Metadata Integration:** Linguistic stylistic indicators such as capitalization ratio, exclamation count, and lexical phrase triggers are merged into the hybrid risk scoring engine.
        """)

    with m_tab2:
        st.markdown(f"""
        - **Champion Algorithm:** `{selected_model}` was chosen as the champion model.
        - **Optimization Objective:** In cybersecurity threat detection, minimizing **False Negatives (FN)** is paramount: failing to detect a scam causes severe financial and identity injury to job seekers.
        - **Calibrated Probability:** Linear models and calibrated estimators produce well-behaved posterior probabilities that seamlessly map into the 0–100 risk scoring framework.
        """)

    with m_tab3:
        st.markdown("""
        - **Dataset Drift:** Attackers continuously evolve phishing terminology and adopt AI-generated job postings to bypass static keyword filters.
        - **Decision-Support Nature:** The system is an automated advisory tool designed to assist human analysts; it should never serve as legal adjudication or absolute proof of corporate fraud.
        - **Privacy First:** The system avoids aggressive scraping or intrusive penetration testing, adhering to safe, non-invasive HTTP verification standards.
        """)
