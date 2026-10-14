"""
Dashboard Page:
Visualizes real-time analytics, risk metrics, scam classification breakdowns,
and recent threat inspections from the JSON database.
"""

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from database.json_db import get_db
from utils.helpers import format_timestamp, render_risk_badge_html
from utils.styles import render_cyber_header


def render_dashboard():
    """Renders comprehensive cybersecurity dashboard with dynamic metrics and Plotly charts."""
    render_cyber_header(
        title="Cybersecurity Threat Analytics Dashboard",
        subtitle="Live telemetry and aggregate metrics across analyzed job postings and recruitment campaigns.",
        badge="SOC METRICS ACTIVE"
    )

    db = get_db()
    analyses = db.find("analyses", sort_key="created_at", reverse=True)

    # Empty State
    if not analyses:
        st.info("ℹ️ No job postings have been analyzed yet. Start by analyzing a job posting to populate this dashboard.")
        col1, col2 = st.columns([1, 3])
        with col1:
            if st.button("🚀 Analyze Your First Job", type="primary"):
                st.session_state["current_page"] = "Detect Job"
                st.rerun()
        return

    # Aggregate Metrics Calculation
    total_analyzed = len(analyses)
    fake_count = sum(1 for a in analyses if str(a.get("prediction")).upper() == "FAKE")
    suspicious_count = sum(1 for a in analyses if str(a.get("prediction")).upper() == "SUSPICIOUS")
    genuine_count = sum(1 for a in analyses if str(a.get("prediction")).upper() == "GENUINE")

    critical_and_high = sum(
        1 for a in analyses if a.get("risk_level") in ("CRITICAL", "HIGH")
    )

    risk_scores = [float(a.get("risk_score", 0)) for a in analyses]
    avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0

    # Metric Cards Row
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-label">Total Analyzed</div>
            <div class="stat-value" style="color: #00F0FF;">{total_analyzed}</div>
            <div class="stat-subtext">Cumulative submissions</div>
        </div>
        """, unsafe_allow_html=True)

    with m2:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-label">Scams Flagged</div>
            <div class="stat-value" style="color: #EF4444;">{fake_count}</div>
            <div class="stat-subtext">Confirmed fraudulent</div>
        </div>
        """, unsafe_allow_html=True)

    with m3:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-label">Suspicious</div>
            <div class="stat-value" style="color: #F59E0B;">{suspicious_count}</div>
            <div class="stat-subtext">Elevated anomalies</div>
        </div>
        """, unsafe_allow_html=True)

    with m4:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-label">Genuine Postings</div>
            <div class="stat-value" style="color: #10B981;">{genuine_count}</div>
            <div class="stat-subtext">Authentic verified</div>
        </div>
        """, unsafe_allow_html=True)

    with m5:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-label">Avg Threat Score</div>
            <div class="stat-value" style="color: #A78BFA;">{avg_risk_score:.1f}<span style="font-size: 16px;">/100</span></div>
            <div class="stat-subtext">{critical_and_high} High/Critical alerts</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Visualizations Row 1
    c1, c2 = st.columns(2)

    with c1:
        # Donut Chart: Verdict Breakdown
        verdict_counts = {
            "Fake / Scam": fake_count,
            "Suspicious": suspicious_count,
            "Genuine": genuine_count,
        }
        fig_donut = px.pie(
            values=list(verdict_counts.values()),
            names=list(verdict_counts.keys()),
            hole=0.55,
            color=list(verdict_counts.keys()),
            color_discrete_map={
                "Fake / Scam": "#EF4444",
                "Suspicious": "#F59E0B",
                "Genuine": "#10B981",
            },
            title="Classification Distribution"
        )
        fig_donut.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(17, 24, 39, 0.9)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(t=40, b=20, l=20, r=20),
            legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    with c2:
        # Bar Chart: Risk Levels
        level_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for a in analyses:
            lvl = str(a.get("risk_level", "LOW")).upper()
            if lvl in level_counts:
                level_counts[lvl] += 1
            else:
                level_counts["LOW"] += 1

        fig_bar = px.bar(
            x=list(level_counts.keys()),
            y=list(level_counts.values()),
            labels={"x": "Risk Severity Level", "y": "Number of Postings"},
            title="Risk Severity Hierarchy",
            color=list(level_counts.keys()),
            color_discrete_map={
                "LOW": "#10B981",
                "MEDIUM": "#F59E0B",
                "HIGH": "#F87171",
                "CRITICAL": "#EF4444",
            }
        )
        fig_bar.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(17, 24, 39, 0.9)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(t=40, b=20, l=20, r=20),
            showlegend=False,
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    # Visualizations Row 2: Scam Categories Breakdown
    all_categories = []
    for a in analyses:
        for cat in a.get("scam_categories", []):
            all_categories.append(cat)

    if all_categories:
        cat_counts = pd.Series(all_categories).value_counts().reset_index()
        cat_counts.columns = ["Scam Category", "Count"]

        fig_cats = px.bar(
            cat_counts,
            x="Count",
            y="Scam Category",
            orientation="h",
            title="Prevalent Scam Typologies Detected",
            color="Count",
            color_continuous_scale="Reds",
        )
        fig_cats.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(17, 24, 39, 0.9)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(t=40, b=20, l=20, r=20),
            yaxis=dict(autorange="reversed"),
        )
        st.plotly_chart(fig_cats, use_container_width=True)

    # Recent Analyses Table
    st.markdown("### 📋 Recent Job Threat Inspections")

    recent_data = []
    for a in analyses[:8]:
        job_data = a.get("job_data", {})
        recent_data.append({
            "Date/Time": format_timestamp(a.get("created_at")),
            "Job Title": job_data.get("title", "Unknown")[:30],
            "Company": job_data.get("company", "Unknown")[:25],
            "Prediction": a.get("prediction", "N/A"),
            "Risk Score": f"{a.get('risk_score', 0):.0f}/100",
            "Risk Level": a.get("risk_level", "N/A"),
            "Top Scam Type": (a.get("scam_categories", []) or ["None"])[0],
        })

    if recent_data:
        df_recent = pd.DataFrame(recent_data)
        st.dataframe(df_recent, use_container_width=True, hide_index=True)
