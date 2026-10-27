"""
Analysis History Page:
Allows users to review, filter, search, view in-depth details, and delete
past job posting security evaluations (CRUD operations).
"""

import pandas as pd
import streamlit as st

from database.json_db import get_db
from utils.helpers import format_timestamp, render_risk_badge_html
from utils.styles import render_cyber_header


def render_history():
    """Renders the analysis audit history table and inspection records."""
    render_cyber_header(
        title="Job Threat Analysis History",
        subtitle="Historical audit log of all analyzed vacancies, threat scores, and flagged indicators.",
        badge="AUDIT LOGS"
    )

    db = get_db()
    current_user = st.session_state.get("user") or {}
    user_id = current_user.get("id")

    # Fetch all records or filtered by user if normal analyst
    is_admin = current_user.get("role") == "admin"
    if is_admin:
        records = db.find("analyses", sort_key="created_at", reverse=True)
    else:
        # Show all or current user's records
        records = db.find("analyses", sort_key="created_at", reverse=True)

    if not records:
        st.info("ℹ️ No analysis history found. Run a job analysis on the 'Detect Job' page to populate history.")
        if st.button("🔍 Go to Detect Job", type="primary"):
            st.session_state["current_page"] = "Detect Job"
            st.rerun()
        return

    # Filter & Search Bar
    s_col1, s_col2, s_col3 = st.columns([2, 1, 1])
    with s_col1:
        search_query = st.text_input("🔍 Search by Title or Company", placeholder="Filter keywords...", key="hist_search")
    with s_col2:
        filter_level = st.selectbox("Risk Level", ["All Levels", "CRITICAL", "HIGH", "MEDIUM", "LOW"], key="hist_lvl")
    with s_col3:
        filter_pred = st.selectbox(
            "Outcome",
            ["All Outcomes", "Likely Genuine", "Suspicious — Further Verification Required", "Insufficient Evidence"],
            key="hist_pred"
        )

    # Apply Filters
    filtered_records = []
    for r in records:
        job_data = r.get("job_data", {})
        title = str(job_data.get("title", "")).lower()
        company = str(job_data.get("company", "")).lower()
        pred = str(r.get("prediction", "")).strip()
        lvl = str(r.get("risk_level", "")).upper()

        # Text match
        if search_query:
            q = search_query.lower()
            if q not in title and q not in company:
                continue

        # Level match
        if filter_level != "All Levels" and lvl != filter_level:
            continue

        # Outcome match (with backward compatibility)
        if filter_pred != "All Outcomes":
            p_norm = pred.upper()
            f_norm = filter_pred.upper()
            if f_norm == "LIKELY GENUINE" and p_norm not in ("LIKELY GENUINE", "GENUINE"):
                continue
            elif "SUSPICIOUS" in f_norm and "SUSPICIOUS" not in p_norm and p_norm != "FAKE":
                continue
            elif f_norm == "INSUFFICIENT EVIDENCE" and p_norm not in ("INSUFFICIENT EVIDENCE", "UNKNOWN"):
                continue

        filtered_records.append(r)

    st.markdown(f"**Showing {len(filtered_records)} of {len(records)} audit records**")

    if not filtered_records:
        st.warning("No records match your selected filter criteria.")
        return

    # Display Records
    for record in filtered_records:
        r_id = record.get("id")
        job = record.get("job_data", {})
        title = job.get("title", "Untitled")
        company = job.get("company", "Unspecified Company")
        pred = record.get("prediction", "UNKNOWN")
        score = float(record.get("risk_score", 0))
        level = record.get("risk_level", "LOW")
        created = format_timestamp(record.get("created_at"))
        scam_cats = record.get("scam_categories", [])

        icon = "🚨" if ("Suspicious" in pred or pred == "FAKE") else "ℹ️" if pred == "Insufficient Evidence" else "✅"
        with st.expander(f"{icon} {title} — {company} ({score:.0f}/100 {level} RISK) - {created}"):
            col_a, col_b = st.columns([3, 1])

            with col_a:
                st.markdown(render_risk_badge_html(level, score), unsafe_allow_html=True)
                st.write(f"**Prediction:** `{pred}` | **Confidence:** `{record.get('confidence', 0)}%`")
                st.write(f"**Location:** {job.get('location', 'N/A')} | **Salary:** {job.get('salary', 'N/A')}")
                if scam_cats:
                    st.write(f"**Identified Scam Types:** {', '.join(scam_cats)}")

                # Red flags
                flags = record.get("red_flags", [])
                if flags:
                    st.markdown("**Key Red Flags:**")
                    for f in flags[:3]:
                        st.markdown(f"- ⚠️ {f}")

            with col_b:
                st.write(f"**Audit ID:** `{r_id[:8]}`")
                # Delete Action
                if st.button("🗑️ Delete Record", key=f"del_{r_id}", use_container_width=True):
                    db.delete("analyses", r_id)
                    st.success("Record deleted successfully.")
                    st.rerun()

                # View in Detect Job
                if st.button("🔬 Re-Examine", key=f"view_{r_id}", use_container_width=True):
                    st.session_state["latest_analysis"] = record
                    st.session_state["current_page"] = "Detect Job"
                    st.rerun()

    # Bulk Clear Action
    st.markdown("---")
    with st.expander("⚠️ Danger Zone: Bulk Clear"):
        st.write("Permanently delete matching audit records from the local database.")
        if st.button("🚨 Clear All Filtered Audit Records", type="secondary"):
            deleted_count = 0
            for fr in filtered_records:
                if db.delete("analyses", fr.get("id")):
                    deleted_count += 1
            st.success(f"Successfully deleted {deleted_count} records.")
            st.rerun()
