"""
Saved Reports Page:
Repository of formal security assessment reports saved by analysts.
Provides full executive dossiers, deletion, and PDF export downloads.
"""

import json
import streamlit as st

from database.json_db import get_db
from utils.helpers import format_timestamp, generate_pdf_report, render_risk_badge_html
from utils.styles import render_cyber_header


def render_reports():
    """Renders the Saved Formal Reports catalog."""
    render_cyber_header(
        title="Saved Threat Assessment Reports",
        subtitle="Formal cybersecurity dossiers and incident documentation archived for audit and legal compliance.",
        badge="REPORTS VAULT"
    )

    db = get_db()
    reports = db.find("reports", sort_key="created_at", reverse=True)

    if not reports:
        st.info("ℹ️ No formal reports have been archived yet. You can save an incident report directly from the 'Detect Job' assessment page.")
        if st.button("🔍 Go to Detect Job", type="primary"):
            st.session_state["current_page"] = "Detect Job"
            st.rerun()
        return

    st.markdown(f"**Total Archived Reports: `{len(reports)}`**")

    for rep in reports:
        rep_id = rep.get("id")
        title = rep.get("title", "Untitled Job")
        company = rep.get("company", "Unspecified Company")
        pred = rep.get("prediction", "UNKNOWN")
        score = float(rep.get("risk_score", 0))
        level = rep.get("risk_level", "LOW")
        created = format_timestamp(rep.get("created_at"))
        full_analysis = rep.get("full_analysis", {})

        with st.expander(f"📄 [{rep_id[:8].upper()}] {title} — {company} ({level} RISK &bull; {score:.0f}/100) — {created}"):
            col_info, col_actions = st.columns([2.5, 1])

            with col_info:
                st.markdown(render_risk_badge_html(level, score), unsafe_allow_html=True)
                st.markdown(f"#### {title}")
                st.write(f"**Target Company:** {company}")
                st.write(f"**Threat Classification:** `{pred}`")

                # High level indicators
                red_flags = full_analysis.get("red_flags", [])
                if red_flags:
                    st.markdown("**Flagged Indicators:**")
                    for rf in red_flags[:4]:
                        st.markdown(f"<div class='flag-item'>⚠️ {rf}</div>", unsafe_allow_html=True)

                # Explanation snippet
                exp_summary = full_analysis.get("explanation", {}).get("summary")
                if exp_summary:
                    st.info(f"**Executive Summary:** {exp_summary}")

            with col_actions:
                st.markdown("##### Actions")

                # PDF Download
                pdf_bytes = generate_pdf_report(full_analysis)
                if pdf_bytes:
                    st.download_button(
                        label="📄 Download PDF",
                        data=pdf_bytes,
                        file_name=f"Report_{rep_id[:8]}.pdf",
                        mime="application/pdf",
                        key=f"pdf_{rep_id}",
                        use_container_width=True,
                    )

                # JSON Export
                json_str = json.dumps(full_analysis, indent=2)
                st.download_button(
                    label="💾 Export Raw JSON",
                    data=json_str,
                    file_name=f"Report_{rep_id[:8]}.json",
                    mime="application/json",
                    key=f"json_{rep_id}",
                    use_container_width=True,
                )

                # Delete Report
                if st.button("🗑️ Delete Report", key=f"del_rep_{rep_id}", use_container_width=True):
                    db.delete("reports", rep_id)
                    st.success("Report deleted successfully.")
                    st.rerun()
