"""
Settings Page:
User profile management, credential updates, account preferences,
history purging with confirmation, and session logout.
"""

import streamlit as st

from auth.authentication import AuthService
from database.json_db import get_db
from utils.helpers import format_timestamp
from utils.styles import render_cyber_header


def render_settings():
    """Renders profile, security settings, and administrative operations."""
    render_cyber_header(
        title="Account & System Settings",
        subtitle="Manage security credentials, audit preferences, and local database storage.",
        badge="SECURITY CONFIG"
    )

    auth = AuthService()
    db = get_db()
    current_user = st.session_state.get("user") or {}

    tab_profile, tab_security, tab_danger = st.tabs([
        "👤 Profile & Preferences",
        "🔑 Change Password",
        "⚠️ Storage & Danger Zone",
    ])

    with tab_profile:
        st.markdown("#### User Profile Information")
        p1, p2 = st.columns(2)
        with p1:
            st.text_input("Username", value=current_user.get("username", "analyst_demo"), disabled=True)
            st.text_input("Full Name", value=current_user.get("full_name", "Cybersecurity Analyst"), disabled=True)
        with p2:
            st.text_input("Email Address", value=current_user.get("email", "analyst@cybersec.org"), disabled=True)
            st.text_input("Assigned Role", value=str(current_user.get("role", "analyst")).upper(), disabled=True)

        st.markdown("#### Threat Engine Preferences")
        c_mode = st.selectbox("Default Scan Sensitivity", ["Standard (Recommended)", "Aggressive (Higher Recall)", "Conservative (Minimal False Positives)"])
        c_pdf = st.checkbox("Automatically append technical URL metadata to PDF reports", value=True)
        st.caption("Settings are stored in the local session state.")

    with tab_security:
        st.markdown("#### Update Account Password")
        old_pw = st.text_input("Current Password", type="password", key="chg_old_pw")
        new_pw = st.text_input("New Password", type="password", key="chg_new_pw")
        confirm_pw = st.text_input("Confirm New Password", type="password", key="chg_conf_pw")

        if st.button("🔒 Update Password", type="primary"):
            if not old_pw or not new_pw:
                st.error("Please enter current and new passwords.")
            elif new_pw != confirm_pw:
                st.error("New passwords do not match.")
            else:
                user_id = current_user.get("id")
                if not user_id:
                    st.error("User session missing ID.")
                else:
                    success, msg = auth.change_password(user_id, old_pw, new_pw)
                    if success:
                        st.success("✅ Password updated successfully! Keep your new credentials secure.")
                    else:
                        st.error(f"⚠️ Error: {msg}")

    with tab_danger:
        st.markdown("#### Purge Audit History & Reports")
        st.warning("Destructive actions cannot be undone. Data will be permanently removed from local JSON storage.")

        st.markdown("##### 1. Clear All Analysis History")
        confirm_purge_analyses = st.checkbox("I confirm I want to erase all analysis audit records", key="chk_purge_a")
        if st.button("🗑️ Purge Analyses Collection", disabled=not confirm_purge_analyses):
            db.clear_collection("analyses")
            st.success("✅ Analysis history successfully purged from database.")
            st.rerun()

        st.markdown("##### 2. Clear All Saved Incident Reports")
        confirm_purge_reports = st.checkbox("I confirm I want to erase all saved incident reports", key="chk_purge_r")
        if st.button("🗑️ Purge Reports Collection", disabled=not confirm_purge_reports):
            db.clear_collection("reports")
            st.success("✅ Saved reports successfully purged from database.")
            st.rerun()

    st.markdown("---")
    # Logout Section
    st.markdown("#### Session Termination")
    if st.button("🚪 Logout of Session", type="secondary", use_container_width=True):
        st.session_state["is_authenticated"] = False
        st.session_state["user"] = None
        st.session_state["current_page"] = "Login"
        st.success("You have been logged out.")
        st.rerun()
