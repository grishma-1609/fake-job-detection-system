"""
Login View:
Handles user authentication, credential validation, demo credentials auto-fill,
and session state initialization.
"""

import streamlit as st

from auth.authentication import AuthService
from utils.styles import render_cyber_header


def render_login():
    """Renders cybersecurity-styled login form."""
    render_cyber_header(
        title="Security Operations Portal - Authentication",
        subtitle="Sign in to access advanced recruitment threat intelligence and audit tooling.",
        badge="SOC RESTRICTED ACCESS"
    )

    auth = AuthService()

    c_box, c_spacer = st.columns([1.5, 1])

    with c_box:
        st.markdown("""
        <div style="background: #111827; border: 1px solid #1E293B; border-radius: 12px; padding: 24px; margin-bottom: 20px;">
            <h3 style="color: #F8FAFC; margin-top: 0; font-size: 18px;">🔑 Sign In to Your Account</h3>
        </div>
        """, unsafe_allow_html=True)

        username_or_email = st.text_input("Username or Email", placeholder="e.g. analyst_demo", key="login_id")
        password = st.text_input("Password", type="password", placeholder="Enter your password", key="login_pw")

        if st.button("🚀 Sign In", type="primary", use_container_width=True):
            if not username_or_email or not password:
                st.error("Please enter both username/email and password.")
            else:
                success, msg, user = auth.authenticate_user(username_or_email, password)
                if success and user:
                    st.session_state["is_authenticated"] = True
                    st.session_state["user"] = user
                    st.session_state["current_page"] = "Dashboard"
                    st.success("✅ Authentication successful! Redirecting to Dashboard...")
                    st.rerun()
                else:
                    st.error(f"❌ {msg}")

        st.markdown("<br>", unsafe_allow_html=True)

        # Quick Demo Login Assistance
        st.markdown("""
        <div style="background: rgba(0, 240, 255, 0.05); border: 1px solid rgba(0, 240, 255, 0.2); border-radius: 8px; padding: 12px;">
            <div style="color: #00F0FF; font-weight: 700; font-size: 13px;">💡 Evaluator / Demo Credentials:</div>
            <div style="color: #94A3B8; font-size: 12px; margin-top: 4px;">
                <strong>Username:</strong> <code>analyst_demo</code> &bull; <strong>Password:</strong> <code>Password@123</code><br>
                <strong>Admin:</strong> <code>admin</code> &bull; <strong>Password:</strong> <code>Admin@123</code>
            </div>
        </div>
        """, unsafe_allow_html=True)

        if st.button("⚡ Quick Login as Demo Analyst", use_container_width=True):
            success, msg, user = auth.authenticate_user("analyst_demo", "Password@123")
            if success and user:
                st.session_state["is_authenticated"] = True
                st.session_state["user"] = user
                st.session_state["current_page"] = "Dashboard"
                st.success("Logged in as Demo Analyst!")
                st.rerun()

        st.markdown("---")
        st.markdown("Don't have an account yet?")
        if st.button("📝 Create New Account (Register)", use_container_width=True):
            st.session_state["current_page"] = "Register"
            st.rerun()
