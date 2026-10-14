"""
Register View:
Handles new user registration, input validation, unique constraints checking,
and password hashing.
"""

import streamlit as st

from auth.authentication import AuthService
from utils.styles import render_cyber_header


def render_register():
    """Renders user account registration form."""
    render_cyber_header(
        title="Register New Threat Analyst Account",
        subtitle="Create an authorized user identity to track and save recruitment threat assessments.",
        badge="ACCOUNT REGISTRATION"
    )

    auth = AuthService()

    c_box, c_spacer = st.columns([1.5, 1])

    with c_box:
        st.markdown("""
        <div style="background: #111827; border: 1px solid #1E293B; border-radius: 12px; padding: 20px; margin-bottom: 20px;">
            <h3 style="color: #F8FAFC; margin-top: 0; font-size: 18px;">📝 Create Your Account</h3>
        </div>
        """, unsafe_allow_html=True)

        full_name = st.text_input("Full Name *", placeholder="e.g. Alex Morgan", key="reg_name")
        username = st.text_input("Username *", placeholder="e.g. amorgan_sec", key="reg_uname")
        email = st.text_input("Email Address *", placeholder="e.g. alex@cybersec.org", key="reg_email")
        password = st.text_input("Password (min 6 characters) *", type="password", placeholder="Enter strong password", key="reg_pw")
        confirm_password = st.text_input("Confirm Password *", type="password", placeholder="Re-enter password", key="reg_cpw")

        if st.button("🛡️ Register Account", type="primary", use_container_width=True):
            if password != confirm_password:
                st.error("Passwords do not match.")
            else:
                success, msg, user = auth.register_user(
                    username=username,
                    full_name=full_name,
                    email=email,
                    password=password,
                    role="analyst",
                )
                if success:
                    st.success(f"✅ {msg}")
                    st.info("Please sign in with your newly created credentials.")
                    # Direct to login page
                    st.session_state["current_page"] = "Login"
                    st.rerun()
                else:
                    st.error(f"❌ Registration failed: {msg}")

        st.markdown("---")
        st.markdown("Already have an account?")
        if st.button("🔑 Back to Sign In", use_container_width=True):
            st.session_state["current_page"] = "Login"
            st.rerun()
