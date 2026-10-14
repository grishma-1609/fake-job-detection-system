"""
Main Streamlit Application Controller:
Intelligent Fake Job & Recruitment Scam Detection System.
Provides master routing, session management, sidebar navigation, and cybersecurity theme injection.
"""

import os
import sys
import streamlit as st

# Configure page metadata
st.set_page_config(
    page_title="Fake Job & Scam Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Ensure project root is in system path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from auth.authentication import AuthService
from database.json_db import get_db
from models.predictor import get_predictor
from utils.styles import apply_cybersecurity_theme
from views import (
    render_dashboard,
    render_detect_job,
    render_history,
    render_home,
    render_login,
    render_model_info,
    render_register,
    render_reports,
    render_security_guide,
    render_settings,
)

# Initialize singletons
auth_service = AuthService()
db = get_db()
predictor = get_predictor()

# Apply CSS
apply_cybersecurity_theme()

# Initialize Session State
if "is_authenticated" not in st.session_state:
    st.session_state["is_authenticated"] = False
if "user" not in st.session_state:
    st.session_state["user"] = None
if "current_page" not in st.session_state:
    st.session_state["current_page"] = "Home"

# Sidebar Navigation Architecture
with st.sidebar:
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 10px; padding: 10px 0 16px 0; border-bottom: 1px solid #1E293B; margin-bottom: 16px;">
        <span style="font-size: 28px;">🛡️</span>
        <div>
            <div style="font-weight: 800; font-size: 15px; color: #FFFFFF; letter-spacing: -0.02em;">CYBER DEFENSE</div>
            <div style="font-size: 11px; color: #00F0FF; font-family: monospace;">JOB FRAUD SHIELD v2.4</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # User Profile / Identity Header
    if st.session_state["is_authenticated"] and st.session_state["user"]:
        user = st.session_state["user"]
        st.markdown(f"""
        <div style="background: #111827; border: 1px solid #1E293B; border-radius: 8px; padding: 10px 12px; margin-bottom: 16px;">
            <div style="font-size: 11px; color: #94A3B8; text-transform: uppercase; font-weight: 600;">ACTIVE OPERATOR</div>
            <div style="font-weight: 700; color: #F8FAFC; font-size: 14px;">{user.get('full_name', 'Analyst')}</div>
            <div style="font-size: 11px; color: #00F0FF; font-family: monospace;">@{user.get('username')} &bull; {str(user.get('role', 'analyst')).upper()}</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 8px; padding: 10px 12px; margin-bottom: 16px;">
            <div style="font-size: 11px; color: #FBBF24; font-weight: 700;">PUBLIC AUDITOR MODE</div>
            <div style="font-size: 11px; color: #94A3B8; margin-top: 2px;">Sign in for persistent incident reports and custom settings.</div>
        </div>
        """, unsafe_allow_html=True)

    # Navigation Menu Items
    menu_items = [
        "Home",
        "Dashboard",
        "Detect Job",
        "Analysis History",
        "Saved Reports",
        "Security Guide",
        "Model Information",
        "Settings",
    ]

    # Add Auth Options
    if st.session_state["is_authenticated"]:
        menu_items.append("Logout")
    else:
        menu_items.append("Login")
        menu_items.append("Register")

    # Determine default index
    current_p = st.session_state.get("current_page", "Home")
    if current_p not in menu_items:
        current_p = "Home"
        st.session_state["current_page"] = "Home"

    selected_page = st.radio(
        "Navigation",
        menu_items,
        index=menu_items.index(current_p),
        label_visibility="collapsed",
    )

    if selected_page != st.session_state["current_page"]:
        if selected_page == "Logout":
            st.session_state["is_authenticated"] = False
            st.session_state["user"] = None
            st.session_state["current_page"] = "Login"
            st.rerun()
        else:
            st.session_state["current_page"] = selected_page
            st.rerun()

    # System Status Footer
    st.markdown("---")
    st.markdown("""
    <div style="font-size: 11px; color: #64748B; font-family: monospace;">
        <div>STATUS: <span style="color: #10B981;">● ONLINE</span></div>
        <div>MODEL: <span style="color: #00F0FF;">LOGISTIC-REGRESSION</span></div>
        <div>STORAGE: <span style="color: #94A3B8;">JSON-DB ATOMIC</span></div>
        <div style="margin-top: 8px; color: #475569;">B.Tech Cybersecurity Capstone</div>
    </div>
    """, unsafe_allow_html=True)

# Page Routing Engine
page = st.session_state.get("current_page", "Home")

# Route handler
if page == "Home":
    render_home()
elif page == "Dashboard":
    render_dashboard()
elif page == "Detect Job":
    render_detect_job()
elif page == "Analysis History":
    render_history()
elif page == "Saved Reports":
    render_reports()
elif page == "Security Guide":
    render_security_guide()
elif page == "Model Information":
    render_model_info()
elif page == "Settings":
    render_settings()
elif page == "Login":
    render_login()
elif page == "Register":
    render_register()
else:
    render_home()
