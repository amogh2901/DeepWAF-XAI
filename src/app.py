import sys
from pathlib import Path

# Set project root path
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Ensure database directory exists
DB_DIR = PROJECT_ROOT / "database"
DB_DIR.mkdir(parents=True, exist_ok=True)

# Path to logs database
DB_PATH = DB_DIR / "logs.db"

# Append to sys path for module imports
sys.path.append(str(PROJECT_ROOT))
import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import random
import time
import pickle
import html
import html as py_html
from datetime import datetime
from threat_intelligence import get_threat_info
from response_engine import response_action, QUARANTINE_THRESHOLD
import quarantine
from threat_score import calculate_threat_score
from honeypot import check_honeypot
from detector import detect_attack
from explainability.explanation_engine import ExplanationEngine, generate_saliency_heatmap
try:
    from adversarial_sandbox import generate_adversarial_mutations
except ModuleNotFoundError:
    from src.adversarial_sandbox import generate_adversarial_mutations
from logger import log_attack
from admin_config import ADMIN_PASSKEY
try:
    from auth import (
        init_users_table, authenticate_user, register_user, update_user_role,
        provision_manual_user, request_account_reset, get_pending_iam_requests,
        admin_resolve_request, get_all_users, USERS_DB_PATH,
        get_soc_key, update_soc_key, get_user_passkey, update_user_passkey,
        count_users_by_role
    )
except ModuleNotFoundError:
    from src.auth import (
        init_users_table, authenticate_user, register_user, update_user_role,
        provision_manual_user, request_account_reset, get_pending_iam_requests,
        admin_resolve_request, get_all_users, USERS_DB_PATH,
        get_soc_key, update_soc_key, get_user_passkey, update_user_passkey,
        count_users_by_role
    )

# Load model info path
MODEL_INFO_PATH = PROJECT_ROOT / "model" / "model_info.pkl"

# Initialize explainability engine
explainer = ExplanationEngine()

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="DeepWAF-XAI Security Platform",
    page_icon="🛡",
    layout="wide"
)

# ---------------- CYBER SECURITY SOC UI & GLOBAL CSS ----------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,400;0,500;0,700;1,400&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');

:root {
    --bg-primary: #0A0E17;
    --bg-surface: #101827;
    --bg-card: #131C2E;
    --bg-terminal: #080C14;
    --border-subtle: #1E293B;
    --border-accent: #26354D;
    --cyan-glow: #00DFD8;
    --blue-accent: #0070F3;
    --emerald-glow: #10B981;
    --crimson-glow: #EF4444;
    --amber-glow: #F59E0B;
    --purple-glow: #8B5CF6;
    --text-main: #F1F5F9;
    --text-muted: #94A3B8;
}

/* Base Body & App Container */
html, body, [class*="css"], .stApp {
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background-color: #0A0E17 !important;
    color: #F1F5F9;
}

/* Custom Scrollbars */
::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}
::-webkit-scrollbar-track {
    background: #0A0E17;
}
::-webkit-scrollbar-thumb {
    background: #1E293B;
    border-radius: 4px;
    border: 1px solid #26354D;
}
::-webkit-scrollbar-thumb:hover {
    background: #0070F3;
}

/* Headings */
h1 {
    color: #00E5FF !important;
    font-size: 34px !important;
    font-weight: 800 !important;
    letter-spacing: -0.5px;
}

h2, h3 {
    color: #38BDF8 !important;
    font-weight: 700 !important;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #0D1322 !important;
    border-right: 1px solid #1E293B !important;
}

section[data-testid="stSidebar"] [data-testid="stSidebarNav"] {
    padding-top: 1rem;
}

section[data-testid="stSidebar"] div[role="radiogroup"] > label {
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid transparent;
    padding: 10px 14px;
    border-radius: 10px;
    margin-bottom: 6px;
    transition: all 0.25s ease;
}

section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover {
    background: rgba(0, 223, 216, 0.08);
    border-color: rgba(0, 223, 216, 0.25);
    transform: translateX(4px);
}

section[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"],
section[data-testid="stSidebar"] div[role="radiogroup"] > label[aria-checked="true"] {
    background: linear-gradient(90deg, rgba(0, 112, 243, 0.2) 0%, rgba(0, 223, 216, 0.1) 100%);
    border-left: 3px solid #00DFD8;
    border-color: rgba(0, 223, 216, 0.4);
}

/* Primary Action Buttons */
.stButton > button {
    background: linear-gradient(135deg, #0070F3 0%, #00DFD8 100%) !important;
    color: #FFFFFF !important;
    font-weight: 700 !important;
    font-size: 14px !important;
    letter-spacing: 0.3px !important;
    border: none !important;
    border-radius: 10px !important;
    padding: 10px 22px !important;
    box-shadow: 0 4px 14px rgba(0, 112, 243, 0.35) !important;
    transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
}

.stButton > button:hover {
    transform: translateY(-2px) scale(1.01) !important;
    box-shadow: 0 6px 22px rgba(0, 223, 216, 0.5) !important;
}

.stButton > button:active {
    transform: translateY(0px) scale(0.99) !important;
}

/* Monospace Inputs & Textareas */
.stTextInput input,
.stTextArea textarea {
    font-family: 'JetBrains Mono', Consolas, monospace !important;
    background: #151C2C !important;
    color: #F1F5F9 !important;
    border: 1px solid #26354D !important;
    border-radius: 10px !important;
    font-size: 13.5px !important;
    transition: all 0.25s ease !important;
}

.stTextInput input:focus,
.stTextArea textarea:focus {
    border-color: #00DFD8 !important;
    box-shadow: 0 0 14px rgba(0, 223, 216, 0.35) !important;
    outline: none !important;
}

/* Metric Cards */
[data-testid="stMetric"] {
    background: linear-gradient(180deg, #111827 0%, #0E1524 100%) !important;
    border: 1px solid #1E293B !important;
    border-top: 3px solid #00DFD8 !important;
    border-radius: 14px !important;
    padding: 16px 20px !important;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35) !important;
    transition: all 0.3s ease !important;
}

[data-testid="stMetric"]:hover {
    transform: translateY(-4px) !important;
    border-color: #00DFD8 !important;
    box-shadow: 0 8px 25px rgba(0, 223, 216, 0.25) !important;
}

[data-testid="stMetricLabel"] {
    color: #94A3B8 !important;
    font-size: 13px !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.5px !important;
}

[data-testid="stMetricValue"] {
    color: #F8FAFC !important;
    font-weight: 700 !important;
    font-size: 26px !important;
    font-family: 'JetBrains Mono', monospace !important;
}

.metric-card {
    background: linear-gradient(180deg, #111827 0%, #0E1524 100%);
    border: 1px solid #1E293B;
    border-top: 3px solid #00DFD8;
    border-radius: 14px;
    padding: 16px 18px;
    transition: all 0.3s ease;
    min-height: 110px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
}

.metric-card.card-safe {
    border-top-color: #10B981;
}

.metric-card.card-threat {
    border-top-color: #EF4444;
}

.metric-card.card-cyan {
    border-top-color: #00DFD8;
}

.metric-card.card-purple {
    border-top-color: #8B5CF6;
}

.metric-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 8px 25px rgba(0, 223, 216, 0.2);
}

.metric-title {
    color: #94A3B8;
    font-size: 13px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-top: 8px;
}

.metric-value {
    color: #FFFFFF;
    font-size: 28px;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
}

.metric-icon {
    font-size: 26px;
}

/* SOC Terminal Frame */
.terminal-window {
    background: #080C14;
    border: 1px solid #1E293B;
    border-radius: 12px;
    overflow: hidden;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
    margin-bottom: 20px;
    animation: fadeInUp 0.4s ease;
}

.terminal-header {
    background: #0F172A;
    border-bottom: 1px solid #1E293B;
    padding: 10px 16px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.terminal-dots {
    display: flex;
    align-items: center;
    gap: 7px;
}

.terminal-dot {
    width: 11px;
    height: 11px;
    border-radius: 50%;
    display: inline-block;
}

.dot-red { background: #FF5F56; box-shadow: 0 0 6px rgba(255, 95, 86, 0.6); }
.dot-yellow { background: #FFBD2E; box-shadow: 0 0 6px rgba(255, 189, 46, 0.6); }
.dot-green { background: #27C93F; box-shadow: 0 0 6px rgba(39, 201, 63, 0.6); }

.terminal-title {
    color: #94A3B8;
    font-family: 'JetBrains Mono', Consolas, monospace;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.5px;
    display: flex;
    align-items: center;
    gap: 8px;
}

.terminal-badge {
    background: rgba(0, 223, 216, 0.1);
    color: #00DFD8;
    border: 1px solid rgba(0, 223, 216, 0.3);
    padding: 2px 8px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.5px;
}

.terminal-legend {
    display: flex;
    align-items: center;
    gap: 8px;
}

.legend-bar {
    display: inline-block;
    width: 70px;
    height: 8px;
    border-radius: 4px;
    background: linear-gradient(90deg, rgba(255, 75, 75, 0.08), rgba(255, 75, 75, 0.95));
}

.terminal-body {
    padding: 18px 20px;
}

/* Multi-Column KPI Grid */
.kpi-card {
    background: linear-gradient(180deg, #111827 0%, #0D1424 100%);
    border: 1px solid #1E293B;
    border-top: 3px solid #00DFD8;
    border-radius: 12px;
    padding: 16px 18px;
    transition: all 0.25s ease;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
}

.kpi-card:hover {
    transform: translateY(-3px);
    box-shadow: 0 6px 20px rgba(0, 0, 0, 0.45);
}

.kpi-card.kpi-cyan { border-top-color: #00DFD8; }
.kpi-card.kpi-emerald { border-top-color: #10B981; }
.kpi-card.kpi-crimson { border-top-color: #EF4444; }
.kpi-card.kpi-amber { border-top-color: #F59E0B; }

.kpi-header {
    color: #94A3B8;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    margin-bottom: 6px;
    display: flex;
    align-items: center;
    gap: 6px;
}

.kpi-value {
    font-size: 22px;
    font-weight: 800;
    color: #FFFFFF;
    font-family: 'JetBrains Mono', monospace;
}

.kpi-sub {
    color: #64748B;
    font-size: 11px;
    margin-top: 4px;
}

/* Adversarial Table & Badges */
.soc-table-container {
    background: #080C14;
    border: 1px solid #1E293B;
    border-radius: 12px;
    overflow: hidden;
    margin-top: 14px;
    margin-bottom: 14px;
}

.soc-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    color: #F1F5F9;
}

.soc-table th {
    background: #0F172A;
    color: #94A3B8;
    text-align: left;
    padding: 12px 16px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    border-bottom: 1px solid #1E293B;
}

.soc-table td {
    padding: 12px 16px;
    border-bottom: 1px solid rgba(30, 41, 59, 0.7);
    vertical-align: middle;
}

.soc-table tbody tr:hover {
    background: rgba(255, 255, 255, 0.02);
}

.soc-table code {
    font-family: 'JetBrains Mono', Consolas, monospace;
    background: #111827;
    color: #00DFD8;
    padding: 3px 6px;
    border-radius: 5px;
    font-size: 12px;
    border: 1px solid #1E293B;
    word-break: break-all;
}

.soc-badge {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 11.5px;
    font-weight: 700;
    letter-spacing: 0.4px;
}

.badge-emerald {
    background: rgba(16, 185, 129, 0.15);
    color: #34D399;
    border: 1px solid #10B981;
    box-shadow: 0 0 10px rgba(16, 185, 129, 0.3);
}

.badge-crimson {
    background: rgba(239, 68, 68, 0.15);
    color: #F87171;
    border: 1px solid #EF4444;
    box-shadow: 0 0 10px rgba(239, 68, 68, 0.3);
}

.badge-blue {
    background: rgba(59, 130, 246, 0.15);
    color: #60A5FA;
    border: 1px solid #3B82F6;
    box-shadow: 0 0 10px rgba(59, 130, 246, 0.25);
}

.badge-amber {
    background: rgba(245, 158, 11, 0.15);
    color: #FBBF24;
    border: 1px solid #F59E0B;
    box-shadow: 0 0 10px rgba(245, 158, 11, 0.25);
}

/* Expanders */
.streamlit-expanderHeader {
    background: #111827 !important;
    border: 1px solid #1E293B !important;
    border-radius: 10px !important;
    color: #F1F5F9 !important;
    font-weight: 600 !important;
}

[data-testid="stExpander"] {
    border: 1px solid #1E293B !important;
    border-radius: 10px !important;
    background: #0D1322 !important;
    margin-bottom: 14px !important;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    background: #0D1322;
    border-radius: 10px;
    padding: 4px;
    border: 1px solid #1E293B;
    gap: 6px;
}

.stTabs [data-baseweb="tab"] {
    border-radius: 8px;
    color: #94A3B8;
    font-weight: 600;
    padding: 8px 16px;
    transition: all 0.2s ease;
}

.stTabs [data-baseweb="tab"]:hover {
    color: #FFFFFF;
    background: rgba(255, 255, 255, 0.04);
}

.stTabs [aria-selected="true"] {
    background: linear-gradient(135deg, rgba(0, 112, 243, 0.3) 0%, rgba(0, 223, 216, 0.2) 100%) !important;
    color: #00DFD8 !important;
    border-bottom: 2px solid #00DFD8 !important;
}

/* Progress Bar */
.stProgress > div > div > div > div {
    background: linear-gradient(90deg, #0070F3 0%, #00DFD8 100%) !important;
    border-radius: 6px;
}

/* Popovers */
div[data-testid="stPopoverBody"] {
    background: #111827 !important;
    border: 1px solid #26354D !important;
    border-radius: 12px !important;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.6) !important;
}

/* Dataframe */
[data-testid="stDataFrame"] {
    border: 1px solid #1E293B !important;
    border-radius: 10px !important;
}

/* Animations */
@keyframes fadeInUp {
    from {
        opacity: 0;
        transform: translateY(20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}

@keyframes glow {
    0% { box-shadow: 0 0 6px rgba(0, 191, 255, 0.15); }
    50% { box-shadow: 0 0 22px rgba(0, 191, 255, 0.45); }
    100% { box-shadow: 0 0 6px rgba(0, 191, 255, 0.15); }
}

@keyframes pulse {
    0% { transform: scale(1); }
    50% { transform: scale(1.02); }
    100% { transform: scale(1); }
}
</style>
""", unsafe_allow_html=True)

# ---------------- Enterprise Authentication Gate ----------------
init_users_table()

if not st.session_state.get("authenticated", False):
    st.html("""
    <style>
    [data-testid="stSidebar"], section[data-testid="stSidebar"], [data-testid="collapsedControl"] {
        display: none !important;
    }
    .auth-card {
        background: linear-gradient(180deg, #111827 0%, #162032 100%);
        border: 1px solid #26354D;
        border-radius: 20px;
        padding: 28px 32px;
        margin-top: 40px;
        box-shadow: 0 0 35px rgba(0, 191, 255, 0.12);
        animation: fadeInUp 0.5s ease;
    }
    .auth-header {
        text-align: center;
        margin-bottom: 20px;
    }
    .auth-title {
        font-size: 28px;
        font-weight: 700;
        color: #00E5FF;
        margin-top: 12px;
        letter-spacing: 0.5px;
    }
    .auth-subtitle {
        color: #94A3B8;
        font-size: 14px;
        margin-top: 6px;
    }
    .auth-badge {
        display: inline-block;
        background: rgba(0, 229, 255, 0.1);
        color: #00E5FF;
        border: 1px solid rgba(0, 229, 255, 0.3);
        border-radius: 20px;
        padding: 4px 14px;
        font-size: 12px;
        font-weight: 600;
        margin-top: 8px;
    }
    </style>
    """)

    _, center_col, _ = st.columns([1, 1.6, 1])

    with center_col:
        st.html("""
        <div class="auth-card">
            <div class="auth-header">
                <img src="https://img.icons8.com/fluency/96/shield.png" width="70" />
                <div class="auth-title">DeepWAF-XAI Platform</div>
                <div class="auth-subtitle">Zero-Trust Enterprise AI Web Application Firewall</div>
                <div class="auth-badge">🛡️ RESTRICTED ACCESS • OPERATOR LOGIN REQUIRED</div>
            </div>
        </div>
        """)

        tab_login, tab_register = st.tabs(["🔐 Sign In", "📝 Create Operator Account"])

        with tab_login:
            st.markdown("#### Operator Sign In")
            st.caption("Authenticate with your credentials to access the SOC console.")

            pending_user = st.session_state.get("pending_2fa_user")

            if pending_user:
                # ── Phase 2: Elevated 2FA Terminal Verification ───────────────
                pending_role = st.session_state.get("pending_2fa_role", "admin")
                role_label = "Administrator" if pending_role == "admin" else "Security Tester"

                st.html(f"""
                <div style="
                    background: linear-gradient(135deg, #1e1b4b 0%, #311042 100%);
                    border: 1px solid #7c3aed;
                    border-radius: 12px;
                    padding: 16px 20px;
                    margin-bottom: 16px;
                ">
                    <div style="color: #a78bfa; font-weight: 700; font-size: 16px;">
                        🔐 Two-Step Verification Required
                    </div>
                    <div style="color: #c4b5fd; font-size: 13px; margin-top: 4px;">
                        Account <b>{pending_user}</b> ({role_label}) requires secondary 2FA verification.
                        A 6-digit one-time passcode has been printed to the <b>secure backend terminal</b>.
                    </div>
                </div>
                """)

                otp_input = st.text_input(
                    "Admin 2FA Terminal Key",
                    type="password",
                    key="auth_phase2_otp",
                    placeholder="Enter 6-digit OTP from backend terminal",
                    max_chars=6
                )

                col_verify, col_cancel = st.columns([1.2, 1])

                with col_verify:
                    if st.button("✅ Verify & Sign In", type="primary", use_container_width=True, key="btn_phase2_verify"):
                        active_otp = st.session_state.get("admin_otp")
                        if otp_input.strip() and active_otp and otp_input.strip() == str(active_otp):
                            # Wipe residual session state before setting fresh authenticated session
                            st.session_state.clear()
                            st.session_state["authenticated"] = True
                            st.session_state["username"] = pending_user
                            st.session_state["role"] = pending_role
                            st.session_state["pending_2fa_user"] = None
                            st.session_state["pending_2fa_role"] = None
                            st.session_state["admin_otp"] = None
                            st.success("✅ 2FA Verification successful! Loading platform...")
                            time.sleep(0.3)
                            st.rerun()
                        else:
                            st.error("❌ Invalid 2FA Key. Please verify the code printed in your backend terminal.")

                with col_cancel:
                    if st.button("↩ Cancel / Go Back", use_container_width=True, key="btn_phase2_cancel"):
                        st.session_state["pending_2fa_user"] = None
                        st.session_state["pending_2fa_role"] = None
                        st.session_state["admin_otp"] = None
                        st.rerun()

            else:
                # ── Phase 1: Standard Username & Password ─────────────────────
                login_user = st.text_input("Username", key="auth_login_user", placeholder="Enter your username")
                login_pwd  = st.text_input("Password", type="password", key="auth_login_pwd", placeholder="••••••••")

                if st.button("🔓 Continue", type="primary", use_container_width=True, key="btn_signin"):
                    if not login_user.strip() or not login_pwd:
                        st.warning("Please enter both username and password.")
                    else:
                        auth_result = authenticate_user(login_user, login_pwd)
                        auth_status = auth_result.get("status")

                        if auth_status == "LOCKED":
                            st.error("🔒 Account Locked. Please submit an unlock request below or contact SOC Admin.")
                        elif auth_status == "FAILED":
                            attempts = auth_result.get("attempts", 1)
                            if attempts == 1:
                                st.warning("⚠️ Invalid credentials (Attempt 1 of 5). Notice: Repeated failed attempts trigger progressive security delays. Account locks after 5 attempts.")
                            elif attempts == 2:
                                st.warning("⚠️ Invalid credentials (Attempt 2 of 5). Notice: 3 more failed attempts will lock this account.")
                            elif attempts == 3:
                                st.warning("⚠️ Invalid credentials (Attempt 3 of 5). Next failed attempt will enforce an automatic 10-second security delay.")
                            elif attempts == 4:
                                st.warning("⏳ Attempt 4 of 5: Security delay penalty triggered. 1 attempt remaining before account lockout.")
                                timer_box = st.empty()
                                for remaining in range(10, 0, -1):
                                    timer_box.info(f"⏱️ Security cooling down... Please wait {remaining} seconds before retry.")
                                    time.sleep(1)
                                timer_box.empty()
                            else:
                                timer_box = st.empty()
                                for remaining in range(20, 0, -1):
                                    timer_box.error(f"🚫 Maximum attempts reached (5/5). Locking account in {remaining} seconds...")
                                    time.sleep(1)
                                timer_box.empty()
                                st.error("🔒 Account Locked. Please submit an unlock request below or contact SOC Admin.")
                        elif auth_status == "SUCCESS":
                            role = auth_result.get("role", "user")
                            if role == "blocked":
                                st.error("⛔ Access Revoked: This account has been blocked by the Administrator.")
                            elif role == "admin":
                                # Trigger Phase 2: Elevated 2FA ONLY for SuperAdmin (admin)
                                otp = random.randint(100000, 999999)
                                st.session_state["admin_otp"] = str(otp)
                                st.session_state["pending_2fa_user"] = login_user.strip()
                                st.session_state["pending_2fa_role"] = role
                                print(f"\n{'='*55}\n  [SECURE SYSTEM LOG] 🛡️  Two-Step 2FA Terminal OTP: {otp}\n  Target Operator: {login_user.strip()} ({role.upper()})\n  Issued at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n{'='*55}\n", flush=True)
                                st.rerun()
                            else:
                                # Security Auditor / Tester (tester) & Standard Operators (user): Direct password login without OTP
                                st.session_state.clear()
                                st.session_state["authenticated"] = True
                                st.session_state["username"] = login_user.strip()
                                st.session_state["role"] = role
                                role_label = "Security Auditor (Tester)" if role == "tester" else "Standard Operator"
                                st.success(f"✅ Authentication successful as {role_label}! Loading security platform...")
                                time.sleep(0.3)
                                st.rerun()

        with tab_register:
            st.markdown("#### Register New Operator")
            st.caption("Create a new standard operator profile in the database.")
            reg_user    = st.text_input("New Username", key="auth_reg_user", placeholder="Choose a unique username")
            reg_pwd     = st.text_input("New Password", type="password", key="auth_reg_pwd", placeholder="At least 6 characters")
            reg_confirm = st.text_input("Confirm Password", type="password", key="auth_reg_confirm", placeholder="••••••••")

            if st.button("🛡️ Create Account", type="primary", use_container_width=True, key="btn_register"):
                if not reg_user.strip() or not reg_pwd or not reg_confirm:
                    st.warning("Please fill in all registration fields.")
                elif reg_pwd != reg_confirm:
                    st.error("Passwords do not match.")
                elif len(reg_pwd) < 6:
                    st.error("Password must be at least 6 characters long.")
                else:
                    success, msg = register_user(reg_user, reg_pwd)
                    if success:
                        st.success(f"✅ {msg} Switch to the **Sign In** tab to log in.")
                    else:
                        st.error(f"❌ {msg}")

        st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)
        with st.expander("🔑 Forgot Password / Request Unlock", expanded=False):
            st.markdown("#### IT Helpdesk Support Ticket")
            st.caption("Submit an account unlock or password reset request to the SOC Administrator.")
            reset_uname = st.text_input("Account Username", key="req_reset_uname", placeholder="Enter your username")
            if st.button("📨 Submit Unlock Request", use_container_width=True, key="btn_submit_reset"):
                if not reset_uname.strip():
                    st.warning("Please enter your username.")
                else:
                    ok, r_msg = request_account_reset(reset_uname.strip())
                    if ok:
                        st.success("✅ Request sent to SOC Admin. Your administrator will review and unlock your account.")
                    else:
                        st.error(f"❌ {r_msg}")

    # Stop rendering remainder of the app until authenticated
    st.stop()

# ---------------- Navigation ----------------
st.sidebar.image(
    "https://img.icons8.com/fluency/96/shield.png",
    width=70
)

st.sidebar.title("DeepWAF-XAI")
st.sidebar.caption("Explainable Deep Learning Framework")

current_operator = st.session_state.get("username", "Admin")
current_role = st.session_state.get("role", "user")

# Blocked user guard
if current_role == "blocked":
    st.error("⛔ Access Denied: Your account has been blocked by the Security Administrator.")
    st.stop()

# Visual role badge
if current_role == "admin":
    role_bg = "#7c3aed"
    role_name = "ADMIN"
    role_icon = "👑"
elif current_role == "tester":
    role_bg = "#059669"
    role_name = "TESTER"
    role_icon = "🧪"
else:
    role_bg = "#2563eb"
    role_name = "USER"
    role_icon = "👤"

st.sidebar.markdown(
    f"🟢 **Operator:** `{current_operator}` &nbsp; "
    f"<span style='background:{role_bg};color:white;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;letter-spacing:0.5px;'>{role_icon} {role_name}</span>",
    unsafe_allow_html=True
)

st.sidebar.markdown("---")

# Strict Multi-Tier RBAC Navigation restriction
# Admins and Testers see both pages; standard users ONLY see Attack Detection
if current_role in ["admin", "tester"]:
    nav_options = [
        "🛡 Attack Detection",
        "📊 Security Dashboard"
    ]
else:
    nav_options = [
        "🛡 Attack Detection"
    ]

def force_state_flush():
    st.session_state['iam_refresh_tick'] = st.session_state.get('iam_refresh_tick', 0) + 1

page = st.sidebar.radio(
    "Navigation",
    nav_options,
    on_change=force_state_flush
)

# ── Sidebar Logout Button ────────────────────────────────────────────────────
st.sidebar.markdown("---")
if st.sidebar.button("🚪 Logout", use_container_width=True, key="btn_sidebar_logout"):
    keys_to_clear = [
        "analysis_complete", "analysis_data", "current_payload", 
        "saliency_scores", "adversarial_results", "raw_payload_input",
        "request_input", "authenticated", "user", "username", "role",
        "otp_verified", "otp_granted", "admin_otp", "pending_2fa_user",
        "pending_2fa_role", "current_page"
    ]
    for key in keys_to_clear:
        st.session_state.pop(key, None)
    st.session_state.clear()
    st.rerun()

# ── Page-change tracker — reset Level-2 OTP on genuine navigation only ────────
# This block runs once per Streamlit rerun (every interaction OR autorefresh).
# It only clears OTP state when the user switches pages, not on every 5-second
# autorefresh of the same page.
if "current_page" not in st.session_state:
    st.session_state["current_page"] = page
if st.session_state["current_page"] != page:
    # User navigated to a different page — wipe Level-2 access
    st.session_state["otp_granted"] = False
    st.session_state["admin_otp"]   = None
    st.session_state["current_page"] = page

# ---------------- Helper functions ----------------

def render_html_heatmap(saliency_scores):
    """
    Generate dark-themed HTML markup visualizing character-level saliency scores.

    Parameters
    ----------
    saliency_scores : list of tuple
        List of (character, importance_score) tuples with scores normalized between 0.0 and 1.0.

    Returns
    -------
    str
        HTML string containing styled spans inside a SOC Terminal Viewport.
    """
    if not saliency_scores:
        return ""

    tokens_html = []
    for char, score in saliency_scores:
        clamped_score = max(0.0, min(1.0, float(score)))
        escaped_char = py_html.escape(char)
        if escaped_char == " ":
            escaped_char = "&nbsp;"
        elif escaped_char == "\n":
            escaped_char = "<br>"
        elif escaped_char == "\t":
            escaped_char = "&nbsp;&nbsp;&nbsp;&nbsp;"

        # High-contrast color with score opacity and glowing border for higher attributions
        bg_style = f"background-color: rgba(255, 75, 75, {clamped_score:.3f});"
        text_color = "#FFFFFF" if clamped_score > 0.25 else "#E2E8F0"
        font_weight = "700" if clamped_score > 0.6 else "600" if clamped_score > 0.3 else "400"
        border_style = f"border: 1px solid rgba(255, 100, 100, {min(1.0, clamped_score * 0.9):.2f});" if clamped_score > 0.35 else "border: 1px solid transparent;"
        glow_style = f"box-shadow: 0 0 8px rgba(255, 75, 75, {clamped_score * 0.7:.2f});" if clamped_score > 0.5 else ""

        tokens_html.append(
            f'<span style="{bg_style} {border_style} {glow_style} color: {text_color}; font-weight: {font_weight}; '
            f'padding: 2px 2px; border-radius: 4px; display: inline-block; line-height: 1.3; font-family: \'JetBrains Mono\', monospace;" '
            f'title="Attribution Score: {clamped_score:.1%}">{escaped_char}</span>'
        )

    inner_payload = "".join(tokens_html)

    html = f"""
    <div class="terminal-window" style="margin-top: 18px; margin-bottom: 14px;">
        <div class="terminal-header">
            <div class="terminal-dots">
                <span class="terminal-dot dot-red"></span>
                <span class="terminal-dot dot-yellow"></span>
                <span class="terminal-dot dot-green"></span>
            </div>
            <div class="terminal-title">
                <span>🔥</span> OCCLUSION_ATTRIBUTION_HEATMAP // CHARACTER_SALIENCY_VIEWPORT
            </div>
            <div class="terminal-legend">
                <span style="font-size: 11px; color: #94A3B8;">Low</span>
                <span class="legend-bar"></span>
                <span style="font-size: 11px; color: #FF6B6B; font-weight: 700;">High Impact</span>
            </div>
        </div>
        <div class="terminal-body" style="
            background: #080C14;
            border-top: none;
            padding: 18px 20px;
            font-family: 'JetBrains Mono', Consolas, monospace;
            font-size: 14px;
            line-height: 1.9;
            white-space: pre-wrap;
            word-break: break-all;
            color: #FFFFFF;
            box-shadow: inset 0 0 16px rgba(0, 0, 0, 0.6);
        ">{inner_payload}</div>
    </div>
    """
    return html

def create_attack_logs_table():
    """Create logs table if it doesn't exist."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS attack_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    request TEXT,
                    attack_type TEXT,
                    confidence REAL,
                    severity TEXT,
                    threat_score REAL,
                    prediction_time_ms REAL
                )
            """)
    except Exception as e:
        st.error(f"Database setup error: {e}")

def load_model_info():
    try:
        with open(MODEL_INFO_PATH, "rb") as f:
            return pickle.load(f)
    except Exception:
        return {
            "embedding_dim": 128,
            "num_classes": 5,
            "sequence_length": 200
        }

def get_db_connection():
    try:
        return sqlite3.connect(DB_PATH)
    except Exception as e:
        st.error(f"Database connection error: {e}")
        return None

def load_attack_logs() -> pd.DataFrame:
    try:
        conn = get_db_connection()
        if conn is None:
            return pd.DataFrame()
        df = pd.read_sql_query("SELECT * FROM attack_logs", conn)
        conn.close()
        if not df.empty:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df
    except Exception as e:
        st.error(f"Error loading logs: {e}")
        return pd.DataFrame()

def get_live_stats():
    df = load_attack_logs()

    if df.empty:
        return {
            "total": 0,
            "safe": 0,
            "malicious": 0,
            "critical": 0,
            "avg_score": 0
        }

    normal = ["Normal", "LEGAL"]

    total = len(df)
    safe = len(df[df["attack_type"].isin(normal)])
    malicious = len(df[~df["attack_type"].isin(normal)])
    critical = len(df[df["severity"] == "CRITICAL"])

    avg_score = (
        df["threat_score"].mean()
        if "threat_score" in df.columns
        else 0
    )

    return {
        "total": total,
        "safe": safe,
        "malicious": malicious,
        "critical": critical,
        "avg_score": avg_score
    }

def get_filtered_logs(df, attack_type, severity, date_range, request_search):
    filtered = df.copy()
    if attack_type != "All":
        filtered = filtered[filtered["attack_type"] == attack_type]
    if severity != "All":
        filtered = filtered[filtered["severity"] == severity]
    if date_range:
        start_dt, end_dt = date_range
        filtered = filtered[
            (filtered["timestamp"] >= start_dt) &
            (filtered["timestamp"] < end_dt + pd.Timedelta(days=1))
        ]
    if request_search:
        filtered = filtered[filtered["request"].str.contains(request_search, case=False, na=False)]
    return filtered

# Create logs table once
create_attack_logs_table()
# Initialise quarantine tables (idempotent)
quarantine.init_pending_table()

# ---------------- Attack Detection Page ----------------
if page == "🛡 Attack Detection":
    if "current_payload" not in st.session_state:
        st.session_state.current_payload = ""
    if "analysis_complete" not in st.session_state:
        st.session_state.analysis_complete = False
    if "analysis_data" not in st.session_state:
        st.session_state.analysis_data = {}

    st.title("🛡 DeepWAF-XAI")

    st.caption(
        "An Explainable Deep Learning Framework for Real-Time Web Attack Detection and Intelligent Threat Mitigation"
    )

    st.markdown("""
    <div style="
        background: linear-gradient(90deg, rgba(16, 185, 129, 0.12) 0%, rgba(0, 223, 216, 0.08) 100%);
        border: 1px solid rgba(16, 185, 129, 0.35);
        padding: 14px 20px;
        border-radius: 12px;
        font-size: 15px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 20px;
        box-shadow: 0 0 20px rgba(16, 185, 129, 0.15);
    ">
        <div>
            <span style="color: #34D399; font-weight: 700;">🟢 AI Engine Online</span> &nbsp;|&nbsp; 
            <span style="color: #94A3B8; font-family: 'JetBrains Mono', monospace; font-size: 13px;">Stacked Character-Level BiLSTM Active</span>
        </div>
        <div style="background: rgba(16, 185, 129, 0.2); color: #34D399; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; letter-spacing: 0.5px;">
            SOC READY
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="terminal-window">
        <div class="terminal-header">
            <div class="terminal-dots">
                <span class="terminal-dot dot-red"></span>
                <span class="terminal-dot dot-yellow"></span>
                <span class="terminal-dot dot-green"></span>
            </div>
            <div class="terminal-title">
                <span>🖥️</span> soc-terminal@deepwaf:~ (HTTP_INGESTION_STREAM)
            </div>
            <div class="terminal-badge">
                LIVE PAYLOAD INGESTION
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

# =========================
# Request Input Section
# =========================

    left, right = st.columns([7,3], gap="large")

# ================= LEFT (70%)
    with left:

        if "request_input" not in st.session_state:
            st.session_state.request_input = ""

        request_input = st.text_area(
            "Paste HTTP Request / URL / Payload",
            key="request_input",
            height=250,
            placeholder="Paste your HTTP request, URL or payload here..."
        )

        st.caption(f"Characters : {len(request_input)} / 5000")

        analyze = st.button(
            "🔍 Analyze Request",
            use_container_width=True
        )


# ================= RIGHT (30%)
    with right:

        with st.popover("❓ Help / Examples", use_container_width=True):

            st.markdown("### Example Inputs")

            st.code(
                "<script>alert('XSS')</script>",
                language="html"
            )

            st.code(
                "SELECT * FROM users WHERE username='admin'--",
                language="sql"
            )

            st.code(
                "../../../etc/passwd",
                language="text"
            )

            st.code(
                "https://paypa1-login-security.com",
                language="text"
            )

            st.info("""
### 🔒 What happens next?

• Attack Type Prediction

• Confidence Score

• Explainable AI

• Threat Intelligence

• Recommended Action
""")


    if analyze:
        if not request_input.strip():
            st.warning("Please enter a request.")
            st.session_state.analysis_complete = False
            st.session_state.analysis_data = {}
        elif check_honeypot(request_input):
            st.error("🚨 Honeypot Triggered!")
            st.session_state.analysis_complete = False
            st.session_state.analysis_data = {}
        else:
            # ── Execute ML Inference Before Interception Checks ──
            attack_type, confidence, probabilities = detect_attack(request_input)

            # ── Strict database pre-check pipeline ──
            precheck = quarantine.check_payload_status(request_input)
            if precheck == "ALLOWLIST":
                st.markdown(f"""
                <div style='background-color: #0e1117; padding: 20px; border-radius: 5px; border-left: 5px solid #00C851; margin-bottom: 20px;'>
                    <h4 style='color: #00C851; margin-top: 0;'>✅ ADMIN-CONFIRMED SAFE (ALLOWLIST)</h4>
                    <p style='color: #cccccc;'><b>⚠️ EXCLUSION DISCLAIMER:</b> This payload has been manually overridden by a Security Administrator. The AI model's native prediction is explicitly bypassed as part of the DeepWAF-XAI framework's Zero-Trust exception protocols.</p>
                    <hr style='border-color: #333;'/>
                    <span style='color: #aaaaaa;'><b>Predicted Class:</b> {attack_type} &nbsp;&nbsp;|&nbsp;&nbsp; <b>Confidence:</b> {confidence:.2%} &nbsp;&nbsp;|&nbsp;&nbsp; <b>Firewall Status:</b> <span style='color: #00C851;'>ALLOWED</span></span>
                </div>
                """, unsafe_allow_html=True)
                st.session_state.analysis_complete = False
                st.session_state.analysis_data = {}
            elif precheck == "BLOCKLIST":
                st.markdown(f"""
                <div style='background-color: #1a0a0a; padding: 20px; border-radius: 5px; border-left: 5px solid #ff4444; margin-bottom: 20px;'>
                    <h4 style='color: #ff4444; margin-top: 0;'>🚨 ADMIN-CONFIRMED BLOCKED (BLOCKLIST)</h4>
                    <p style='color: #cccccc;'><b>⚠️ EXCLUSION DISCLAIMER:</b> This payload has been manually flagged as malicious by a Security Administrator. The AI model's native prediction is explicitly overridden as part of the DeepWAF-XAI framework's Zero-Trust exception protocols.</p>
                    <hr style='border-color: #333;'/>
                    <span style='color: #aaaaaa;'><b>Predicted Class:</b> {attack_type} &nbsp;&nbsp;|&nbsp;&nbsp; <b>Confidence:</b> {confidence:.2%} &nbsp;&nbsp;|&nbsp;&nbsp; <b>Firewall Status:</b> <span style='color: #ff4444;'>BLOCKED</span></span>
                </div>
                """, unsafe_allow_html=True)
                st.session_state.analysis_complete = False
                st.session_state.analysis_data = {}
            elif precheck == "PENDING":
                st.markdown(f"""
                <div style='background-color: #1a1500; padding: 20px; border-radius: 5px; border-left: 5px solid #ffbb33; margin-bottom: 20px;'>
                    <h4 style='color: #ffbb33; margin-top: 0;'>⏳ QUARANTINED: ALREADY IN PENDING QUEUE</h4>
                    <p style='color: #cccccc;'>This payload was previously flagged and is currently awaiting SuperAdmin review. The status will update once the ticket is resolved.</p>
                    <hr style='border-color: #333;'/>
                    <span style='color: #aaaaaa;'><b>Predicted Class:</b> {attack_type} &nbsp;&nbsp;|&nbsp;&nbsp; <b>Confidence:</b> {confidence:.2%} &nbsp;&nbsp;|&nbsp;&nbsp; <b>Firewall Status:</b> <span style='color: #ffbb33;'>TEMPORARILY BLOCKED</span></span>
                </div>
                """, unsafe_allow_html=True)
                st.session_state.analysis_complete = False
                st.session_state.analysis_data = {}
            else:
                progress = st.progress(0)
                status = st.empty()

                steps = [
                    "🔍 Parsing HTTP Request...",
                    "🧠 Running Deep Learning Model...",
                    "📊 Calculating Confidence...",
                    "🛡 Mapping Threat Intelligence...",
                    "⚡ Generating Explainable AI..."
                ]

                for i, step in enumerate(steps):
                    status.info(step)
                    progress.progress((i + 1) * 20)
                    time.sleep(0.2)

                start_time = time.perf_counter()

                progress.progress(100)
                status.success("✅ Analysis Completed")
                time.sleep(0.3)

                progress.empty()
                status.empty()
                explanation_result = explainer.explain(payload=request_input, prediction=attack_type, confidence=confidence)
                end_time = time.perf_counter()
                prediction_time_ms = (end_time - start_time) * 1000

                model_info = load_model_info()

                embedding_dim = model_info.get("embedding_dim", 128)
                sequence_length = model_info.get(
                    "sequence_length",
                    model_info.get("max_sequence_length", 200)
                )
                classes = model_info.get("classes", [])
                num_classes = len(classes) if classes else 5

                info = get_threat_info(attack_type) or {
                    "severity": "MEDIUM",
                    "description": "Unknown threat pattern detected.",
                    "action": "Monitor request.",
                    "mitre": "",
                    "cvss": "",
                    "recommendation": ""
                }

                # Calculate threat score once
                threat_score = calculate_threat_score(info["severity"], confidence)

                # Log attack
                log_attack(
                    request=request_input,
                    attack_type=attack_type,
                    confidence=confidence,
                    severity=info["severity"],
                    threat_score=threat_score,
                    prediction_time_ms=prediction_time_ms
                )

                # Quarantine & Threat Intel gate: call response engine ONCE
                response = response_action(
                    info["severity"],
                    confidence=confidence,
                    attack_type=attack_type,
                    payload=request_input,
                )
                _quarantined = response.get("quarantined") == True

                if _quarantined:
                    logged_ok, q_msg = quarantine.log_pending_request(
                        payload=request_input,
                        predicted_class=attack_type,
                        confidence=confidence,
                    )
                    if not logged_ok and q_msg == "Already pending":
                        st.info("⏳ This payload is already in the queue awaiting Admin review. Status will update soon.")

                # Save state in session_state for persistent de-nested rendering
                st.session_state.current_payload = request_input
                st.session_state.analysis_complete = True
                st.session_state.analysis_data = {
                    "attack_type": attack_type,
                    "confidence": confidence,
                    "probabilities": probabilities,
                    "explanation_result": explanation_result,
                    "prediction_time_ms": prediction_time_ms,
                    "embedding_dim": embedding_dim,
                    "sequence_length": sequence_length,
                    "num_classes": num_classes,
                    "info": info,
                    "threat_score": threat_score,
                    "response": response,
                    "_quarantined": _quarantined
                }

    # ================================================================
    # Render Analysis Results (De-nested from Analyze button)
    # ================================================================
    if st.session_state.get("analysis_complete", False) and st.session_state.get("analysis_data"):
        data = st.session_state.analysis_data
        active_payload = st.session_state.get("current_payload", "")
        attack_type = data["attack_type"]
        confidence = data["confidence"]
        probabilities = data["probabilities"]
        explanation_result = data["explanation_result"]
        prediction_time_ms = data["prediction_time_ms"]
        embedding_dim = data["embedding_dim"]
        sequence_length = data["sequence_length"]
        num_classes = data["num_classes"]
        info = data["info"]
        threat_score = data["threat_score"]
        response = data["response"]
        _quarantined = data.get("_quarantined", False)

        # ================================================================
        # PATH A  —  QUARANTINED
        # ONLY the quarantine warning is rendered. Nothing else.
        # ================================================================
        if _quarantined:
            st.warning(
                f"🛡️ QUARANTINED: PENDING ADMIN APPROVAL\n\n"
                f"The AI model has analyzed this request and flagged it for manual review. "
                f"It has been **temporarily BLOCKED** and is awaiting a final decision "
                f"from the Security Administrator.\n\n"
                f"**Predicted Class:** {attack_type}   "
                f"**Confidence:** {confidence:.2%}   "
                f"**Threshold:** {QUARANTINE_THRESHOLD:.0%}   "
                f"**Firewall:** BLOCKED"
            )

        # ================================================================
        # PATH B  —  HIGH-CONFIDENCE / VERIFIED INTEL (standard path)
        # ALL standard UI is inside this else. Strictly unreachable when
        # _quarantined is True.
        # ================================================================
        else:
            # ── Detect whether this response came from the Threat Intel Feed ──
            _intel_reasons = {"Admin Verified Safe", "Admin Verified Threat"}
            _from_threat_intel = response.get("reason", "") in _intel_reasons

            # ── Detection result banner ───────────────────────────────────────
            if response.get("action") == "ALLOW" and _from_threat_intel:
                st.html("""
                <div style="
                    background: linear-gradient(135deg, #064e3b, #065f46);
                    border: 2px solid #10b981;
                    border-radius: 16px;
                    padding: 28px 32px;
                    margin: 12px 0 20px 0;
                    box-shadow: 0 0 28px rgba(16,185,129,.35);
                    animation: fadeInUp .5s ease;
                ">
                    <div style="font-size:36px; margin-bottom:10px;">✅</div>
                    <div style="color:#6ee7b7; font-size:22px; font-weight:700;">
                        Admin Verified Safe — Allowed by WAF Threat Intel Feed
                    </div>
                    <div style="color:#a7f3d0; margin-top:10px; font-size:15px;">
                        This payload matched an admin-verified allowlist rule.
                        The AI model was <strong>bypassed</strong> — no neural network inference was performed.
                        Request has been permitted directly by the database rule engine.
                    </div>
                </div>
                """)

            elif response.get("action") == "BLOCK" and _from_threat_intel:
                st.html("""
                <div style="
                    background: linear-gradient(135deg, #450a0a, #7f1d1d);
                    border: 2px solid #ef4444;
                    border-radius: 16px;
                    padding: 28px 32px;
                    margin: 12px 0 20px 0;
                    box-shadow: 0 0 28px rgba(239,68,68,.40);
                    animation: fadeInUp .5s ease;
                ">
                    <div style="font-size:36px; margin-bottom:10px;">🚫</div>
                    <div style="color:#fca5a5; font-size:22px; font-weight:700;">
                        Admin Verified Threat — Blocked by WAF Threat Intel Feed
                    </div>
                    <div style="color:#fecaca; margin-top:10px; font-size:15px;">
                        This payload matched an admin-verified blacklist rule.
                        The AI model was <strong>bypassed</strong> — no neural network inference was performed.
                        Request has been permanently blocked by the database rule engine.
                    </div>
                </div>
                """)

            elif response.get("action") == "ALLOW":
                st.success(f"✅ Safe Request — {response.get('reason', 'Safe Request')}: {response.get('message', '')}")
            elif attack_type.lower() in ["normal", "legal"]:
                info["severity"] = "LOW"
                info["description"] = "Normal web request."
                info["action"] = "No action required."
                st.success("✅ Safe Request")
            else:
                if info["severity"] == "CRITICAL":
                    st.error("🚨 CRITICAL SECURITY THREAT")
                elif info["severity"] == "HIGH":
                    st.warning("⚠ Malicious Activity")
                else:
                    st.warning("⚠ Suspicious Request Detected")

            # ── AI widgets: hidden when the DB rule engine fired ──────────────
            if not _from_threat_intel:
                is_normal = attack_type.lower() in ["normal", "legal"]
                pred_class_type = "kpi-emerald" if is_normal else ("kpi-crimson" if info.get("severity") in ["CRITICAL", "HIGH"] else "kpi-amber")
                threat_kpi_type = "kpi-crimson" if threat_score >= 0.7 else ("kpi-amber" if threat_score >= 0.4 else "kpi-emerald")

                # Multi-Column SOC KPI Cards
                st.markdown(f"""
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin-top: 14px; margin-bottom: 22px;">
                    <div class="kpi-card {pred_class_type}">
                        <div class="kpi-header"><span>🎯</span> AI Classification</div>
                        <div class="kpi-value" style="color: {'#34D399' if is_normal else '#F87171'}; font-size: 20px;">{attack_type}</div>
                        <div class="kpi-sub">BiLSTM Prediction</div>
                    </div>
                    <div class="kpi-card kpi-cyan">
                        <div class="kpi-header"><span>📊</span> Model Confidence</div>
                        <div class="kpi-value" style="color: #00DFD8;">{confidence:.2%}</div>
                        <div class="kpi-sub">Softmax Probability</div>
                    </div>
                    <div class="kpi-card {threat_kpi_type}">
                        <div class="kpi-header"><span>⚡</span> Threat Index</div>
                        <div class="kpi-value" style="color: {'#EF4444' if threat_score >= 0.7 else ('#F59E0B' if threat_score >= 0.4 else '#10B981')};">{threat_score:.2f} <span style="font-size:13px; color:#64748B;">/ 1.0</span></div>
                        <div class="kpi-sub">{info.get("severity", "MEDIUM")} Risk Level</div>
                    </div>
                    <div class="kpi-card kpi-cyan">
                        <div class="kpi-header"><span>⏱</span> Inference Latency</div>
                        <div class="kpi-value" style="color: #38BDF8;">{prediction_time_ms:.2f} <span style="font-size:13px; color:#64748B;">ms</span></div>
                        <div class="kpi-sub">Neural Compute Time</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                # Threat Intelligence
                st.markdown("### 🛡 Threat Intelligence & Attribution")
                st.markdown(f"""
                <div style="
                    background: #0D1322;
                    border: 1px solid #1E293B;
                    border-radius: 12px;
                    padding: 20px;
                    margin-bottom: 18px;
                ">
                    <div style="display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 16px;">
                        <div style="flex: 1; min-width: 140px;">
                            <span style="font-size: 11px; font-weight: 700; color: #64748B; text-transform: uppercase;">Severity</span><br>
                            <span class="soc-badge {'badge-crimson' if info.get('severity') in ['CRITICAL', 'HIGH'] else ('badge-amber' if info.get('severity') == 'MEDIUM' else 'badge-emerald')}" style="margin-top: 4px;">
                                {info.get('severity', 'N/A')}
                            </span>
                        </div>
                        <div style="flex: 1; min-width: 140px;">
                            <span style="font-size: 11px; font-weight: 700; color: #64748B; text-transform: uppercase;">CVSS Score</span><br>
                            <span style="font-family: 'JetBrains Mono', monospace; font-size: 15px; font-weight: 700; color: #F1F5F9;">
                                {info.get('cvss', 'N/A')}
                            </span>
                        </div>
                        <div style="flex: 2; min-width: 200px;">
                            <span style="font-size: 11px; font-weight: 700; color: #64748B; text-transform: uppercase;">MITRE ATT&CK ID</span><br>
                            <span style="font-family: 'JetBrains Mono', monospace; font-size: 13px; color: #00DFD8; font-weight: 600;">
                                {info.get('mitre', 'N/A')}
                            </span>
                        </div>
                    </div>
                    <div style="border-top: 1px solid #1E293B; padding-top: 12px; margin-top: 8px;">
                        <p style="margin: 0 0 8px 0;"><b style="color: #94A3B8;">Description:</b> <span style="color: #E2E8F0;">{info.get('description', 'N/A')}</span></p>
                        <p style="margin: 0 0 8px 0;"><b style="color: #94A3B8;">Recommended Action:</b> <span style="color: #E2E8F0;">{info.get('action', 'N/A')}</span></p>
                        <p style="margin: 0;"><b style="color: #94A3B8;">Security Guidance:</b> <span style="color: #E2E8F0;">{info.get('recommendation', 'N/A')}</span></p>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                # Probability chart
                if probabilities:
                    df_probs = pd.DataFrame(
                        probabilities.items(),
                        columns=["Attack Type", "Probability"]
                    )
                    df_probs["Probability"] *= 100
                    df_probs = df_probs.sort_values("Probability", ascending=False)
                    fig = px.bar(
                        df_probs,
                        x="Attack Type",
                        y="Probability",
                        color="Attack Type",
                        text_auto=".2f",
                        title="Attack Prediction Probabilities",
                    )
                    fig.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font=dict(color="#F1F5F9", family="Plus Jakarta Sans"),
                        xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
                        yaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
                    )
                    st.plotly_chart(fig, use_container_width=True)

                # Explainable AI
                st.markdown("## 🧠 Explainable AI")
                with st.expander("View AI Decision Explanation", expanded=True):
                    st.success(f"Prediction : {explanation_result['prediction']}")
                    st.metric("Model Confidence", f"{explanation_result['confidence']:.2f}%")
                    st.write("### Decision Reasons")
                    for reason in explanation_result["explanation"]:
                        st.markdown(f"✔ {reason}")
                    st.write("### Recommended Action")
                    st.warning(explanation_result["recommended_action"])

                    # Character-Level Saliency Heatmap
                    try:
                        saliency_scores = generate_saliency_heatmap(
                            payload=active_payload,
                            predict_function=detect_attack,
                            target_class=attack_type
                        )
                        if saliency_scores:
                            heatmap_html = render_html_heatmap(saliency_scores)
                            st.markdown(heatmap_html, unsafe_allow_html=True)
                    except Exception as heatmap_err:
                        print(f"[DeepWAF-XAI] Saliency Heatmap error: {heatmap_err}")

                # Adversarial Evasion Sandbox
                with st.expander("🧪 Adversarial Evasion Sandbox", expanded=False):
                    st.markdown("#### 🔬 Neural Network Robustness & Mutation Testing")
                    st.caption(
                        "Simulates advanced WAF evasion techniques (case toggling, comment injection, whitespace alteration, and null-byte injection) to benchmark the BiLSTM model's resilience against bypasses."
                    )

                    if st.button("🧪 Run Adversarial Stress Test", key="btn_run_adversarial_test", use_container_width=True):
                        try:
                            with st.spinner("Generating adversarial mutations and evaluating model resilience..."):
                                mutations = generate_adversarial_mutations(active_payload)

                            if not mutations:
                                st.info("No mutations generated for this payload.")
                            else:
                                results = []
                                blocked_count = 0
                                is_original_attack = attack_type.lower() not in ["normal", "legal"]

                                for mut in mutations:
                                    m_tech = mut["technique"]
                                    m_payload = mut["payload"]

                                    # Run through existing detector predict_function
                                    pred_class, conf, _ = detect_attack(m_payload)
                                    is_detected_as_attack = pred_class.lower() not in ["normal", "legal"]

                                    # Determine if evasion was blocked or succeeded
                                    if is_original_attack:
                                        # Original was an attack: model is resilient if it still detects an attack
                                        status = "🛡️ DETECTED (BLOCKED)" if is_detected_as_attack else "⚠️ EVADED (BYPASS)"
                                        if is_detected_as_attack:
                                            blocked_count += 1
                                    else:
                                        # Original was normal: model is resilient if it remains Normal
                                        status = "✅ NORMAL" if not is_detected_as_attack else "⚠️ FALSE POSITIVE"
                                        if not is_detected_as_attack:
                                            blocked_count += 1

                                    results.append({
                                        "technique": m_tech,
                                        "payload": m_payload,
                                        "prediction": pred_class,
                                        "confidence": f"{conf:.2%}",
                                        "status": status
                                    })

                                total_mutations = len(mutations)
                                resilience_score = (blocked_count / total_mutations) * 100.0 if total_mutations > 0 else 100.0

                                # Display Resilience Score Metric Card & Progress Bar
                                res_col1, res_col2 = st.columns([1.2, 2])
                                with res_col1:
                                    st.metric(
                                        "Evasion Resilience Score",
                                        f"{resilience_score:.1f}%",
                                        help="Percentage of adversarial mutations successfully neutralized and classified correctly by the AI model."
                                    )
                                with res_col2:
                                    if resilience_score >= 80:
                                        st.success(f"🟢 **HIGH RESILIENCE ({blocked_count}/{total_mutations} Blocked)** — The BiLSTM model demonstrated high robustness against perturbation.")
                                    elif resilience_score >= 50:
                                        st.warning(f"🟡 **MODERATE RESILIENCE ({blocked_count}/{total_mutations} Blocked)** — Partial vulnerability to certain token fragmentation techniques.")
                                    else:
                                        st.error(f"🔴 **VULNERABLE ({blocked_count}/{total_mutations} Blocked)** — Model was bypassed by one or more evasion techniques.")
                                    st.progress(resilience_score / 100.0)

                                # Custom SOC Table with Monospace Payloads & Glowing Badges
                                table_html_rows = []
                                for r in results:
                                    status_val = r["status"]
                                    if status_val == "🛡️ DETECTED (BLOCKED)":
                                        badge_markup = '<span class="soc-badge badge-emerald">🛡️ DETECTED (BLOCKED)</span>'
                                    elif status_val == "⚠️ EVADED (BYPASS)":
                                        badge_markup = '<span class="soc-badge badge-crimson">⚠️ EVADED (BYPASS)</span>'
                                    elif status_val == "✅ NORMAL":
                                        badge_markup = '<span class="soc-badge badge-blue">✅ NORMAL</span>'
                                    else:
                                        badge_markup = f'<span class="soc-badge badge-amber">{html.escape(str(status_val))}</span>'

                                    # Escape HTML characters first
                                    safe_payload = html.escape(str(r["payload"]))
                                    # Convert literal control characters to visible representations so they don't break the HTML string block
                                    safe_payload = safe_payload.replace('\n', '\\n').replace('\t', '\\t').replace('\r', '\\r')

                                    safe_tech = html.escape(str(r["technique"]))
                                    safe_pred = html.escape(str(r["prediction"]))
                                    safe_conf = html.escape(str(r["confidence"]))

                                    table_html_rows.append(
                                        f"<tr>"
                                        f"<td><strong>{safe_tech}</strong></td>"
                                        f"<td><code>{safe_payload}</code></td>"
                                        f"<td><span style=\"font-family: 'JetBrains Mono', monospace; font-weight: 600;\">{safe_pred}</span></td>"
                                        f"<td><span style=\"font-family: 'JetBrains Mono', monospace;\">{safe_conf}</span></td>"
                                        f"<td>{badge_markup}</td>"
                                        f"</tr>"
                                    )

                                soc_table_html = (
                                    '<div class="soc-table-container">'
                                    '<table class="soc-table">'
                                    '<thead>'
                                    '<tr>'
                                    '<th>Mutation Technique</th>'
                                    '<th>Mutated Payload</th>'
                                    '<th>New Prediction</th>'
                                    '<th>Confidence</th>'
                                    '<th>Detection Status</th>'
                                    '</tr>'
                                    '</thead>'
                                    '<tbody>'
                                    + ''.join(table_html_rows)
                                    + '</tbody>'
                                    '</table>'
                                    '</div>'
                                )
                                st.markdown(soc_table_html, unsafe_allow_html=True)

                        except Exception as adv_err:
                            print(f"[DeepWAF-XAI] Adversarial Sandbox error: {adv_err}")
                            st.warning("Adversarial stress test encountered a temporary processing issue.")

                # Threat Score
                st.subheader("Threat Score")
                st.progress(min(1.0, max(0.0, float(threat_score))))
                if   threat_score >= 0.90: st.error("🚨 CRITICAL RISK")
                elif threat_score >= 0.70: st.warning("⚠ HIGH RISK")
                elif threat_score >= 0.40: st.info("🟠 MEDIUM RISK")
                else:                      st.success("🟢 LOW RISK")

            # Adaptive Security Response — always shown (DB rule or AI decision)
            _status     = response.get("status", "N/A")
            _message    = response.get("message", "N/A")
            _firewall   = response.get("firewall", "N/A")
            _alert      = response.get("admin_alert", "N/A")
            _log        = response.get("log_status", "N/A")
            _rec_action = response.get("recommended_action", "N/A")
            _fp         = response.get("fp_mitigation", False)

            st.subheader("🛡 Adaptive Security Response")
            if _fp:
                st.warning(
                    f"🟡 **FALSE POSITIVE MITIGATION ACTIVE** — "
                    f"Status: **{_status}**\n\n{_message}"
                )
            elif _status == "BLOCKED":  st.error(f"🚫 **Status: {_status}** — {_message}")
            elif _status == "SAFE":     st.success(f"✅ **Status: {_status}** — {_message}")
            elif _status == "MONITOR":  st.info(f"🔵 **Status: {_status}** — {_message}")
            else:                       st.warning(f"⚠️ **Status: {_status}** — {_message}")

            st.write("**Firewall:**",          _firewall)
            st.write("**Admin Alert:**",        _alert)
            st.write("**Log Status:**",         _log)
            st.write("**Recommended Action:**", _rec_action)

            # Model Details — only meaningful when AI was actually used
            if not _from_threat_intel:
                st.markdown(f"""
                ### 📚 Model Details
                - **Model:** Bi-Directional LSTM
                - **Embedding:** {embedding_dim} Dimensions
                - **Sequence Length:** {sequence_length}
                - **Framework:** TensorFlow 2.x
                - **Classes:** {num_classes}
                - **Prediction:** Softmax
                """)
        
    stats = get_live_stats()

    st.html("<br>")

    cards = [
        ("📨", "Total Requests", stats["total"], "card-cyan"),
        ("✅", "Safe Requests", stats["safe"], "card-safe"),
        ("🚨", "Malicious", stats["malicious"], "card-threat"),
        ("☠", "Critical", stats["critical"], "card-threat"),
        ("🎯", "Avg Score", f"{stats['avg_score']:.2f}", "card-purple")
    ]

    cols = st.columns(5)

    for col, (icon, title, value, card_class) in zip(cols, cards):
        with col:
            st.html(f"""
            <div class="metric-card {card_class}">
                <div class="metric-icon">{icon}</div>
                <div class="metric-title">{title}</div>
                <div class="metric-value">{value}</div>
            </div>
            """)
        
    st.markdown("---")               

# ---------------- Security Dashboard ----------------
elif page == "📊 Security Dashboard":
    # Multi-Tier RBAC Hard Guard
    current_role = st.session_state.get("role")
    if current_role not in ["admin", "tester"]:
        st.error("⛔ Access Denied: Administrator or Tester role required to view the Security Dashboard.")
        st.stop()

    if current_role == "tester":
        st.html("""
        <div style="
            background: linear-gradient(135deg, #064e3b 0%, #065f46 100%);
            border: 1px solid #10b981;
            border-radius: 12px;
            padding: 14px 20px;
            margin-bottom: 16px;
        ">
            <div style="color: #6ee7b7; font-weight: 700; font-size: 16px;">
                🧪 Read-Only Tester Mode Active
            </div>
            <div style="color: #a7f3d0; font-size: 13px; margin-top: 3px;">
                You are viewing the SOC console in Read-Only Security Auditor / Tester Mode.
            </div>
        </div>
        """)

    st.title("DeepWAF-XAI Security Operations Center")

    if current_role == "admin":
        st.markdown("### 🔐 SuperAdmin SOC Verification")
        passkey = st.text_input("Enter Admin SOC Passkey", type="password", key="soc_admin_passkey_input")
        expected_key = get_soc_key("soc_admin_key", "admin")
        if passkey != expected_key:
            st.warning("SuperAdmin authentication required")
            st.stop()
        st.success("✅ Full SuperAdmin Access Granted")
    else:  # tester
        active_username = st.session_state.get("username", "")
        st.markdown("### 🔬 Security Auditor Telemetry Verification")
        st.caption(f"Operator **{active_username}** — Personal Auditor Access Key required for read-only telemetry access.")
        passkey = st.text_input("Enter your Personal Auditor Access Key", type="password", key="soc_tester_passkey_input")
        expected_key = get_user_passkey(active_username)
        if passkey != expected_key:
            st.warning("Personal Auditor Access Key verification required")
            st.stop()
        st.success(f"✅ Auditor Telemetry Access Granted (Read-Only Mode for {active_username})")

    st.write("")  # UI spacing
    if st.button("🔄 Refresh Data", use_container_width=True, type="primary"):
        st.session_state['iam_refresh_tick'] = st.session_state.get('iam_refresh_tick', 0) + 1
        try:
            st.rerun(scope="app")
        except TypeError:
            st.rerun()

    # ---------------- Identity & Access Management (IAM) Control Panel ----------------
    if st.session_state.get("role") == "admin":
        with st.expander("🛡️ Identity & Access Management (IAM)", expanded=False):
            st.markdown("### 🛡️ DeepWAF-XAI IAM Control Console")
            st.caption("Manage user access permissions, review account lockouts, handle password reset requests, and provision operator accounts.")

            # Helper for formatting IAM timestamps into local human-readable display
            def format_user_timestamp(ts_val) -> str:
                if not ts_val or pd.isna(ts_val):
                    return "—"
                try:
                    dt = pd.to_datetime(ts_val)
                    if dt.tzinfo is not None:
                        dt = dt.tz_convert(datetime.now().astimezone().tzinfo)
                    return dt.strftime("%B %d, %Y at %I:%M %p")
                except Exception:
                    try:
                        dt = datetime.strptime(str(ts_val).strip()[:19], "%Y-%m-%d %H:%M:%S")
                        return dt.strftime("%B %d, %Y at %I:%M %p")
                    except Exception:
                        return str(ts_val)

            # Helper for non-blocking IAM pending requests polling
            @st.fragment(run_every="5s")
            def render_iam_pending_requests():
                _ = st.session_state.get('iam_refresh_tick', 0)
                st.markdown("### 🔐 Pending IAM Requests & Lockout Management")
                st.caption("Review locked accounts and user-submitted IT password reset requests. (Auto-refreshes every 5s)")

                pending_requests = get_pending_iam_requests()
                trigger_unlock_refresh = False

                if pending_requests:
                    req_records = []
                    pending_usernames = []
                    for _p_id, _p_uname, _p_role, _p_attempts, _p_locked, _p_reset, _p_created in pending_requests:
                        pending_usernames.append(_p_uname)
                        status_tags = []
                        if _p_locked == 1:
                            status_tags.append("🚨 LOCKED (Brute-Force)")
                        if _p_reset == 1:
                            status_tags.append("🔑 RESET REQUESTED")

                        req_records.append({
                            "User ID": f"USR-{_p_id:04d}",
                            "Username": _p_uname,
                            "Role": str(_p_role).upper(),
                            "Failed Attempts": _p_attempts,
                            "Lockout Status": " & ".join(status_tags) if status_tags else "ACTIVE",
                            "Created At": format_user_timestamp(_p_created)
                        })

                    st.dataframe(pd.DataFrame(req_records), use_container_width=True)

                    st.markdown("#### 🔓 Unlock & Reset Account Action")
                    with st.form("iam_resolve_form"):
                        col_req_user, col_req_pwd = st.columns(2)
                        with col_req_user:
                            sel_req_user = st.selectbox("Select User to Unlock", pending_usernames, key="iam_sel_pending_user")
                        with col_req_pwd:
                            new_temp_pwd = st.text_input("New Temporary Password (Optional)", type="password", key="iam_new_temp_pwd", placeholder="Leave blank to keep password")

                        submit_unlock = st.form_submit_button("✅ Approve & Unlock Account", type="primary", use_container_width=True)
                        if submit_unlock:
                            try:
                                ok, r_msg = admin_resolve_request(sel_req_user, new_temp_pwd.strip() if new_temp_pwd.strip() else None)
                                if ok:
                                    st.success(f"✅ {r_msg}")
                                    trigger_unlock_refresh = True
                                else:
                                    st.error(f"❌ {r_msg}")
                            except Exception as e:
                                st.error(f"Database Error: {e}")
                else:
                    st.success("🟢 No pending lockout or password reset requests. All operator accounts are operational.")

                if trigger_unlock_refresh:
                    import time
                    time.sleep(0.2)
                    st.session_state['iam_refresh_tick'] = st.session_state.get('iam_refresh_tick', 0) + 1
                    try:
                        st.rerun(scope="app")
                    except TypeError:
                        st.rerun()

            # Fetch pending IAM requests for tab badge
            pending_requests = get_pending_iam_requests()
            req_tab_title = f"🔐 Pending Requests ({len(pending_requests)})" if pending_requests else "🔐 Pending Requests"

            tab_requests, tab_manage, tab_provision, tab_keys = st.tabs([req_tab_title, "👥 Manage Existing Users", "✨ Provision New User", "🔑 System Passkeys"])

            with tab_requests:
                _ = st.session_state.get('iam_refresh_tick', 0)
                render_iam_pending_requests()

            with tab_manage:
                trigger_role_refresh = False

                # Fetch fresh users directly from SQLite
                _manage_users = get_all_users()
                st.markdown("#### Modify User Role")
                st.caption(f"Role Capacity Quotas: **TESTER** ({count_users_by_role('tester')}/3 active) • **USER** ({count_users_by_role('user') + count_users_by_role('operator')}/5 active)")
                # Exclude SuperAdmin 'Amogh' from the editable selection list
                editable_users = [u[1] for u in _manage_users if u[1].lower() != "amogh"]

                if editable_users:
                    col_sel_user, col_sel_role, col_sel_btn = st.columns([2, 1.5, 1])
                    with col_sel_user:
                        selected_user = st.selectbox("Select User", editable_users, key="iam_sel_user")
                    with col_sel_role:
                        # Find current role for default index
                        curr_u_role = next((u[2] for u in _manage_users if u[1] == selected_user), "user")
                        role_opts = ["user", "admin", "tester", "blocked"]
                        default_idx = role_opts.index(curr_u_role) if curr_u_role in role_opts else 0
                        selected_new_role = st.selectbox("New Role", role_opts, index=default_idx, key="iam_sel_role")
                    with col_sel_btn:
                        st.markdown("<div style='margin-top:28px;'></div>", unsafe_allow_html=True)
                        if st.button("🔄 Update Role", type="primary", use_container_width=True, key="btn_iam_update"):
                            try:
                                ok, r_msg = update_user_role(selected_user, selected_new_role)
                                if ok:
                                    st.success(f"✅ {r_msg}")
                                    trigger_role_refresh = True
                                else:
                                    st.error(f"❌ {r_msg}")
                            except Exception as e:
                                st.error(f"Database Error: {e}")
                else:
                    st.info("No editable operator accounts found in directory.")

                if trigger_role_refresh:
                    import time
                    time.sleep(0.2)
                    st.session_state['iam_refresh_tick'] = st.session_state.get('iam_refresh_tick', 0) + 1
                    try:
                        st.rerun(scope="app")
                    except TypeError:
                        st.rerun()

                st.markdown("---")
                st.markdown("#### 📋 Live User Directory")
                # Direct inline re-fetch from SQLite on every render
                _live_directory_users = get_all_users()
                if _live_directory_users:
                    _dir_records = []
                    for _user_row in _live_directory_users:
                        _uid = _user_row[0]
                        _uname = _user_row[1]
                        _urole = _user_row[2] or "user"
                        _ucreated = _user_row[3]
                        _uattempts = _user_row[4] if len(_user_row) > 4 else 0
                        _ulocked = _user_row[5] if len(_user_row) > 5 else 0
                        _ureset = _user_row[6] if len(_user_row) > 6 else 0
                        _upasskey = _user_row[7] if len(_user_row) > 7 else None

                        _formatted_ts = format_user_timestamp(_ucreated)

                        if _uname.lower() == "amogh":
                            _status_str = "PROTECTED"
                        elif _ulocked == 1:
                            _status_str = "LOCKED"
                        elif _ureset == 1:
                            _status_str = "RESET REQUESTED"
                        elif str(_urole).lower() == "blocked":
                            _status_str = "REVOKED"
                        else:
                            _status_str = "ACTIVE"

                        _role_upper = str(_urole).strip().upper()
                        if _role_upper == "ADMIN" or _uname.lower() == "amogh":
                            _personal_key = "••••••••"
                        elif _role_upper == "TESTER":
                            _personal_key = _upasskey if (_upasskey and _upasskey != "temp_key_123") else "—"
                        else:
                            _personal_key = "—"

                        _dir_records.append({
                            "User ID": f"USR-{_uid:04d}",
                            "Username": _uname,
                            "Assigned Role": _role_upper,
                            "Failed Logins": _uattempts or 0,
                            "Status": _status_str,
                            "Personal Key": _personal_key,
                            "Created At": _formatted_ts
                        })
                    st.dataframe(pd.DataFrame(_dir_records), use_container_width=True)
                else:
                    st.info("User directory is currently empty.")

            with tab_provision:
                trigger_prov_refresh = False

                st.markdown("#### Provision New Account")
                st.caption(f"Create and assign roles to operator accounts directly from the SOC console. Active Quotas: **TESTER** ({count_users_by_role('tester')}/3) • **USER** ({count_users_by_role('user') + count_users_by_role('operator')}/5)")

                p_col1, p_col2 = st.columns(2)
                with p_col1:
                    prov_user = st.text_input("Username", key="prov_u_name", placeholder="e.g. jdoe_soc")
                    prov_pwd  = st.text_input("Temporary Password", type="password", key="prov_u_pwd", placeholder="At least 6 characters")
                with p_col2:
                    prov_role = st.selectbox("Initial Role", ["user", "admin", "tester", "blocked"], key="prov_u_role")
                    st.markdown("<div style='margin-top:28px;'></div>", unsafe_allow_html=True)
                    if st.button("✨ Provision Account", type="primary", use_container_width=True, key="btn_prov_submit"):
                        if not prov_user.strip() or not prov_pwd:
                            st.warning("Please provide both username and password.")
                        else:
                            try:
                                ok, p_msg = provision_manual_user(prov_user.strip(), prov_pwd, prov_role)
                                if ok:
                                    st.success(f"✅ {p_msg}")
                                    trigger_prov_refresh = True
                                else:
                                    st.error(f"❌ {p_msg}")
                            except Exception as e:
                                st.error(f"Database Error: {e}")

                if trigger_prov_refresh:
                    import time
                    time.sleep(0.2)
                    st.session_state['iam_refresh_tick'] = st.session_state.get('iam_refresh_tick', 0) + 1
                    try:
                        st.rerun(scope="app")
                    except TypeError:
                        st.rerun()

            with tab_keys:
                trigger_admin_key_refresh = False
                trigger_tester_key_refresh = False

                st.markdown("### 🔑 SOC Access Key Management")
                st.caption("Configure dynamic secondary verification passkeys for SuperAdmin and Individual Security Auditors.")

                col_k1, col_k2 = st.columns(2)
                with col_k1:
                    st.markdown("#### 🔐 Admin SOC Passkey")
                    st.caption("Master verification passkey required for SuperAdmin dashboard access.")
                    curr_admin_k = get_soc_key("soc_admin_key", "admin")
                    new_admin_k = st.text_input("New Admin Passkey", value=curr_admin_k, type="password", key="iam_edit_admin_key")
                    if st.button("💾 Update Admin Passkey", type="primary", use_container_width=True, key="btn_update_admin_key"):
                        if not new_admin_k.strip():
                            st.warning("Admin passkey cannot be empty.")
                        else:
                            try:
                                ok = update_soc_key("soc_admin_key", new_admin_k.strip())
                                if ok:
                                    st.success("✅ Admin Passkey updated successfully.")
                                    trigger_admin_key_refresh = True
                                else:
                                    st.error("❌ Failed to update Admin passkey.")
                            except Exception as e:
                                st.error(f"Database Error: {e}")

                with col_k2:
                    st.markdown("#### 🔬 Individual Security Auditor Keys")
                    st.caption("Manage personal access tokens (PAT) for each assigned Security Auditor.")

                    # Fetch all users with role 'tester' directly from database
                    fresh_users = get_all_users()
                    tester_users = [u[1] for u in fresh_users if str(u[2]).lower() == "tester"]

                    if not tester_users:
                        st.info("No active Security Auditors (TESTERs) to manage.")
                    else:
                        sel_tester = st.selectbox("Select Security Auditor", tester_users, key="iam_sel_tester_pat")
                        curr_tester_pat = get_user_passkey(sel_tester) or get_soc_key("soc_tester_key", "tester123")
                        new_tester_pat = st.text_input(f"Personal Access Key for {sel_tester}", value=curr_tester_pat, type="password", key=f"iam_edit_pat_{sel_tester}")
                        if st.button("💾 Update Personal Key", type="primary", use_container_width=True, key="btn_update_tester_pat"):
                            if not new_tester_pat.strip():
                                st.warning("Personal access key cannot be empty.")
                            else:
                                try:
                                    ok = update_user_passkey(sel_tester, new_tester_pat.strip())
                                    if ok:
                                        st.success(f"✅ Personal Access Key for '{sel_tester}' updated successfully.")
                                        trigger_tester_key_refresh = True
                                    else:
                                        st.error(f"❌ Failed to update personal key for '{sel_tester}'.")
                                except Exception as e:
                                    st.error(f"Database Error: {e}")

                if trigger_admin_key_refresh or trigger_tester_key_refresh:
                    import time
                    time.sleep(0.2)
                    st.session_state['iam_refresh_tick'] = st.session_state.get('iam_refresh_tick', 0) + 1
                    try:
                        st.rerun(scope="app")
                    except TypeError:
                        st.rerun()

    # ---------------- Live Database Admin Console (Admin Only) ----------------
    if st.session_state.get("role") == "admin":
        st.markdown("---")
        st.markdown("### 🗄️ Live Database Admin Console")
        st.caption("Execute raw SQL queries directly against the database. (Protected by DB Firewall Defense-in-Depth layer)")

        raw_query = st.text_input("Enter raw SQL Query (e.g., SELECT * FROM attack_logs LIMIT 5):")
        if st.button("Execute Query", type="primary"):
            if raw_query:
                try:
                    from db_firewall import DBFirewall
                    fw = DBFirewall()
                    # Send the live query from the UI directly to the DB Firewall
                    success, result = fw.execute_safe_query(raw_query)

                    if success:
                        st.success("✅ Query Executed Successfully (ALLOWED)")
                        if isinstance(result, list) and len(result) > 0:
                            st.dataframe(pd.DataFrame(result), use_container_width=True)
                        elif isinstance(result, list) and len(result) == 0:
                            st.info("Query returned 0 rows.")
                    else:
                        st.error(f"❌ DB FIREWALL BLOCKED: {result}")
                except Exception as e:
                    st.error(f"Execution Error: {e}")
            else:
                st.warning("Please enter a query to execute.")

    # Load logs
    df_logs = load_attack_logs()


    # Filters setup
    attack_type_options = ["All"]
    severity_options = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
    if not df_logs.empty:
        try:
            df_logs["timestamp"] = pd.to_datetime(df_logs["timestamp"], errors="coerce")
            date_min = df_logs['timestamp'].min().date()
            date_max = df_logs['timestamp'].max().date()
        except Exception as e:
            st.error(f"Error processing timestamps: {e}")
            date_min, date_max = None, None
        try:
            attack_type_options += sorted(df_logs["attack_type"].dropna().unique().tolist())
        except:
            pass
    else:
        date_min, date_max = None, None

    # Date range selector
    if date_min and date_max:
        selected_dates = st.sidebar.date_input("Select Date Range", [date_min, date_max])
        if len(selected_dates) == 2:
            start_date, end_date = selected_dates
            date_range = (pd.to_datetime(str(start_date)), pd.to_datetime(str(end_date)))
        else:
            date_range = None
    else:
        date_range = None

    attack_type_filter = st.sidebar.selectbox("Attack Type", attack_type_options)
    severity_filter = st.sidebar.selectbox("Severity", severity_options)
    request_search = st.sidebar.text_input("Search Request")

    # Move get_filtered_logs outside for clarity
    # Already done above

    filtered_df = get_filtered_logs(df_logs, attack_type_filter, severity_filter, date_range, request_search)

    # Metrics
    total_requests = len(df_logs)
    normal_labels = ["Normal", "LEGAL"]
    malicious_requests = len(df_logs[~df_logs["attack_type"].isin(normal_labels)]) if not df_logs.empty else 0
    safe_requests = len(df_logs[df_logs["attack_type"].isin(normal_labels)]) if not df_logs.empty else 0

    def safe_mean(series):
        return series.mean() if not series.empty and pd.notnull(series).any() else 0

    confidence_avg = safe_mean(df_logs["confidence"]) * 100 if "confidence" in df_logs.columns else 0
    threat_score_avg = safe_mean(df_logs["threat_score"]) if "threat_score" in df_logs.columns else 0
    prediction_time_avg = safe_mean(df_logs["prediction_time_ms"]) if "prediction_time_ms" in df_logs.columns else 0
    critical_count = len(df_logs[df_logs["severity"] == "CRITICAL"]) if "severity" in df_logs.columns else 0
    high_count = len(df_logs[df_logs["severity"] == "HIGH"]) if "severity" in df_logs.columns else 0
    medium_count = len(df_logs[df_logs["severity"] == "MEDIUM"]) if "severity" in df_logs.columns else 0
    low_count = len(df_logs[df_logs["severity"] == "LOW"]) if "severity" in df_logs.columns else 0

    # Show metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Requests", total_requests)
    col2.metric("Safe Requests", safe_requests)
    col3.metric("Malicious Requests", malicious_requests)
    col4.metric("Critical", critical_count)
    col5, col6, col7, col8 = st.columns(4)
    col5.metric("Confidence", f"{confidence_avg:.2f}%")
    col6.metric("Threat Score", f"{threat_score_avg:.2f}")
    col7.metric("Prediction Time", f"{prediction_time_avg:.2f} ms")
    col8.metric("High Severity", high_count)
    col9, col10 = st.columns(2)
    col9.metric("Medium", medium_count)
    col10.metric("Low", low_count)

    # ── Attack Type Distribution & Severity Distribution ─────────────────────
    # Render side-by-side as modern donut charts with dark-theme styling.
    _chart_col1, _chart_col2 = st.columns(2)

    # ── Attack Type Donut ─────────────────────────────────────────────────────
    with _chart_col1:
        if not df_logs.empty and "attack_type" in df_logs.columns:
            try:
                import plotly.graph_objects as go

                # ── STEP 1: Normalize labels — collapse historical naming variants ──
                # Map every known legacy/inconsistent label to its canonical display name
                # so duplicate slices never appear in the chart.
                _label_map = {
                    # Normal / legal traffic
                    "normal":       "Normal",
                    "LEGAL":        "Normal",
                    "legal":        "Normal",
                    # SQL Injection variants
                    "SQL":          "SQL Injection",
                    "sql":          "SQL Injection",
                    "sql_injection": "SQL Injection",
                    # XSS variants
                    "XSS":          "Cross Site Scripting",
                    "xss":          "Cross Site Scripting",
                    # Path Traversal / Shell variants
                    "SHELL":        "Path Traversal",
                    "shell":        "Path Traversal",
                    # Phishing variants
                    "PHISHING":     "Phishing URL",
                    "phishing":     "Phishing URL",
                    "phishing_link": "Phishing URL",
                }
                _normalized_col = (
                    df_logs["attack_type"]
                    .map(lambda v: _label_map.get(str(v), v))
                )

                # Data prep: bucket tiny slices (<2%) into "Other" to kill label clutter
                _atk_counts = _normalized_col.value_counts()
                _atk_total  = _atk_counts.sum()
                _threshold  = 0.02 * _atk_total
                _main_atk   = _atk_counts[_atk_counts >= _threshold]
                _other_sum  = _atk_counts[_atk_counts < _threshold].sum()
                if _other_sum > 0:
                    _main_atk = pd.concat([
                        _main_atk,
                        pd.Series({"Other": _other_sum})
                    ])

                _SOC_PALETTE = [
                    "#00E5FF", "#2563EB", "#7C3AED", "#EC4899",
                    "#F59E0B", "#10B981", "#EF4444", "#64748B",
                ]

                fig_attack = go.Figure(go.Pie(
                    labels=_main_atk.index.tolist(),
                    values=_main_atk.values.tolist(),
                    hole=0.45,
                    textinfo="label+percent",
                    textposition="inside",
                    insidetextorientation="radial",
                    marker=dict(
                        colors=_SOC_PALETTE[:len(_main_atk)],
                        line=dict(color="#0B1220", width=2),
                    ),
                    hovertemplate="<b>%{label}</b><br>Count: %{value}<br>Share: %{percent}<extra></extra>",
                ))
                fig_attack.update_layout(
                    title=dict(
                        text="Attack Type Distribution",
                        font=dict(color="white", size=16),
                        x=0.5,
                    ),
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="white", size=12),
                    legend=dict(
                        orientation="v",
                        x=1.02, xanchor="left",
                        y=0.5,  yanchor="middle",
                        font=dict(color="white", size=11),
                        bgcolor="rgba(0,0,0,0)",
                    ),
                    margin=dict(l=20, r=120, t=50, b=20),
                    annotations=[dict(
                        text=f"<b>{int(_atk_total)}</b><br>total",
                        x=0.5, y=0.5,
                        font=dict(size=15, color="white"),
                        showarrow=False,
                    )],
                )
                st.plotly_chart(fig_attack, use_container_width=True)
            except Exception as e:
                st.error(f"Chart Error: {e}")

    # ── Severity Distribution Donut ───────────────────────────────────────────
    with _chart_col2:
        if not df_logs.empty and "severity" in df_logs.columns:
            try:
                _SEV_COLORS = {
                    "CRITICAL": "#EF4444",
                    "HIGH":     "#F59E0B",
                    "MEDIUM":   "#3B82F6",
                    "LOW":      "#10B981",
                }
                _sev_counts = df_logs["severity"].value_counts()
                _sev_labels = _sev_counts.index.tolist()
                _sev_values = _sev_counts.values.tolist()
                _sev_colors = [_SEV_COLORS.get(lbl, "#64748B") for lbl in _sev_labels]

                fig_severity = go.Figure(go.Pie(
                    labels=_sev_labels,
                    values=_sev_values,
                    hole=0.45,
                    textinfo="label+percent",
                    textposition="inside",
                    insidetextorientation="radial",
                    marker=dict(
                        colors=_sev_colors,
                        line=dict(color="#0B1220", width=2),
                    ),
                    hovertemplate="<b>%{label}</b><br>Count: %{value}<br>Share: %{percent}<extra></extra>",
                ))
                fig_severity.update_layout(
                    title=dict(
                        text="Severity Distribution",
                        font=dict(color="white", size=16),
                        x=0.5,
                    ),
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="white", size=12),
                    legend=dict(
                        orientation="v",
                        x=1.02, xanchor="left",
                        y=0.5,  yanchor="middle",
                        font=dict(color="white", size=11),
                        bgcolor="rgba(0,0,0,0)",
                    ),
                    margin=dict(l=20, r=120, t=50, b=20),
                    annotations=[dict(
                        text=f"<b>{sum(_sev_values)}</b><br>total",
                        x=0.5, y=0.5,
                        font=dict(size=15, color="white"),
                        showarrow=False,
                    )],
                )
                st.plotly_chart(fig_severity, use_container_width=True)
            except Exception as e:
                st.error(f"Chart Error: {e}")

    # Attacks over time
    if not df_logs.empty:
        try:
            df_logs["timestamp"] = pd.to_datetime(df_logs["timestamp"], errors="coerce")
            df_logs = df_logs.dropna(subset=["timestamp"])
            df_logs['date'] = pd.DatetimeIndex(df_logs['timestamp']).date
            time_series = df_logs.groupby('date').size().reset_index(name='counts')
            fig_time = px.line(time_series, x='date', y='counts', title='Attacks Over Time')
            st.plotly_chart(fig_time)
        except Exception as e:
            st.error(f"Chart Error: {e}")

    # Histograms
    if "confidence" in df_logs.columns:
        try:
            fig_confidence = px.histogram(df_logs, x='confidence', nbins=20, title='Confidence Scores Distribution')
            st.plotly_chart(fig_confidence)
        except Exception as e:
            st.error(f"Chart Error: {e}")
    if "prediction_time_ms" in df_logs.columns:
        try:
            fig_pred_time = px.histogram(df_logs, x='prediction_time_ms', nbins=20, title='Prediction Time Distribution (ms)')
            st.plotly_chart(fig_pred_time)
        except Exception as e:
            st.error(f"Chart Error: {e}")

    # Threat Score by Attack Type
    if "attack_type" in df_logs.columns and "threat_score" in df_logs.columns:
        try:
            threat_by_type = df_logs.groupby('attack_type')['threat_score'].mean().reset_index()
            fig_threat = px.bar(
                threat_by_type,
                x='attack_type',
                y='threat_score',
                title='Average Threat Score by Attack Type'
            )
            st.plotly_chart(fig_threat)
        except Exception as e:
            st.error(f"Chart Error: {e}")

    # Helper for non-blocking Live Attack Logs polling
    @st.fragment(run_every="5s")
    def render_live_attack_logs(attack_type="All", severity="All", dates=None, search_query=""):
        _ = st.session_state.get('iam_refresh_tick', 0)
        df_current_logs = load_attack_logs()
        filtered_current_df = get_filtered_logs(df_current_logs, attack_type, severity, dates, search_query)

        display_cols = ['timestamp', 'request', 'attack_type', 'confidence', 'severity', 'threat_score', 'prediction_time_ms']
        for col in display_cols:
            if col not in filtered_current_df.columns:
                filtered_current_df[col] = ''

        st.subheader("Live Attack Logs")
        st.caption("Real-time telemetry stream (Auto-refreshes every 5s)")

        if not filtered_current_df.empty:
            st.dataframe(filtered_current_df[display_cols].sort_values(by='timestamp', ascending=False), use_container_width=True)
            csv_data = filtered_current_df.to_csv(index=False).encode("utf-8")
            st.download_button("Download Attack Logs as CSV", data=csv_data, file_name="attack_logs.csv", mime="text/csv", key="btn_dl_logs_csv")
        else:
            st.info("No matching attack logs found.")

    _ = st.session_state.get('iam_refresh_tick', 0)
    render_live_attack_logs(attack_type_filter, severity_filter, date_range, request_search)

    # Attack Map (simulated)
    countries = [
        ("USA", 37.0902, -95.7129),
        ("Russia", 61.5240, 105.3188),
        ("China", 35.8617, 104.1954),
        ("India", 20.5937, 78.9629),
        ("Germany", 51.1657, 10.4515),
        ("Brazil", -14.2350, -51.9253),
        ("UK", 55.3781, -3.4360),
        ("Canada", 56.1304, -106.3468)
    ]
    attack_map_data = []
    for _, row in filtered_df.iterrows():
        if row["attack_type"] not in ["Normal", "LEGAL"]:
            country = random.choice(countries)
            attack_map_data.append({
                "country": country[0],
                "lat": country[1],
                "lon": country[2],
                "attack": row["attack_type"]
            })
    if attack_map_data:
        df_map = pd.DataFrame(attack_map_data)
        try:
            fig_map = px.scatter_geo(
                df_map,
                lat="lat",
                lon="lon",
                color="attack",
                hover_name="country",
                projection="natural earth"
            )
            fig_map.update_traces(marker=dict(size=14, opacity=0.9))
            st.plotly_chart(fig_map)
        except Exception as e:
            st.error(f"Map Chart Error: {e}")
    else:
        st.info("No malicious attacks recorded yet.")

    # ---------------- DB Firewall Events ----------------
    st.markdown("---")
    st.markdown("### 🛡️ Database Request Firewall Events")
    try:
        from db_firewall import DBFirewall
        fw = DBFirewall()
        success, firewall_logs = fw.execute_safe_query("SELECT timestamp, query, block_reason FROM db_firewall_logs ORDER BY id DESC LIMIT 10")

        if success and firewall_logs:
            df_fw = pd.DataFrame(firewall_logs, columns=["Timestamp", "Blocked Query", "Block Reason"])
            st.dataframe(df_fw, use_container_width=True)
        else:
            st.success("No malicious database requests detected. DB Firewall is active and monitoring.")
    except Exception as e:
        st.error(f"Could not load DB Firewall logs: {e}")

    # ---------------- WAF Rate Limiter Events ----------------
    st.markdown("---")
    st.markdown("### 🚦 WAF Rate Limiter Events")
    st.caption(
        f"Clients are limited to **5 requests / 10 seconds**. "
        "Entries below indicate suspected DoS / Brute-Force attempts blocked at the WAF layer."
    )
    try:
        import sqlite3 as _sl
        _rl_conn = _sl.connect(str(DB_PATH))
        _rl_cur  = _rl_conn.cursor()

        # Check table exists before querying (table is created by waf_server.py on first run)
        _rl_cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='waf_rate_limit_logs'"
        )
        _table_exists = _rl_cur.fetchone()

        if _table_exists:
            _rl_cur.execute(
                "SELECT timestamp, client_ip, path, req_count "
                "FROM waf_rate_limit_logs ORDER BY id DESC LIMIT 10"
            )
            _rl_rows = _rl_cur.fetchall()
            _rl_conn.close()

            if _rl_rows:
                df_rl = pd.DataFrame(
                    _rl_rows,
                    columns=["Timestamp", "Client IP", "Requested Path", "Request Count"]
                )
                st.error(
                    f"⚠️ {len(_rl_rows)} rate-limit block event(s) detected. "
                    "Review the table below for suspected DoS/Brute-Force sources."
                )
                st.dataframe(df_rl, use_container_width=True)
            else:
                st.success("No rate-limit violations detected. WAF Rate Limiter is active.")
        else:
            _rl_conn.close()
            st.info(
                "WAF Rate Limiter is configured (5 req/10 s). "
                "Start `waf_server.py` to activate live DoS protection and populate this log."
            )
    except Exception as e:
        st.error(f"Could not load WAF Rate Limiter logs: {e}")

    # ============================================================================
    # 🚨 Level 2: Quarantine & Unknown Threat Management
    # ============================================================================
    st.markdown("---")
    if st.session_state.get("role") == "admin":
        st.markdown("""
        <div style="
            background:linear-gradient(135deg,#1a0a2e,#2d1050);
            border:1.5px solid #7c3aed;
            border-radius:16px;
            padding:20px 26px;
            margin-bottom:18px;
            box-shadow:0 0 28px rgba(124,58,237,0.2);
        ">
            <div style="font-size:24px;font-weight:700;color:#a78bfa;margin-bottom:6px;">
                🚨 Level 2: Quarantine &amp; Unknown Threat Management
            </div>
            <div style="color:#c4b5fd;font-size:14px;">
                Elevated privileges required. Request a Dynamic OTP to unlock this panel.
                The OTP is delivered to the secure backend terminal — never stored in the UI.
            </div>
        </div>
        """, unsafe_allow_html=True)

        # ── OTP lifecycle via session_state ────────────────────────────────────
        if "admin_otp" not in st.session_state:
            st.session_state["admin_otp"] = None
        if "otp_granted" not in st.session_state:
            st.session_state["otp_granted"] = False

        # ── Step 1: Request OTP button ──────────────────────────────────────────
        col_otp_btn, col_otp_status = st.columns([1, 3])
        with col_otp_btn:
            if st.button(
                "🔐 Request Elevated Access OTP",
                use_container_width=True,
                help="Generates a one-time 6-digit code printed to the secure backend terminal"
            ):
                otp = random.randint(100000, 999999)
                st.session_state["admin_otp"] = str(otp)
                st.session_state["otp_granted"] = False   # reset on new OTP
                # Simulate secure gateway: print to backend terminal only
                print(f"\n{'='*55}")
                print(f"  [SECURE SYSTEM LOG] 🛡️  Elevated Access OTP Generated: {otp}")
                print(f"  Issued at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"{'='*55}\n")
                st.toast("✅ OTP sent to secure admin terminal.", icon="🔐")

        with col_otp_status:
            if st.session_state["admin_otp"] is not None:
                st.markdown(
                    """
                    <div style="
                        background:#1a1a2e;
                        border:1px solid #7c3aed;
                        border-radius:10px;
                        padding:10px 16px;
                        color:#c4b5fd;
                        font-size:13px;
                        margin-top:2px;
                    ">
                        🟡 &nbsp;<b>OTP active</b> — check your backend terminal, then enter it below.
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    """
                    <div style="
                        background:#1a1030;
                        border:1px solid #5b21b6;
                        border-radius:10px;
                        padding:10px 16px;
                        color:#94a3b8;
                        font-size:13px;
                        margin-top:2px;
                    ">
                        🔒 &nbsp;No active OTP — click <b>Request Elevated Access OTP</b> to begin.
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        st.markdown("<div style='margin-top:12px;'></div>", unsafe_allow_html=True)

        # ── Step 2: OTP verification input ────────────────────────────────────
        entered_otp = st.text_input(
            "🔑 Enter 6-digit Dynamic OTP",
            type="password",
            key="elevated_otp_input",
            placeholder="Enter the OTP from your secure backend terminal",
            max_chars=6,
        )

        if entered_otp:
            if st.session_state["admin_otp"] is None:
                st.warning("⚠️ No OTP has been generated yet. Click **Request Elevated Access OTP** first.")
            elif entered_otp == st.session_state["admin_otp"]:
                st.session_state["otp_granted"] = True
            else:
                st.session_state["otp_granted"] = False
                st.markdown(
                    """
                    <div style="
                        background:#2d0a0a;
                        border:1px solid #ef4444;
                        border-radius:10px;
                        padding:12px 18px;
                        color:#fca5a5;
                        font-size:14px;
                    ">
                        ❌ <b>Incorrect OTP.</b> Access denied. Request a new OTP if needed.
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        # ── Step 3: Render panel or locked state ────────────────────────────────
        if st.session_state["otp_granted"]:
            st.markdown(
                """
                <div style="
                    background:#0d2416;
                    border:1px solid #16a34a;
                    border-radius:10px;
                    padding:12px 18px;
                    color:#4ade80;
                    font-size:14px;
                    margin-bottom:14px;
                ">
                    ✅ <b>Elevated Access Granted</b> — Dynamic OTP verified. Quarantine Management Panel Active.
                </div>
                """,
                unsafe_allow_html=True,
            )
            quarantine.render_quarantine_ui()
        elif not entered_otp:
            st.markdown(
                """
                <div style="
                    background:#1a1030;
                    border:1px solid #5b21b6;
                    border-radius:10px;
                    padding:14px 18px;
                    color:#c4b5fd;
                    font-size:14px;
                    margin-top:8px;
                ">
                    🔒 <b>Elevated permissions required</b> to manage quarantined payloads.
                    Request an OTP and enter it above to proceed.
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.warning("🔒 Level 2 Quarantine & Unknown Threat Management requires Administrator privileges. Your current role (TESTER) is restricted to read-only analytics.")



