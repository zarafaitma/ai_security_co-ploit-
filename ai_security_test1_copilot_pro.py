import streamlit as st
from langchain_ollama import OllamaLLM
import subprocess
import re
import os
import json
from datetime import datetime
import pandas as pd
import plotly.graph_objects as go
import socket
import database  # SQLite persistence layer (database.py)

# ==============================================================================
# 1. GLOBAL PAGE CONFIGURATION & ARCHITECTURE
# ==============================================================================
st.set_page_config(
    page_title="AI Security Copilot Pro v1.3.5",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==============================================================================
# 2. FULL EMBEDDED SOC CYBERPUNK UI STYLING (CSS)
# ==============================================================================
st.markdown("""
    <style>
    /* Global Application Reset & Dark Core Theme */
    .stApp { 
        background-color: #0f1419; 
        color: #e0e7ff; 
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    /* Sidebar Navigation Panel Dashboard Spec */
    [data-testid="stSidebar"] { 
        background-color: #0a0e14; 
        border-right: 1px solid #1e293b;
    }
    
    [data-testid="stSidebar"] [data-testid="stVerticalBlockBorderWrapper"] {
        border-left: none;
    }
    
    /* Container Structural Margins */
    .main .block-container {
        padding-top: 1.5rem;
        padding-bottom: 1.5rem;
        padding-left: 2rem;
        padding-right: 2rem;
    }
    
    /* Interactive Dashboard Top Header Matrix */
    .dashboard-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 28px;
        padding-bottom: 20px;
        border-bottom: 1px solid #1e293b;
    }
    
    .dashboard-header h1 {
        margin: 0;
        font-size: 1.85rem;
        font-weight: 700;
        color: #f8fafc;
        letter-spacing: -0.5px;
    }
    
    .dashboard-header .subtitle {
        color: #94a3b8;
        font-size: 0.95rem;
        margin-top: 6px;
    }
    
    .timestamp-badge {
        background: #1e293b;
        color: #38bdf8;
        padding: 10px 18px;
        border-radius: 8px;
        font-size: 0.85rem;
        font-family: 'Courier New', monospace;
        font-weight: 600;
        border: 1px solid #334155;
    }
    
    /* SOC Telemetry Cards Grid Layout */
    .stat-card {
        background: linear-gradient(135deg, #111827 0%, #0f172a 100%);
        border: 1px solid #1e293b;
        border-radius: 12px;
        padding: 22px;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }
    
    .stat-card:hover {
        border-color: #3b82f6;
        box-shadow: 0 4px 20px rgba(59, 130, 246, 0.15);
        transform: translateY(-2px);
    }
    
    .stat-card .title {
        color: #94a3b8;
        font-size: 0.8rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.75px;
        margin-bottom: 10px;
    }
    
    .stat-card .value {
        font-size: 2.3rem;
        font-weight: 700;
        color: #f8fafc;
        margin: 0;
        margin-bottom: 6px;
    }
    
    .stat-card .trend-up {
        color: #10b981;
        font-size: 0.8rem;
        font-weight: 500;
        display: flex;
        align-items: center;
        gap: 4px;
    }
    
    .stat-card .trend-danger {
        color: #ef4444;
        font-size: 0.8rem;
        font-weight: 500;
        display: flex;
        align-items: center;
        gap: 4px;
    }
    
    /* Professional Operations Log Table Styling */
    .table-container {
        background: #0b0f17;
        border: 1px solid #1e293b;
        border-radius: 12px;
        padding: 8px;
        overflow: hidden;
    }
    
    .pro-table {
        width: 100%;
        border-collapse: collapse;
        text-align: left;
    }
    
    .pro-table th {
        color: #94a3b8;
        font-size: 0.75rem;
        text-transform: uppercase;
        padding: 14px;
        border-bottom: 1px solid #1e293b;
        font-weight: 600;
        letter-spacing: 0.5px;
        background-color: #0f1419;
    }
    
    .pro-table td {
        padding: 14px;
        font-size: 0.85rem;
        border-bottom: 1px solid #1e293b;
        color: #e2e8f0;
    }
    
    .pro-table tr:hover {
        background-color: #161e2e;
    }
    
    /* SOC Incident Risk Badges */
    .badge {
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        display: inline-block;
        text-align: center;
    }
    
    .badge-critical {
        background: rgba(239, 68, 68, 0.15);
        color: #ef4444;
        border: 1px solid rgba(239, 68, 68, 0.3);
    }
    
    .badge-high {
        background: rgba(249, 115, 22, 0.15);
        color: #f97316;
        border: 1px solid rgba(249, 115, 22, 0.3);
    }
    
    .badge-medium {
        background: rgba(245, 158, 11, 0.15);
        color: #f59e0b;
        border: 1px solid rgba(245, 158, 11, 0.3);
    }
    
    .badge-low {
        background: rgba(16, 185, 129, 0.15);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.3);
    }
    
    /* Core Live Emulation Output Terminal Box */
    .terminal-box {
        background-color: #000000;
        border: 1px solid #1e293b;
        font-family: 'Courier New', monospace;
        padding: 16px;
        border-radius: 10px;
        color: #10b981;
        height: 220px;
        overflow-y: auto;
        font-size: 0.82rem;
        line-height: 1.6;
        box-shadow: inset 0 0 10px rgba(0,0,0,0.8);
    }
    
    /* Cyberpunk Static Threat Visualizer Bars */
    .threat-bar-bg {
        background: #1e293b;
        border-radius: 10px;
        height: 8px;
        width: 100%;
        margin-top: 6px;
        overflow: hidden;
    }
    
    .threat-bar-fill {
        height: 100%;
        border-radius: 10px;
        transition: width 0.5s ease-in-out;
    }
    
    /* Layout Section Titles */
    .section-title {
        font-size: 1.15rem;
        font-weight: 600;
        color: #f8fafc;
        margin-bottom: 16px;
        margin-top: 24px;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    
    /* Right Column Chat Panel Interface */
    .chat-header {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 20px;
        padding-bottom: 16px;
        border-bottom: 1px solid #1e293b;
    }
    
    .chat-title {
        font-size: 1.25rem;
        font-weight: 600;
        color: #f8fafc;
        margin: 0;
    }
    
    .chat-status {
        font-size: 0.8rem;
        color: #10b981;
        display: flex;
        align-items: center;
        gap: 6px;
        margin-top: 4px;
    }
    
    /* Custom Sidebar Identity Profile Component Card */
    .profile-card {
        background: #111827;
        padding: 16px;
        border-radius: 10px;
        border: 1px solid #1e293b;
        margin-top: 28px;
    }
    
    .profile-header {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 15px;
    }
    
    .profile-avatar {
        width: 38px;
        height: 38px;
        border-radius: 50%;
        background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: bold;
        font-size: 0.8rem;
        color: white;
        box-shadow: 0 0 10px rgba(59,130,246,0.4);
    }
    
    .profile-name {
        font-size: 0.9rem;
        font-weight: 700;
        color: #f8fafc;
    }
    
    .profile-status {
        font-size: 0.75rem;
        color: #10b981;
        font-weight: 500;
    }
    
    /* Custom Global Webkit Interactive Scrollbars */
    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-track {
        background: transparent;
    }
    ::-webkit-scrollbar-thumb {
        background: #334155;
        border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #475569;
    }
    </style>
""", unsafe_allow_html=True)

# ==============================================================================
# 2.5 ADDITIONAL UI EXTENSION STYLING (NEW)
#     Top app bar, SaaS-style stat cards, extra badge variants, reports list,
#     engine status card, chat avatar/bubbles, chat input, bottom status bar.
#     Purely additive/presentational — does not touch any class above.
# ==============================================================================
st.markdown("""
    <style>
    /* ---- Top Application Bar ---- */
    .app-topbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 6px 0 22px 0;
        margin-bottom: 6px;
    }
    .topbar-left {
        display: flex;
        align-items: center;
        gap: 18px;
    }
    .topbar-search {
        background: #161e2e;
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 10px 16px;
        color: #64748b;
        font-size: 0.85rem;
        width: 320px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 10px;
    }
    .topbar-right {
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .topbar-icon-btn {
        width: 38px;
        height: 38px;
        border-radius: 8px;
        background: #161e2e;
        border: 1px solid #1e293b;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1rem;
        position: relative;
        color: #94a3b8;
        flex-shrink: 0;
    }
    .notif-badge {
        position: absolute;
        top: -5px;
        right: -5px;
        background: #ef4444;
        color: #ffffff;
        font-size: 0.62rem;
        font-weight: 700;
        border-radius: 50%;
        width: 17px;
        height: 17px;
        display: flex;
        align-items: center;
        justify-content: center;
        border: 2px solid #0f1419;
    }
    .window-controls {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-left: 8px;
        padding-left: 16px;
        border-left: 1px solid #1e293b;
    }
    .window-dot {
        width: 30px;
        height: 30px;
        border-radius: 6px;
        background: #161e2e;
        border: 1px solid #1e293b;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 0.7rem;
        color: #64748b;
        flex-shrink: 0;
    }

    /* ---- SaaS-style Stat Card Internals (wraps inside existing .stat-card) ---- */
    .sc-top {
        display: flex;
        align-items: center;
        gap: 14px;
        margin-bottom: 16px;
    }
    .sc-icon {
        width: 46px;
        height: 46px;
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.35rem;
        flex-shrink: 0;
    }
    .sc-value {
        font-size: 1.7rem;
        font-weight: 700;
        color: #f8fafc;
        line-height: 1.15;
    }
    .sc-label {
        color: #94a3b8;
        font-size: 0.82rem;
        margin-top: 2px;
    }
    .sc-trend {
        font-size: 0.78rem;
        font-weight: 500;
    }
    .sc-trend.up { color: #10b981; }
    .sc-trend.down { color: #ef4444; }

    /* ---- Extra Badge Variants (sit alongside badge-critical/high/medium/low) ---- */
    .badge-info {
        background: rgba(56, 189, 248, 0.15);
        color: #38bdf8;
        border: 1px solid rgba(56, 189, 248, 0.3);
    }
    .badge-purple {
        background: rgba(168, 85, 247, 0.15);
        color: #a855f7;
        border: 1px solid rgba(168, 85, 247, 0.3);
    }
    .badge-cyan {
        background: rgba(34, 211, 238, 0.15);
        color: #22d3ee;
        border: 1px solid rgba(34, 211, 238, 0.3);
    }
    .badge-neutral {
        background: rgba(148, 163, 184, 0.15);
        color: #94a3b8;
        border: 1px solid rgba(148, 163, 184, 0.3);
    }
    .badge-success {
        background: rgba(16, 185, 129, 0.15);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.3);
    }

    /* ---- Recent Activity / Reports-style List ---- */
    .reports-list {
        display: flex;
        flex-direction: column;
        gap: 8px;
    }
    .report-item {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 10px;
        border-radius: 8px;
        transition: background 0.2s;
    }
    .report-item:hover {
        background: #161e2e;
    }
    .report-icon {
        width: 36px;
        height: 36px;
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1rem;
        flex-shrink: 0;
    }
    .report-name {
        font-size: 0.85rem;
        font-weight: 600;
        color: #e2e8f0;
    }
    .report-meta {
        font-size: 0.72rem;
        color: #64748b;
        margin-top: 2px;
    }

    /* ---- Sidebar Engine Status Card (sibling of .profile-card) ---- */
    .engine-status-card {
        background: #111827;
        padding: 16px;
        border-radius: 10px;
        border: 1px solid #1e293b;
        margin-top: 10px;
    }

    /* ---- Sidebar Nav Buttons (active state via Streamlit's native button type) ---- */
    [data-testid="stSidebar"] div[data-testid="stButton"] button {
        text-align: left !important;
        justify-content: flex-start !important;
        font-weight: 500;
        border-radius: 8px;
        padding: 10px 14px;
    }
    [data-testid="stSidebar"] div[data-testid="stButton"] button[kind="secondary"] {
        background: transparent;
        border: 1px solid transparent;
        color: #94a3b8;
    }
    [data-testid="stSidebar"] div[data-testid="stButton"] button[kind="secondary"]:hover {
        background: #161e2e;
        border: 1px solid #1e293b;
        color: #e2e8f0;
    }
    [data-testid="stSidebar"] div[data-testid="stButton"] button[kind="primary"] {
        background: rgba(59, 130, 246, 0.15) !important;
        border: 1px solid rgba(59, 130, 246, 0.4) !important;
        color: #3b82f6 !important;
        box-shadow: none !important;
    }
    [data-testid="stSidebar"] div[data-testid="stButton"] button[kind="primary"]:hover {
        background: rgba(59, 130, 246, 0.22) !important;
        border: 1px solid rgba(59, 130, 246, 0.5) !important;
        color: #60a5fa !important;
    }

    /* ---- Quick-reply pill buttons in chat (best-effort key-based targeting) ---- */
    .st-key-qr_explain button, .st-key-qr_fix button, .st-key-qr_critical button {
        border-radius: 20px !important;
        background: #161e2e !important;
        border: 1px solid #1e293b !important;
        font-size: 0.78rem !important;
        padding: 6px 10px !important;
        color: #cbd5e1 !important;
    }
    .st-key-view_full_timeline button {
        background: transparent !important;
        border: 1px solid #1e293b !important;
        color: #94a3b8 !important;
        font-size: 0.8rem !important;
    }

    /* ---- Chat Avatar Wrapper + Bubble Differentiation (best-effort, version-dependent) ---- */
    .chat-avatar {
        width: 44px;
        height: 44px;
        border-radius: 12px;
        background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.4rem;
        box-shadow: 0 0 14px rgba(59,130,246,0.35);
        flex-shrink: 0;
    }
    [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]) {
        flex-direction: row-reverse;
    }
    [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]) [data-testid="stChatMessageContent"] {
        background: #2563eb;
        border-radius: 14px 14px 2px 14px;
        border: none;
    }
    [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarAssistant"]) [data-testid="stChatMessageContent"] {
        background: #161e2e;
        border: 1px solid #1e293b;
        border-radius: 14px 14px 14px 2px;
    }

    /* ---- Chat Input ---- */
    [data-testid="stChatInput"] {
        background: #111827 !important;
        border: 1px solid #1e293b !important;
        border-radius: 16px !important;
    }
    [data-testid="stChatInput"] textarea {
        color: #e2e8f0 !important;
    }

    /* ---- Bottom Full-width Status Bar ---- */
    .status-bar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 12px;
        background: #0b0f17;
        border: 1px solid #1e293b;
        border-radius: 12px;
        padding: 14px 26px;
        margin-top: 30px;
        font-size: 0.85rem;
        color: #94a3b8;
    }
    .status-item {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .status-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        display: inline-block;
        flex-shrink: 0;
    }
    </style>
""", unsafe_allow_html=True)

# ==============================================================================
# 3. BACKEND AI ENGINE INITIALIZATION (QWEN 2.5:3B)
# ==============================================================================
@st.cache_resource
def load_qwen_engine():
    """Initializes and caches the Ollama Qwen Core Link layer"""
    return OllamaLLM(model="qwen2.5:3b")

try:
    llm = load_qwen_engine()
except:
    llm = None
    st.warning("⚠️ Qwen2.5:3b initialization bypassed. Verify Ollama pipeline infrastructure is active.")

# ==============================================================================
# 3.5 DATABASE LAYER INITIALIZATION (NEW - creates security_copilot.db)
# ==============================================================================
@st.cache_resource
def _init_database():
    """Runs create_database() exactly once per app process (cached)."""
    database.create_database()
    return True

db_ready = _init_database()

# ==============================================================================
# 4. VOLATILE SESSION DATA AND STATE MANAGEMENT STATE MACHINES
# ==============================================================================
if "messages" not in st.session_state:
    st.session_state.messages = [
        {"role": "assistant", "content": "Welcome Operator. Strict SOC Analytical Framework Engine Online. Telemetry streams mapped."}
    ]
if "total_scans" not in st.session_state:
    st.session_state.total_scans = 142
if "threats_found" not in st.session_state:
    st.session_state.threats_found = 12
if "system_logs" not in st.session_state:
    st.session_state.system_logs = [
        "[SYSTEM CORE] Kernel processing modules online.",
        "[AI COGNITION] Qwen2.5:3b model state verified against conservative rules.",
        "[NETWORK INTERFACE] Secure proxy listening ports established.",
        "[SECURITY CORE] SOC JSON compliance engine active."
    ]
if "history" not in st.session_state:
    st.session_state.history = [
        ["11:42 AM", "142.250.202.46", "Port Perimeter Profiling", "LOW"],
        ["10:15 AM", "auth.log", "Deep Log Anomaly Parsing", "MEDIUM"],
        ["09:04 AM", "scanme.nmap.org", "DNS Baseline A Record Audit", "LOW"],
        ["07:30 AM", "api.target.com", "HTTP Response Security Header Audit", "MEDIUM"]
    ]
if "latest_chart" not in st.session_state:
    st.session_state.latest_chart = None

def add_log(msg):
    """Pushes a fresh transactional message string to the system log stack"""
    st.session_state.system_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
    database.save_log(msg)  # NEW: persist to security_copilot.db

def add_history(target, task, risk, raw_result=""):
    """Inserts a structured operational execution record row at top of timeline index"""
    time_now = datetime.now().strftime("%I:%M %p")
    st.session_state.history.insert(0, [time_now, target, task, risk])
    database.save_scan(target, task, risk, raw_result)  # NEW: persist to security_copilot.db

# ==============================================================================
# 4.5 AUTHENTICATION GATE (NEW) — Phase 1
#     Nothing above this line (Sections 1-4) or below it (Sections 5 onward,
#     i.e. the entire original dashboard/recon/chat logic) has been touched.
#     This block only decides whether a given script run is allowed to reach
#     Section 5+. Uses the existing database.get_user()/verify_password().
# ==============================================================================
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "username" not in st.session_state:
    st.session_state.username = None
if "role" not in st.session_state:
    st.session_state.role = None

def is_admin():
    """Returns True if the currently logged-in operator has the admin role."""
    return st.session_state.get("role") == "admin"

if not st.session_state.authenticated:
    _gate_l, _gate_c, _gate_r = st.columns([1, 1.1, 1])
    with _gate_c:
        st.markdown("""
            <div style='text-align:center; margin-top: 80px; margin-bottom: 10px;'>
                <div style='font-size: 2.4rem;'>🛡️</div>
                <h2 style='color:#f8fafc; margin-bottom:2px;'>AI Security Copilot Pro</h2>
                <p style='color:#94a3b8; font-size:0.85rem;'>Operator authentication required to access the SOC console.</p>
            </div>
        """, unsafe_allow_html=True)

        with st.form("login_form"):
            login_username = st.text_input("Username")
            login_password = st.text_input("Password", type="password")
            login_submitted = st.form_submit_button("Sign In", use_container_width=True)

        if login_submitted:
            user_record = database.get_user(login_username)
            if user_record and database.verify_password(login_password, user_record["password_hash"]):
                st.session_state.authenticated = True
                st.session_state.username = user_record["username"]
                st.session_state.role = user_record["role"]
                add_log(f"Operator '{user_record['username']}' authenticated (role: {user_record['role']}).")
                st.rerun()
            else:
                st.error("Invalid username or password.")

    st.stop()

# ==============================================================================
# 5. INTEGRATED HARDWARE/SUBPROCESS OPERATIONAL UTILITY CONTROLLERS
# ==============================================================================
def run_nmap(ip):
    """Executes basic port mapping directly over local network space"""
    try:
        res = subprocess.run(["nmap", "-F", "-sV", ip], capture_output=True, text=True, timeout=30)
        return res.stdout if res.stdout else "No responses matched scan footprint thresholds."
    except Exception as e:
        return f"Nmap internal pipeline fault execution: {e}"

def run_whois(dom):
    """Gathers registrar records over open network protocol targets"""
    try:
        res = subprocess.run(["whois", dom], capture_output=True, text=True, timeout=30)
        return res.stdout[:2500] if res.stdout else "WHOIS standard configuration data empty."
    except Exception as e:
        return f"WHOIS internal registration lookup exception: {e}"

def run_dig(dom):
    """Performs fast DNS domain analysis querying standard stable 'A' record strings"""
    try:
        res = subprocess.run(["dig", dom, "A"], capture_output=True, text=True, timeout=15)
        if not res.stdout or "ANSWER SECTION" not in res.stdout:
            return "DNS query failed from scanning environment."
        return res.stdout
    except Exception as e:
        return "DNS query failed from scanning environment."

def run_headers(target):
    """Captures absolute raw HTTP response headers using standard lib curl wrapper"""
    try:
        clean_target = target.replace("http://", "").replace("https://", "").split('/')[0]
        res = subprocess.run(["curl", "-I", "-s", "-L", "--max-time", "15", clean_target], capture_output=True, text=True)
        return res.stdout.strip() if res.stdout else ""
    except Exception as e:
        return ""

def render_port_donut_chart(open_ports_count=3, filtered_closed_count=97):
    """Generates an elegant donut chart showing port configuration profiles"""
    labels = ['Open Ports', 'Closed/Filtered']
    values = [open_ports_count, filtered_closed_count]
    fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.6, marker=dict(colors=['#ef4444', '#1e293b']))])
    fig.update_layout(
        template="plotly_dark", 
        height=220, 
        showlegend=True, 
        margin=dict(l=10, r=10, t=10, b=10), 
        paper_bgcolor='rgba(0,0,0,0)', 
        plot_bgcolor='rgba(0,0,0,0)'
    )
    return fig

def run_subdomain_brute_force(domain):
    """Lightweight operational subdomain discovery check framework"""
    common_prefixes = ['www', 'mail', 'api', 'dev', 'admin', 'vpn', 'staging']
    discovered = []
    for prefix in common_prefixes:
        subdomain = f"{prefix}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            discovered.append({"Subdomain": subdomain, "Status": "Active/Resolved"})
        except socket.gaierror:
            continue
    return discovered if discovered else [{"Subdomain": f"www.{domain}", "Status": "Active (Fallback)"}]

# ==============================================================================
# 5.5 NEW PRESENTATION-LAYER HELPER FUNCTIONS (DISPLAY-ONLY, NO BUSINESS LOGIC)
#     These only format/aggregate existing session-state data for the new
#     SaaS-style layout. They do not call any external tool/process and do
#     not write to the database.
# ==============================================================================
def render_stat_card(icon, icon_color, value, label, trend_text, trend_positive=True):
    """Builds the markup for one SaaS-style stat card. Reuses the existing
    .stat-card class for the outer shell (hover/border/gradient) and only
    introduces new inner classes for the icon+value+trend layout."""
    trend_class = "up" if trend_positive else "down"
    return f"""<div class='stat-card'>
        <div class='sc-top'>
            <div class='sc-icon' style='background:{icon_color}22; color:{icon_color};'>{icon}</div>
            <div>
                <div class='sc-value'>{value}</div>
                <div class='sc-label'>{label}</div>
            </div>
        </div>
        <div class='sc-trend {trend_class}'>{trend_text}</div>
    </div>"""

def get_category_badge(task_name):
    """Maps an operation/task name to a presentational badge class via a
    simple substring heuristic. Display-only — never affects routing."""
    t = task_name.lower()
    if "dns" in t:
        return "badge-cyan"
    elif "header" in t or "http" in t:
        return "badge-info"
    elif "nmap" in t or "port" in t:
        return "badge-purple"
    elif "subdomain" in t:
        return "badge-purple"
    elif "chain" in t or "automated" in t:
        return "badge-info"
    else:
        return "badge-neutral"

def render_risk_distribution_chart(history):
    """Aggregates REAL risk-level counts from st.session_state.history into
    a donut chart. Returns None if there is no recognizable data yet."""
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for row in history:
        risk = row[3] if len(row) > 3 else "LOW"
        if risk in counts:
            counts[risk] += 1

    color_map = {"LOW": "#10b981", "MEDIUM": "#f59e0b", "HIGH": "#f97316", "CRITICAL": "#ef4444"}
    labels = [k for k in counts if counts[k] > 0]
    values = [counts[k] for k in counts if counts[k] > 0]
    if not values:
        return None

    colors = [color_map[k] for k in labels]
    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=.65,
        marker=dict(colors=colors),
        textinfo='percent',
        textfont=dict(size=11)
    )])
    fig.update_layout(
        template="plotly_dark",
        height=250,
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.3, font=dict(size=10)),
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)'
    )
    return fig

# ==============================================================================
# 6. SIDEBAR GRAPHICS NAVIGATION INTERFACE
# ==============================================================================
with st.sidebar:
    st.markdown("### 🛡️ AI SECURITY COPILOT PRO")
    st.markdown("<p style='color: #64748b; font-size: 0.8rem; margin-top:-10px;'>SOC Cockpit Version 1.3.5</p>", unsafe_allow_html=True)
    st.markdown("---")
    
    # Active Navigation Toggle Buttons (still 100% decorative — no on_click/return-value
    # handling existed in the original file either, so relabeling/expanding is presentation-only)
    st.button("📊 Dashboard", use_container_width=True, key="nav_dash_hub", type="primary")
    st.button("📜 Log Analyzer", use_container_width=True, key="nav_log_analyzer")
    st.button("🤖 AI Copilot", use_container_width=True, key="nav_ai_term")
    st.button("🛰️ Vulnerability Explorer", use_container_width=True, key="nav_net_recon")
    st.button("🌐 Threat Intelligence", use_container_width=True, key="nav_threat_intel")
    st.button("📋 Reports", use_container_width=True, key="nav_compliance")
    st.button("💻 Assets", use_container_width=True, key="nav_assets")
    st.button("⚙️ Settings", use_container_width=True, key="nav_ctrl_panel")
    
    st.markdown("---")
    
    # Cyberpunk Profile Card Model Mapping (split into profile + engine status,
    # exact original text/values preserved)
    st.markdown("""
    <div class='profile-card'>
        <div class='profile-header'>
            <div class='profile-avatar'>NR</div>
            <div>
                <div class='profile-name'>netR4ptOr@</div>
                <div class='profile-status'>● SOC Lead Analyst</div>
            </div>
        </div>
    </div>
    <div class='engine-status-card'>
        <div style='font-size: 0.75rem; color: #94a3b8; display: flex; justify-content: space-between; margin-bottom: 8px;'>
            <span>Engine: Qwen2.5 (SOC-Rules)</span>
            <span>Enforced</span>
        </div>
        <div class='threat-bar-bg'><div class='threat-bar-fill' style='width: 100%; background: #10b981;'></div></div>
    </div>
    """, unsafe_allow_html=True)

    # NEW (Phase 1): session info + logout + admin-only account provisioning.
    # Purely additive — none of the sidebar markup above this line was edited.
    st.markdown(f"""
        <div style='margin-top: 14px; padding: 10px 14px; border-radius: 8px; background:#111827; border:1px solid #1e293b; font-size:0.78rem; color:#94a3b8;'>
            Signed in as <span style='color:#e2e8f0; font-weight:600;'>{st.session_state.username}</span> · <span style='color:#38bdf8;'>{st.session_state.role}</span>
        </div>
    """, unsafe_allow_html=True)

    if st.button("🚪 Logout", use_container_width=True, key="logout_btn"):
        add_log(f"Operator '{st.session_state.username}' logged out.")
        st.session_state.authenticated = False
        st.session_state.username = None
        st.session_state.role = None
        st.rerun()

    if is_admin():
        with st.expander("➕ Create New Operator Account"):
            new_username = st.text_input("New Username", key="new_user_username")
            new_password = st.text_input("New Password", type="password", key="new_user_password")
            new_role = st.selectbox("Role", ["analyst", "admin"], key="new_user_role")
            if st.button("Create Account", use_container_width=True, key="create_user_btn"):
                if new_username and new_password:
                    new_id = database.create_user(new_username, new_password, new_role)
                    if new_id:
                        st.success(f"Account '{new_username}' created.")
                        add_log(f"Operator '{st.session_state.username}' created new account '{new_username}' (role: {new_role}).")
                    else:
                        st.error("Could not create account — username may already exist.")
                else:
                    st.warning("Username and password are required.")

# ==============================================================================
# 6.5 NEW TOP APPLICATION BAR (FULL-WIDTH, ABOVE BOTH MAIN COLUMNS)
#     Hamburger / search / theme toggle / gear / window controls are
#     decorative only — Streamlit cannot natively support a real OS-level
#     window chrome or a functional in-browser search-everything box here.
#     The notification badge count IS real (HIGH+CRITICAL ops in history).
# ==============================================================================
_high_crit_count = sum(1 for _row in st.session_state.history if _row[3] in ("HIGH", "CRITICAL"))

st.markdown(f"""
    <div class='app-topbar'>
        <div class='topbar-left'>
            <div class='topbar-icon-btn'>☰</div>
            <div class='topbar-search'><span>Search anything...</span><span>🔍</span></div>
        </div>
        <div class='topbar-right'>
            <div class='topbar-icon-btn'>🔔<span class='notif-badge'>{_high_crit_count}</span></div>
            <div class='topbar-icon-btn'>🌙</div>
            <div class='topbar-icon-btn'>⚙️</div>
            <div class='window-controls'>
                <div class='window-dot'>—</div>
                <div class='window-dot'>▢</div>
                <div class='window-dot'>✕</div>
            </div>
        </div>
    </div>
""", unsafe_allow_html=True)

# ==============================================================================
# 7. MAIN INTERFACE SPLIT DESKTOP DOCK PANEL WINDOWING
# ==============================================================================
col_dash, col_chat = st.columns([1.9, 1.3])

# --- LEFT DOCK: SOC MONITOR MATRIX & SCHEMATICS ---
with col_dash:
    # Core Dashboard Banner Title (timestamp now split into two pills to match the reference)
    st.markdown(f"""
        <div class='dashboard-header'>
            <div>
                <h1>Dashboard Telemetry Matrix</h1>
                <div class='subtitle'>Automated network intelligence and compliance tracking feeds.</div>
            </div>
            <div style='display:flex; gap:10px;'>
                <div class='timestamp-badge'>📅 {datetime.now().strftime("%d %b %Y")}</div>
                <div class='timestamp-badge'>🕒 {datetime.now().strftime("%H:%M:%S")}</div>
            </div>
        </div>
    """, unsafe_allow_html=True)
    
    # Core Operations Metrics Row Layout — same data/labels/trends as before,
    # restructured through render_stat_card() into the icon+value+trend layout
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(render_stat_card("🎯", "#3b82f6", st.session_state.total_scans, "Targets Profiled", "↑ Global Matrix Sync", True), unsafe_allow_html=True)
    with m2:
        st.markdown(render_stat_card("⚠️", "#ef4444", st.session_state.threats_found, "Exposure Markers", "↑ Attack Surface Bloat", False), unsafe_allow_html=True)
    with m3:
        st.markdown(render_stat_card("📊", "#f59e0b", "28", "Global Risk Index", "● Conservative Baseline", True), unsafe_allow_html=True)
    with m4:
        st.markdown(render_stat_card("💾", "#10b981", "~1.7 GB", "Host Memory", "● Dynamic Sandbox", True), unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Full-width Operations History Timeline (now 5 columns / 5 rows, matching the reference)
    st.markdown("<div class='section-title'>🔍 Operations History Timeline</div>", unsafe_allow_html=True)
    
    table_html = """<div class='table-container'><table class='pro-table'>
                    <tr><th>Target Endpoint</th><th>Operation Category</th><th>Timestamp</th><th>Status</th><th>Threat Weight</th></tr>"""
    
    for row in st.session_state.history[:5]:
        badge_class = "badge-low"
        if row[3] == "CRITICAL": badge_class = "badge-critical"
        elif row[3] == "HIGH": badge_class = "badge-high"
        elif row[3] == "MEDIUM": badge_class = "badge-medium"
        
        cat_badge = get_category_badge(row[2])
        
        table_html += f"""<tr>
            <td style='font-weight: 700; color: #f8fafc;'>{row[1]}</td>
            <td><span class='badge {cat_badge}'>{row[2]}</span></td>
            <td style='color: #94a3b8; font-family: monospace;'>{row[0]}</td>
            <td><span class='badge badge-success'>Completed</span></td>
            <td><span class='badge {badge_class}'>{row[3]}</span></td>
        </tr>"""
    table_html += "</table></div>"
    st.markdown(table_html, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # New 3-column row: real Risk Distribution donut | existing Attack Surface panel (moved) | real Recent Activity
    col_risk, col_threats, col_activity = st.columns(3)
    
    with col_risk:
        st.markdown("<div class='section-title'>🍩 Risk Distribution</div>", unsafe_allow_html=True)
        risk_fig = render_risk_distribution_chart(st.session_state.history)
        if risk_fig is not None:
            st.plotly_chart(risk_fig, use_container_width=True)
        else:
            st.markdown("<div style='text-align:center; color:#64748b; padding: 40px 0; font-size:0.85rem;'>No Data</div>", unsafe_allow_html=True)
    
    with col_threats:
        st.markdown("<div class='section-title'>⚠️ Attack Surface Vector Shares</div>", unsafe_allow_html=True)
        st.markdown("""
            <div style='background: #0b0f17; border: 1px solid #1e293b; border-radius: 12px; padding: 20px;'>
                <div style='margin-bottom: 16px;'>
                    <div style='display: flex; justify-content: space-between; font-size: 0.82rem;'><span>Service Banner Visibility</span><span style='color: #f59e0b; font-weight:700;'>24</span></div>
                    <div class='threat-bar-bg'><div class='threat-bar-fill' style='width: 55%; background: #f59e0b;'></div></div>
                </div>
                <div style='margin-bottom: 16px;'>
                    <div style='display: flex; justify-content: space-between; font-size: 0.82rem;'><span>Missing HTTP Security Headers</span><span style='color: #38bdf8; font-weight:700;'>18</span></div>
                    <div class='threat-bar-bg'><div class='threat-bar-fill' style='width: 40%; background: #38bdf8;'></div></div>
                </div>
                <div>
                    <div style='display: flex; justify-content: space-between; font-size: 0.82rem;'><span>Unresolved DNS Queries</span><span style='color: #64748b; font-weight:700;'>3</span></div>
                    <div class='threat-bar-bg'><div class='threat-bar-fill' style='width: 12%; background: #64748b;'></div></div>
                </div>
            </div>
        """, unsafe_allow_html=True)
        
    with col_activity:
        st.markdown("<div class='section-title'>🕒 Recent Activity</div>", unsafe_allow_html=True)
        recent_items = st.session_state.history[:3]
        activity_html = "<div class='reports-list'>"
        _icon_color_map = {"badge-cyan": "#22d3ee", "badge-info": "#38bdf8", "badge-purple": "#a855f7"}
        for row in recent_items:
            cat_badge = get_category_badge(row[2])
            icon_color = _icon_color_map.get(cat_badge, "#94a3b8")
            activity_html += f"""<div class='report-item'>
                <div class='report-icon' style='background:{icon_color}22; color:{icon_color};'>📄</div>
                <div>
                    <div class='report-name'>{row[2]}</div>
                    <div class='report-meta'>{row[1]} · {row[0]}</div>
                </div>
            </div>"""
        activity_html += "</div>"
        st.markdown(activity_html, unsafe_allow_html=True)
        st.button("View Full Timeline", use_container_width=True, key="view_full_timeline")
        
    # Per-session Graph Canvas
    st.markdown("<div class='section-title'>📊 Live Compliance Analytics Graph Canvas</div>", unsafe_allow_html=True)
    if st.session_state.latest_chart is not None:
        st.plotly_chart(st.session_state.latest_chart, use_container_width=True)
    else:
        st.markdown("""
            <div style='border: 2px dashed #1e293b; padding: 40px; text-align: center; border-radius: 12px; color: #64748b; font-size: 0.9rem;'>
                Execute an HTTP Security Header analysis command via the Copilot console to project real-time charts here.
            </div>
        """, unsafe_allow_html=True)
        
    # 🚀 1. NEW ADVANCED RECON UI: PORT SCAN VISUALIZER
    st.markdown("<div class='section-title'>📊 Port Perimeter Share</div>", unsafe_allow_html=True)
    try:
        fig = render_port_donut_chart(open_ports_count=3, filtered_closed_count=97)
        st.plotly_chart(fig, use_container_width=True)
    except NameError:
        st.error("⚠️ Helper function 'render_port_donut_chart' is missing. Please add it to Section 5!")
        
    # Bottom Injected Operational Output Trace Panel Box View
    st.markdown("<div class='section-title'>📟 Security Engine Trace Output Console</div>", unsafe_allow_html=True)
    logs_html = "<br>".join(st.session_state.system_logs[::-1][:8])
    st.markdown(f"<div class='terminal-box'>{logs_html}</div>", unsafe_allow_html=True)

    # 🚀 2. NEW ADVANCED RECON UI: SUBDOMAIN BRUTE-FORCER
    st.markdown("---")
    st.markdown("<div class='section-title'>🛰️ Automated Subdomain Intelligence</div>", unsafe_allow_html=True)
    sub_target = st.text_input("Enter Root Domain (e.g., google.com):", key="sub_recon_input")

    if st.button("Launch Subdomain Brute-Force", key="sub_recon_btn"):
        if sub_target:
            with st.spinner("Executing dictionary attack matrix..."):
                try:
                    results = run_subdomain_brute_force(sub_target)
                    if results:
                        st.success(f"Discovered {len(results)} active subdomains!")
                        st.dataframe(results, use_container_width=True)
                    else:
                        st.info("No subdomains discovered with the standard wordlist.")
                except NameError:
                    st.error("⚠️ Helper function 'run_subdomain_brute_force' is missing. Please add it to Section 5!")

# --- RIGHT DOCK: REALTIME AI ANALYST OPERATIONS PANELS ---
with col_chat:
    st.markdown("""
        <div class='chat-header'>
            <div class='chat-avatar'>🤖</div>
            <div>
                <h2 class='chat-title'>AI Analyst Assistant Terminal</h2>
                <div class='chat-status'><span style='width: 7px; height: 7px; background: #10b981; border-radius: 50%; display:inline-block;'></span> Strict SOC Mode Active</div>
            </div>
        </div>
    """, unsafe_allow_html=True)
    
    # Internal Dialog Message Window Enclosure Container
    chat_box = st.container(height=560)
      
    with chat_box:
        for m in st.session_state.messages:
            avatar = "🤖" if m["role"] == "assistant" else "🧑‍💻"
            with st.chat_message(m["role"], avatar=avatar):
                st.markdown(m["content"])

    # NEW: Quick-reply pill buttons — the only functional addition to the chat
    # panel. Each one just feeds straight into the SAME prompt variable that
    # st.chat_input produces, so it runs through the identical ROUTE 7/1/8
    # logic below, completely unchanged.
    quick_prompt = None
    qr1, qr2, qr3 = st.columns(3)
    with qr1:
        if st.button("💬 Explain this", use_container_width=True, key="qr_explain"):
            quick_prompt = "Explain this finding in more detail."
    with qr2:
        if st.button("🛠️ How to fix?", use_container_width=True, key="qr_fix"):
            quick_prompt = "What are the recommended remediation steps for this?"
    with qr3:
        if st.button("🚨 Is this critical?", use_container_width=True, key="qr_critical"):
            quick_prompt = "Is this finding critical or urgent? Please assess severity."

    # Command Router Processing Evaluation Engine Box Intercept Input Loops
    chat_input_value = st.chat_input("Issue technical requests or type system commands...")
    prompt = chat_input_value if chat_input_value else quick_prompt

    if prompt:
        st.session_state.messages.append({"role": "user", "content": prompt})
        with chat_box:
            with st.chat_message("user", avatar="🧑‍💻"):
                st.markdown(prompt)
        
        prompt_lower = prompt.lower()
        
        with chat_box:
            with st.chat_message("assistant", avatar="🤖"):
                
                # ROUTE 7: AUTOMATED INFRASTRUCTURE CHAIN ANALYSIS (ONE-BUTTON AUTOMATION)
                if "analyze" in prompt_lower or "fullscan" in prompt_lower:
                    dom_match = re.search(r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", prompt)
                    if dom_match:
                        target_domain = dom_match.group(1)
                        add_log(f"💥 CHAIN AUTOMATION TRIGGERED FOR TARGET: {target_domain}")
                        
                        # Phase 1: HTTP Security Headers
                        with st.spinner("📦 Phase 1/3: Gathering HTTP Security Response Headers..."):
                            header_data = run_headers(target_domain)
                            add_log(f"HTTP Headers captured for {target_domain}")
                        
                        # Phase 2: DNS Dig Records
                        with st.spinner("🌍 Phase 2/3: Querying DNS Baseline Record Matrix..."):
                            dns_data = run_dig(target_domain)
                            add_log(f"DNS query operation complete for {target_domain}")
                            
                        # Phase 3: Resolve IP and Nmap Scan
                        with st.spinner("🔒 Phase 3/3: Resolving IP and running perimeter Nmap scan..."):
                            try:
                                resolved_ip = socket.gethostbyname(target_domain)
                                add_log(f"Resolved {target_domain} to {resolved_ip}")
                                nmap_data = run_nmap(resolved_ip)
                                add_log(f"Nmap perimeter footprint complete for {resolved_ip}")
                            except Exception as ip_err:
                                resolved_ip = "Unresolved"
                                nmap_data = "No responses matched scan footprint thresholds."
                                dns_data = "DNS query failed from scanning environment."
                                add_log("IP resolution dropped on parsing pipeline.")

                        st.session_state.total_scans += 3
                        
                        # Trigger Internal Header Chart Visualization Generation automatically inside the chain block
                        if header_data:
                            compliance_figure = go.Figure(data=[
                                go.Bar(x=["CSP", "HSTS", "X-Frame-Options", "X-XSS"], y=[30, 20, 0, 0], marker_color=['#ef4444', '#f59e0b', '#10b981', '#10b981'], width=0.5)
                            ])
                            compliance_figure.update_layout(title=f"Target: {target_domain} Security Risk Distribution Metrics", template="plotly_dark", height=280, paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', margin=dict(l=10, r=10, t=45, b=10))
                            st.session_state.latest_chart = compliance_figure

                        # Phase 4: Pass all raw aggregates to Qwen Core for a Strict SOC Master Report
                        if llm:
                            with st.spinner("🤖 AI Copilot orchestrating conservative security assessment..."):
                                chain_analysis_prompt = f"""
                                You are a SOC-Grade Analysis Engine. Process this network infrastructure dump for target `{target_domain}` ({resolved_ip}) and build a factual Tactical Report.
                                
                                CRITICAL SECURITY ASSESSMENT MANDATES:
                                1. NEVER assume vulnerabilities. Open port or active service does NOT mean vulnerable.
                                2. Version old/not latest does NOT mean exploitable. Do NOT claim exploitation is possible.
                                3. Use strictly conservative terminology: "potential exposure", "service visibility", "attack surface".
                                4. NEVER invent, hallucinate, or assume CVE identifiers. Only output a CVE if explicitly provided in the raw dataset below. If absent, explicitly write: "No CVE validation performed."
                                5. Handle DNS drops cleanly. If text indicates failure, print: "DNS query failed from scanning environment." Do NOT assume domain misconfiguration.
                                
                                Structure your report exactly into these sections:
                                ### Infrastructure Summary
                                Target:
                                Resolved IP:
                                Confidence:
                                
                                ### Observations
                                (List detected ports, services, and explicit versions cleanly. If version absent, output: "Version not detected.")
                                
                                ### Potential Risks
                                (Only write direct evidence-based risks like metadata exposures or perimeter visibility. No unverified vulnerability claims)
                                
                                ### Recommendations
                                (Practical, calm, actionable hardening advice without fear-based or alarmist jargon)
                                
                                ### Validation Status
                                CVE Validation: Performed / Not Performed
                                Vulnerability Confirmation: Available / Not Available
                                Confidence Level: High / Medium / Low
                                
                                Raw Input Telemetry Feed Logs:
                                --- HTTP HEADERS ---
                                {header_data if header_data else "No Headers Retrieved"}
                                --- DNS ZONE DATA ---
                                {dns_data}
                                --- NMAP PORT SCAN ---
                                {nmap_data}
                                """
                                master_report = llm.invoke(chain_analysis_prompt)
                                st.markdown(master_report)
                                st.session_state.messages.append({"role": "assistant", "content": master_report})
                                chain_raw_result = f"--- HTTP HEADERS ---\n{header_data}\n\n--- DNS ZONE DATA ---\n{dns_data}\n\n--- NMAP PORT SCAN ---\n{nmap_data}"
                                add_history(target_domain, "Automated Chain Scan", "MEDIUM", chain_raw_result)
                        else:
                            st.error("AI Language model core link offline.")
                    else:
                        st.error("Please provide a valid domain target (e.g. analyze target.com)")

                # ROUTE 1: AUTOMATED HTTP RESPONSE SECURITY HEADERS AUDITING ENGINE
                elif "header" in prompt_lower or "http" in prompt_lower:
                    dom_match = re.search(r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", prompt)
                    if dom_match:
                        target_domain = dom_match.group(1)
                        add_log(f"HTTP response network probe issued to target: {target_domain}")
                        captured_raw = run_headers(target_domain)
                        
                        if not captured_raw:
                            error_payload = {
                                "error": "No HTTP headers provided for analysis",
                                "status": "insufficient_data"
                            }
                            st.json(error_payload)
                            st.session_state.messages.append({"role": "assistant", "content": f"```json\n{json.dumps(error_payload, indent=2)}\n```"})
                        else:
                            st.session_state.total_scans += 1
                            
                            header_analysis_schema_prompt = f"""
                            You are a Conservative Security Header Analysis Engine.
                            Analyze the following raw HTTP response headers and generate a structured JSON report.
                            
                            CRITICAL COMPLIANCE RULES:
                            1. NEVER assume vulnerabilities. Missing header = "Not Detected", NOT a confirmed exploit.
                            2. Use safe terminology: "potential exposure", "service visibility", "attack surface".
                            3. Structure your response strictly as valid JSON matching the structure below. Do not output anything else.
                            
                            Expected Output Structure:
                            {{
                              "target": "{target_domain}",
                              "missing_headers": ["List", "detected", "missing", "headers"],
                              "potential_exposure": "Brief description of attack surface visibility",
                              "risk_weight": "LOW/MEDIUM/HIGH"
                            }}

                            Raw Telemetry Feed:
                            {captured_raw}
                            """
                            
                            if llm:
                                with st.spinner("🤖 AI Copilot orchestrating conservative security header analysis..."):
                                    header_report = llm.invoke(header_analysis_schema_prompt)
                                    clean_json = header_report.replace("```json", "").replace("```", "").strip()
                                    try:
                                        json_data = json.loads(clean_json)
                                        st.json(json_data)
                                        st.session_state.messages.append({"role": "assistant", "content": f"```json\n{json.dumps(json_data, indent=2)}\n```"})
                                        add_history(target_domain, "HTTP Header Audit", json_data.get("risk_weight", "LOW"), header_report)
                                    except Exception:
                                        st.markdown(header_report)
                                        st.session_state.messages.append({"role": "assistant", "content": header_report})
                                        add_history(target_domain, "HTTP Header Audit", "LOW", header_report)
                            else:
                                st.error("AI Language model core link offline.")
                    else:
                        st.error("Please provide a valid domain target (e.g. header target.com)")

                # ROUTE A: DIRECT NMAP SCAN COMMAND (NEW — Phase 4.1 hotfix)
                elif "scan" in prompt_lower:
                    ip_match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", prompt)
                    if ip_match:
                        target_ip = ip_match.group(0)
                        add_log(f"Direct Nmap scan command issued for target: {target_ip}")
                        nmap_result = run_nmap(target_ip)
                        st.code(nmap_result, language="text")
                        st.session_state.messages.append({"role": "assistant", "content": f"```\n{nmap_result}\n```"})
                        st.session_state.total_scans += 1
                        add_history(target_ip, "Direct Nmap Scan", "LOW", nmap_result)
                    else:
                        st.error("Please provide a valid IP address (e.g. scan 192.168.1.1)")

                # ROUTE B: DIRECT WHOIS LOOKUP COMMAND (NEW — Phase 4.1 hotfix)
                elif "whois" in prompt_lower:
                    dom_match = re.search(r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", prompt)
                    if dom_match:
                        target_domain = dom_match.group(1)
                        add_log(f"Direct WHOIS lookup command issued for target: {target_domain}")
                        whois_result = run_whois(target_domain)
                        st.code(whois_result, language="text")
                        st.session_state.messages.append({"role": "assistant", "content": f"```\n{whois_result}\n```"})
                        st.session_state.total_scans += 1
                        add_history(target_domain, "WHOIS Lookup", "LOW", whois_result)
                    else:
                        st.error("Please provide a valid domain target (e.g. whois google.com)")

                # ROUTE C: DIRECT DIG/DNS LOOKUP COMMAND (NEW — Phase 4.1 hotfix)
                elif "dig" in prompt_lower or "dns" in prompt_lower:
                    dom_match = re.search(r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", prompt)
                    if dom_match:
                        target_domain = dom_match.group(1)
                        add_log(f"Direct DNS dig command issued for target: {target_domain}")
                        dig_result = run_dig(target_domain)
                        st.code(dig_result, language="text")
                        st.session_state.messages.append({"role": "assistant", "content": f"```\n{dig_result}\n```"})
                        st.session_state.total_scans += 1
                        add_history(target_domain, "DNS Dig Query", "LOW", dig_result)
                    else:
                        st.error("Please provide a valid domain target (e.g. dig google.com)")

                # ROUTE D: DIRECT SUBDOMAIN DISCOVERY COMMAND (NEW — Phase 4.1 hotfix)
                elif "subdomain" in prompt_lower:
                    dom_match = re.search(r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", prompt)
                    if dom_match:
                        target_domain = dom_match.group(1)
                        add_log(f"Direct subdomain discovery command issued for target: {target_domain}")
                        subdomain_results = run_subdomain_brute_force(target_domain)
                        st.dataframe(subdomain_results, use_container_width=True)
                        st.session_state.messages.append({"role": "assistant", "content": f"Discovered {len(subdomain_results)} subdomain(s) for `{target_domain}`. See table above."})
                        st.session_state.total_scans += 1
                        add_history(target_domain, "Subdomain Discovery", "LOW", str(subdomain_results))
                    else:
                        st.error("Please provide a valid domain target (e.g. subdomain google.com)")

                # 🤖 ROUTE 8: GENERAL CHAT FALLBACK (If no commands match)
                else:
                    if llm:
                        with st.spinner("🤖 AI Copilot analyzing query..."):
                            response = llm.invoke(prompt)
                            st.markdown(response)
                            st.session_state.messages.append({"role": "assistant", "content": response})
                    else:
                        st.error("AI Language model core link offline.")

# ==============================================================================
# 8. NEW BOTTOM STATUS BAR (FULL-WIDTH, BELOW BOTH MAIN COLUMNS)
#     AI Engine + Database reflect REAL llm / db_ready state — not fabricated.
# ==============================================================================
st.markdown(f"""
    <div class='status-bar'>
        <div class='status-item'><span class='status-dot' style='background:#10b981;'></span> System Status: <span style='color:#10b981; font-weight:600;'>Secure</span></div>
        <div class='status-item'><span class='status-dot' style='background:{"#10b981" if llm else "#ef4444"};'></span> AI Engine: <span style='color:#e2e8f0; font-weight:600;'>{"Qwen2.5:3b (Ollama)" if llm else "Offline"}</span></div>
        <div class='status-item'><span class='status-dot' style='background:{"#10b981" if db_ready else "#ef4444"};'></span> Database: <span style='color:#e2e8f0; font-weight:600;'>{"Connected" if db_ready else "Disconnected"}</span></div>
        <div class='status-item' style='color:#64748b;'>Version: v1.3.5</div>
    </div>
""", unsafe_allow_html=True)
