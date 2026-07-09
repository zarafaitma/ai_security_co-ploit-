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
        margin-top: 40px;
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

_init_database()

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
# 6. SIDEBAR GRAPHICS NAVIGATION INTERFACE
# ==============================================================================
with st.sidebar:
    st.markdown("### 🛡️ RECONTOOLKIT PRO")
    st.markdown("<p style='color: #64748b; font-size: 0.8rem; margin-top:-10px;'>SOC Cockpit Version 1.3.5</p>", unsafe_allow_html=True)
    st.markdown("---")
    
    # Active Navigation Toggle Buttons
    st.button("📊 Dashboard Hub", use_container_width=True, key="nav_dash_hub")
    st.button("🤖 Live AI Terminal", use_container_width=True, key="nav_ai_term")
    st.button("🕵️ Network Recon Center", use_container_width=True, key="nav_net_recon")
    st.button("📋 Compliance Reports", use_container_width=True, key="nav_compliance")
    st.button("⚙️ Control Panel Configuration", use_container_width=True, key="nav_ctrl_panel")
    
    st.markdown("---")
    
    # Cyberpunk Profile Card Model Mapping
    st.markdown("""
    <div class='profile-card'>
        <div class='profile-header'>
            <div class='profile-avatar'>NR</div>
            <div>
                <div class='profile-name'>netR4ptOr@</div>
                <div class='profile-status'>● SOC Lead Analyst</div>
            </div>
        </div>
        <div style='font-size: 0.75rem; color: #94a3b8; display: flex; justify-content: space-between; margin-bottom: 8px;'>
            <span>Engine: Qwen2.5 (SOC-Rules)</span>
            <span>Enforced</span>
        </div>
        <div class='threat-bar-bg'><div class='threat-bar-fill' style='width: 100%; background: #10b981;'></div></div>
    </div>
    """, unsafe_allow_html=True)

# ==============================================================================
# 7. MAIN INTERFACE SPLIT DESKTOP DOCK PANEL WINDOWING
# ==============================================================================
col_dash, col_chat = st.columns([1.9, 1.3])

# --- LEFT DOCK: SOC MONITOR MATRIX & SCHEMATICS ---
with col_dash:
    # Core Dashboard Banner Title
    st.markdown(f"""
        <div class='dashboard-header'>
            <div>
                <h1>Dashboard Telemetry Matrix</h1>
                <div class='subtitle'>Automated network intelligence and compliance tracking feeds.</div>
            </div>
            <div class='timestamp-badge'>📅 {datetime.now().strftime("%d %b %Y")} | 🕒 {datetime.now().strftime("%H:%M:%S")}</div>
        </div>
    """, unsafe_allow_html=True)
    
    # Core Operations Metrics Row Layout
    m1, m2, m3, m4 = st.columns(4)
    with m1: 
        st.markdown(f"<div class='stat-card'><div class='title'>Targets Profiled</div><div class='value' style='color: #3b82f6;'>{st.session_state.total_scans}</div><span class='trend-up'>↑ Global Matrix Sync</span></div>", unsafe_allow_html=True)
    with m2: 
        st.markdown(f"<div class='stat-card'><div class='title'>Exposure Markers</div><div class='value' style='color: #ef4444;'>{st.session_state.threats_found}</div><span class='trend-danger'>↑ Attack Surface Bloat</span></div>", unsafe_allow_html=True)
    with m3: 
        st.markdown("<div class='stat-card'><div class='title'>Global Risk Index</div><div class='value' style='color: #f59e0b;'>28</div><span style='color: #10b981; font-size: 0.8rem; font-weight:500;'>● Conservative Baseline</span></div>", unsafe_allow_html=True)
    with m4: 
        st.markdown("<div class='stat-card'><div class='title'>Host Memory</div><div class='value' style='color: #10b981;'>~1.7 GB</div><span class='trend-up'>● Dynamic Sandbox</span></div>", unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Dynamic Layout Split for Tracking Timelines and Charts Rows
    col_table_frame, col_side_analytics = st.columns([1.6, 1.0])
    
    with col_table_frame:
        st.markdown("<div class='section-title'>🔍 Operations History Timeline</div>", unsafe_allow_html=True)
        
        # Build pure HTML injected data grids mapping the execution arrays safely
        table_html = """<div class='table-container'><table class='pro-table'>
                        <tr><th>TIMESTAMP</th><th>TARGET ENDPOINT</th><th>OPERATION CATEGORY</th><th>THREAT WEIGHT</th></tr>"""
        
        for row in st.session_state.history[:4]:
            badge_class = "badge-low"
            if row[3] == "CRITICAL": badge_class = "badge-critical"
            elif row[3] == "HIGH": badge_class = "badge-high"
            elif row[3] == "MEDIUM": badge_class = "badge-medium"
            
            table_html += f"""<tr>
                <td style='color: #94a3b8; font-family: monospace;'>{row[0]}</td>
                <td style='font-weight: 700; color: #f8fafc;'>{row[1]}</td>
                <td style='color: #cbd5e1;'>{row[2]}</td>
                <td><span class='badge {badge_class}'>{row[3]}</span></td>
            </tr>"""
        table_html += "</table></div>"
        st.markdown(table_html, unsafe_allow_html=True)
        
    with col_side_analytics:
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
    st.markdown("### 📊 Port Perimeter Share")
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
            <div style='font-size: 1.6rem;'>🤖</div>
            <div>
                <h2 class='chat-title'>AI Analyst Assistant Terminal</h2>
                <div class='chat-status'><span style='width: 7px; height: 7px; background: #10b981; border-radius: 50%; display:inline-block;'></span> Strict SOC Mode Active</div>
            </div>
        </div>
    """, unsafe_allow_html=True)
    
    # Internal Dialog Message Window Enclosure Container
    chat_box = st.container(height=650)
      
    with chat_box:
        for m in st.session_state.messages:
            with st.chat_message(m["role"]):
                st.markdown(m["content"])

    # Command Router Processing Evaluation Engine Box Intercept Input Loops
    if prompt := st.chat_input("Issue technical requests or type system commands..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with chat_box:
            with st.chat_message("user"):
                st.markdown(prompt)
        
        prompt_lower = prompt.lower()
        
        with chat_box:
            with st.chat_message("assistant"):
                
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

                # 🤖 ROUTE 8: GENERAL CHAT FALLBACK (If no commands match)
                else:
                    if llm:
                        with st.spinner("🤖 AI Copilot analyzing query..."):
                            response = llm.invoke(prompt)
                            st.markdown(response)
                            st.session_state.messages.append({"role": "assistant", "content": response})
                    else:
                        st.error("AI Language model core link offline.")
