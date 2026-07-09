import streamlit as st
from langchain_ollama import OllamaLLM
import subprocess
import re
import os
from datetime import datetime

# ==========================================
# 1. PAGE CONFIGURATION & PREMIUM SOC CSS
# ==========================================
st.set_page_config(page_title="AI Security Copilot Pro", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
    <style>
    /* Global Dark Cyber Theme */
    .stApp { background-color: #0B0F19; color: #E2E8F0; }
    
    /* Sidebar Styling */
    div[data-testid="stSidebar"] { 
        background-color: #06090F; 
        border-right: 1px solid #1E293B;
    }
    
    /* Top Bar Header */
    .dashboard-header {
        display: flex; justify-content: space-between; align-items: center;
        padding-bottom: 15px; border-bottom: 1px solid #1E293B; margin-bottom: 20px;
    }
    .dashboard-header h1 { margin: 0; font-size: 1.8rem; color: #F8FAFC; }
    .dashboard-header .timestamp { color: #94A3B8; font-size: 0.9rem; background: #1E293B; padding: 5px 12px; border-radius: 6px; }

    /* Premium Metric Cards */
    .stat-card {
        background: linear-gradient(145deg, #111827 0%, #0F172A 100%);
        border: 1px solid #1E293B; padding: 20px; border-radius: 12px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        transition: transform 0.2s ease;
    }
    .stat-card:hover { transform: translateY(-2px); border-color: #3B82F6; }
    .stat-card .title { color: #94A3B8; font-size: 0.85rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px;}
    .stat-card .value { font-size: 2.2rem; font-weight: 700; margin: 0; color: #F8FAFC; }
    .stat-card .trend-up { color: #10B981; font-size: 0.8rem; margin-top: 8px; display: block; }
    .stat-card .trend-danger { color: #EF4444; font-size: 0.8rem; margin-top: 8px; display: block; }

    /* Tables */
    .table-container { background: #111827; border: 1px solid #1E293B; border-radius: 12px; padding: 15px; overflow: hidden; }
    .pro-table { width: 100%; border-collapse: collapse; text-align: left; }
    .pro-table th { color: #94A3B8; font-size: 0.75rem; text-transform: uppercase; padding: 12px; border-bottom: 1px solid #1E293B; }
    .pro-table td { padding: 12px; font-size: 0.85rem; border-bottom: 1px solid #1E293B; color: #E2E8F0; }
    .pro-table tr:hover { background-color: #1E293B; }

    /* Badges */
    .badge { padding: 4px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; }
    .badge-critical { background: rgba(239, 68, 68, 0.2); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-medium { background: rgba(245, 158, 11, 0.2); color: #F59E0B; border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-low { background: rgba(16, 185, 129, 0.2); color: #10B981; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-info { background: rgba(59, 130, 246, 0.2); color: #3B82F6; border: 1px solid rgba(59, 130, 246, 0.3); }

    /* Terminal Console */
    .terminal-box {
        background-color: #000000; border: 1px solid #1E293B;
        font-family: 'Consolas', 'Courier New', monospace; padding: 15px;
        border-radius: 8px; color: #10B981; height: 180px; overflow-y: auto; font-size: 0.8rem;
    }
    
    .threat-bar-bg { background: #1E293B; border-radius: 10px; height: 8px; width: 100%; margin-top: 5px; overflow: hidden; }
    .threat-bar-fill { height: 100%; border-radius: 10px; }
    </style>
""", unsafe_allow_html=True)

# ==========================================
# 2. OPTIMIZED BACKEND ENGINE (QWEN 2.5:3B)
# ==========================================
@st.cache_resource
def load_qwen_engine():
    # Memory efficient initialization for Qwen 3B
    return OllamaLLM(model="qwen2.5:3b")

llm = load_qwen_engine()

# Initialize Session States
if "messages" not in st.session_state:
    st.session_state.messages = [{"role": "assistant", "content": "Hello Analyst! I am your AI Copilot powered by Qwen2.5 (3B). High-speed optimization is active. Ready for deployment."}]
if "total_scans" not in st.session_state:
    st.session_state.total_scans = 24
if "threats_found" not in st.session_state:
    st.session_state.threats_found = 3
if "system_logs" not in st.session_state:
    st.session_state.system_logs = ["[SYSTEM READY] Qwen2.5:3b AI Engine loaded successfully.", "[OPTIMIZATION] CPU RAM footprint reduced by 65%."]
if "history" not in st.session_state:
    st.session_state.history = [
        [datetime.now().strftime("%I:%M %p"), "auth.log", "Linux Auth Log", "MEDIUM"],
        [datetime.now().strftime("%I:%M %p"), "142.250.202.46", "Vulnerability Scan", "CRITICAL"]
    ]

def add_log(msg):
    st.session_state.system_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def add_history(target, task, risk):
    time_now = datetime.now().strftime("%I:%M %p")
    st.session_state.history.insert(0, [time_now, target, task, risk])

# Subprocess Sub-modules
def run_nmap(ip):
    try:
        res = subprocess.run(["nmap", "-F", "-sV", ip], capture_output=True, text=True)
        return res.stdout if res.stdout else "No output from Nmap."
    except Exception as e: return f"Error: {e}"

def run_whois(dom):
    try:
        res = subprocess.run(["whois", dom], capture_output=True, text=True)
        return res.stdout[:2000] if res.stdout else "No WHOIS data."
    except Exception as e: return f"Error: {e}"

# ==========================================
# 3. SIDEBAR NAVIGATION
# ==========================================
with st.sidebar:
    st.markdown("### 🛡️ COPILOT PRO")
    st.markdown("---")
    st.button("📊 Dashboard Overview", use_container_width=True)
    st.button("📄 Log Analyzer", use_container_width=True)
    st.button("🤖 AI Copilot", use_container_width=True)
    st.button("🔍 Vulnerability Explorer", use_container_width=True)
    st.button("⚙️ Settings", use_container_width=True)
    
    st.markdown("<br><br><br><br><br>", unsafe_allow_html=True)
    st.markdown("""
        <div style='background:#111827; padding:15px; border-radius:10px; border:1px solid #1E293B;'>
            <div style='display:flex; align-items:center; gap:10px;'>
                <div style='width:35px; height:35px; border-radius:50%; background:#3B82F6; display:flex; align-items:center; justify-content:center; font-weight:bold;'>NR</div>
                <div>
                    <div style='font-size:0.9rem; font-weight:bold; color:#F8FAFC;'>netR4ptOr@</div>
                    <div style='font-size:0.75rem; color:#10B981;'>● Core Active</div>
                </div>
            </div>
            <div style='margin-top:15px;'>
                <div style='font-size:0.75rem; color:#94A3B8; display:flex; justify-content:space-between;'><span>Engine: Qwen2.5 (3B)</span><span>Optimized</span></div>
                <div class='threat-bar-bg'><div class='threat-bar-fill' style='width:100%; background:#10B981;'></div></div>
            </div>
        </div>
    """, unsafe_allow_html=True)

# ==========================================
# 4. MAIN LAYOUT
# ==========================================
col_dash, col_chat = st.columns([2.2, 1.0])

# --- DASHBOARD PANEL ---
with col_dash:
    st.markdown(f"""
        <div class='dashboard-header'>
            <div>
                <h1>Dashboard Overview</h1>
                <div style='color:#94A3B8; font-size:0.9rem; margin-top:4px;'>Real-time low-latency security metrics telemetry.</div>
            </div>
            <div class='timestamp'>📅 {datetime.now().strftime("%d %b %Y")} | 🕒 {datetime.now().strftime("%I:%M %p")}</div>
        </div>
    """, unsafe_allow_html=True)
    
    # Metrics Row
    m1, m2, m3, m4 = st.columns(4)
    with m1: st.markdown(f"<div class='stat-card'><div class='title'>Targets Scanned</div><div class='value' style='color:#3B82F6;'>{st.session_state.total_scans}</div><span class='trend-up'>↑ Active Profiling</span></div>", unsafe_allow_html=True)
    with m2: st.markdown(f"<div class='stat-card'><div class='title'>Alerts Detected</div><div class='value' style='color:#EF4444;'>{st.session_state.threats_found}</div><span class='trend-danger'>Static Analysis Threat</span></div>", unsafe_allow_html=True)
    with m3: st.markdown("<div class='stat-card'><div class='title'>System Risk Score</div><div class='value' style='color:#F59E0B;'>68</div><span style='color:#F59E0B; font-size:0.8rem; margin-top:8px; display:block;'>Medium Risk</span></div>", unsafe_allow_html=True)
    with m4: st.markdown("<div class='stat-card'><div class='title'>RAM Footprint</div><div class='value' style='color:#10B981;'>~1.8 GB</div><span class='trend-up'>● Ultra Optimized Mode</span></div>", unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Table & Threat Mix
    col_table, col_threats = st.columns([1.7, 1])
    
    with col_table:
        st.markdown("<h3 style='font-size:1.1rem; margin-bottom:15px;'>🔍 Recent Operations Log</h3>", unsafe_allow_html=True)
        table_html = """<div class='table-container'><table class='pro-table'>
                        <tr><th>TARGET / FILE</th><th>OPERATION TYPE</th><th>TIMESTAMP</th><th>RISK LEVEL</th></tr>"""
        for row in st.session_state.history[:5]:
            risk_class = "badge-info"
            if row[3] == "CRITICAL": risk_class = "badge-critical"
            elif row[3] == "MEDIUM": risk_class = "badge-medium"
            elif row[3] == "LOW": risk_class = "badge-low"
            
            table_html += f"""<tr>
                <td style='font-weight:bold;'>{row[1]}</td>
                <td style='color:#94A3B8;'>{row[2]}</td>
                <td style='color:#94A3B8;'>{row[0]}</td>
                <td><span class='badge {risk_class}'>{row[3]}</span></td>
            </tr>"""
        table_html += "</table></div>"
        st.markdown(table_html, unsafe_allow_html=True)

    with col_threats:
        st.markdown("<h3 style='font-size:1.1rem; margin-bottom:15px;'>⚠️ Top Threats Detected</h3>", unsafe_allow_html=True)
        st.markdown("""
            <div style='background:#111827; border:1px solid #1E293B; border-radius:12px; padding:20px;'>
                <div style='margin-bottom:15px;'>
                    <div style='display:flex; justify-content:space-between; font-size:0.85rem;'><span>Brute Force Attempts</span><span style='color:#EF4444;'>18</span></div>
                    <div class='threat-bar-bg'><div class='threat-bar-fill' style='width:85%; background:#EF4444;'></div></div>
                </div>
                <div style='margin-bottom:15px;'>
                    <div style='display:flex; justify-content:space-between; font-size:0.85rem;'><span>Failed Logins</span><span style='color:#F59E0B;'>12</span></div>
                    <div class='threat-bar-bg'><div class='threat-bar-fill' style='width:60%; background:#F59E0B;'></div></div>
                </div>
                <div>
                    <div style='display:flex; justify-content:space-between; font-size:0.85rem;'><span>Suspicious IP Access</span><span style='color:#3B82F6;'>4</span></div>
                    <div class='threat-bar-bg'><div class='threat-bar-fill' style='width:25%; background:#3B82F6;'></div></div>
                </div>
            </div>
        """, unsafe_allow_html=True)

    # Core Terminal Output
    st.markdown("<br><h3 style='font-size:1.1rem; margin-bottom:10px;'>📟 Core Output Terminal</h3>", unsafe_allow_html=True)
    logs_html = "<br>".join(st.session_state.system_logs[::-1][:10])
    st.markdown(f"<div class='terminal-box'>{logs_html}</div>", unsafe_allow_html=True)


# --- INTERACTIVE AI CHAT TERMINAL ---
with col_chat:
    st.markdown("""
        <div style='display:flex; align-items:center; gap:10px; margin-bottom:15px; border-bottom:1px solid #1E293B; padding-bottom:15px;'>
            <div style='font-size:1.5rem;'>🤖</div>
            <div>
                <h2 style='margin:0; font-size:1.2rem; color:#F8FAFC;'>AI Copilot Engine</h2>
                <div style='font-size:0.8rem; color:#10B981;'>● Qwen2.5:3b (Optimized Mode)</div>
            </div>
        </div>
    """, unsafe_allow_html=True)
    
    chat_box = st.container(height=630)
    
    with chat_box:
        for m in st.session_state.messages:
            with st.chat_message(m["role"]): st.markdown(m["content"])

    if prompt := st.chat_input("Ask anything or issue target commands..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with chat_box: 
            with st.chat_message("user"): st.markdown(prompt)
            
        prompt_lower = prompt.lower()
        
        with chat_box:
            with st.chat_message("assistant"):
                
                # ROUTE 1: HIGH-SPEED NMAP SCAN
                if "scan" in prompt_lower or "nmap" in prompt_lower or re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", prompt):
                    ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", prompt)
                    if ip_match:
                        target = ip_match.group(1)
                        add_log(f"Fast Nmap scan initiated on target: {target}")
                        st.session_state.total_scans += 1
                        
                        with st.spinner(f"Running port scan on {target}..."):
                            raw = run_nmap(target)
                        
                        # Short & crisp prompt structure optimized for a 3B model
                        cve_prompt = f"Analyze these raw Nmap scan results as a cybersecurity expert. Provide CVE mapping and Metasploit suggestions concisely using markdown headers:\n{raw}"
                        
                        with st.spinner("Processing CVE metrics via Qwen2.5..."):
                            res = llm.invoke(cve_prompt)
                            
                        st.markdown(res)
                        st.session_state.messages.append({"role": "assistant", "content": res})
                        
                        risk_level = "LOW"
                        if any(x in res.upper() for x in ["CRITICAL", "HIGH", "EXPLOIT"]):
                            risk_level = "CRITICAL"
                            st.session_state.threats_found += 1
                        elif "MEDIUM" in res.upper(): risk_level = "MEDIUM"
                            
                        add_history(target, "Vulnerability Scan", risk_level)
                        add_log(f"High-speed report generated for {target}")
                    else: st.error("Please supply a valid target IP address.")

                # ROUTE 2: FAST LOG ANALYZER
                elif "log" in prompt_lower:
                    path_match = re.search(r"([\w./-]+\.log)", prompt)
                    if path_match:
                        path = path_match.group(1).strip()
                        if os.path.exists(path):
                            add_log(f"Parsing system log: {path}")
                            with open(path, "r") as f: content = "".join(f.readlines()[-35:])
                            
                            with st.spinner("Analyzing anomalies..."):
                                res = llm.invoke("Identify security threats inside these logs concisely (Incident, Summary, Evidence):\n" + content)
                            st.markdown(res)
                            st.session_state.messages.append({"role": "assistant", "content": res})
                            risk = "CRITICAL" if any(x in res.upper() for x in ["CRITICAL", "HIGH", "BRUTE FORCE"]) else "MEDIUM"
                            add_history(os.path.basename(path), "Log Analysis", risk)
                        else: st.error(f"File path '{path}' not found.")
                    else: st.error("Please specify a valid log file path.")

                # ROUTE 3: WHOIS OSINT LOOKUP
                elif "whois" in prompt_lower or "domain" in prompt_lower:
                    dom_match = re.search(r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", prompt)
                    if dom_match:
                        dom = dom_match.group(1)
                        add_log(f"OSINT registry lookups for: {dom}")
                        with st.spinner(f"Querying WHOIS for {dom}..."): raw = run_whois(dom)
                        with st.spinner("Structuring records..."): res = llm.invoke(f"Summarize key data points from this WHOIS layout:\n{raw}")
                        st.markdown(res)
                        st.session_state.messages.append({"role": "assistant", "content": res})
                        add_history(dom, "Domain OSINT", "LOW")
                    else: st.error("Please provide a valid domain name.")

                # ROUTE 4: FLEXIBLE CHAT TERMINAL (General Life / Technical Intelligence)
                else:
                    with st.spinner("Processing query..."):
                        system_context = f"You are AI Security Copilot. Answer the following general question clearly and professionally: {prompt}"
                        res = llm.invoke(system_context)
                    st.markdown(res)
                    st.session_state.messages.append({"role": "assistant", "content": res})
                    
        st.rerun()
