import streamlit as st
from langchain_ollama import OllamaLLM
import subprocess
import re
import os
from datetime import datetime
import pandas as pd

# 1. Page Configuration
st.set_page_config(page_title="AI Security Copilot Pro", layout="wide", initial_sidebar_state="expanded")

# 2. Advanced Cyber Dark Theme CSS
st.markdown("""
    <style>
    .stApp { background-color: #0A0D14; color: #E5E7EB; }
    div[data-testid="stSidebar"] { background-color: #05070A; border-right: 1px solid #1F2937; }
    
    /* Metric Cards */
    .metric-card {
        background-color: #111622; border: 1px solid #1F2937;
        padding: 20px; border-radius: 12px; text-align: center;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    }
    .metric-card h3 { margin: 0; font-size: 2rem; color: #3B82F6; }
    .metric-card p { margin: 5px 0 0 0; color: #9CA3AF; font-size: 0.9rem; }
    
    /* Live Log Console */
    .log-box {
        background-color: #05070A; border: 1px solid #1F2937;
        font-family: 'Courier New', Courier, monospace; padding: 12px;
        border-radius: 8px; color: #10B981; height: 180px; overflow-y: auto; font-size: 0.85rem;
    }

    /* Professional Table Styling */
    .report-table {
        width: 100%; border-collapse: collapse; margin-top: 20px;
        background-color: #111622; border-radius: 10px; overflow: hidden;
    }
    .report-table th { background-color: #1F2937; color: #9CA3AF; padding: 12px; text-align: left; font-size: 0.9rem; }
    .report-table td { padding: 12px; border-bottom: 1px solid #1F2937; font-size: 0.85rem; color: #E5E7EB; }
    
    /* Risk Badges */
    .badge { padding: 4px 8px; border-radius: 6px; font-weight: bold; font-size: 0.75rem; }
    .badge-critical { background-color: #7F1D1D; color: #FECACA; }
    .badge-medium { background-color: #78350F; color: #FEF3C7; }
    .badge-low { background-color: #064E3B; color: #D1FAE5; }
    .badge-info { background-color: #1E3A8A; color: #DBEAFE; }
    </style>
""", unsafe_allow_html=True)

# 3. Backend Logic & Caching
@st.cache_resource
def load_llama3():
    return OllamaLLM(model="llama3")

llm = load_llama3()

if "messages" not in st.session_state:
    st.session_state.messages = [{"role": "assistant", "content": "Welcome Analyst. Systems are online. I am ready for target deployment."}]
if "total_scans" not in st.session_state:
    st.session_state.total_scans = 0
if "threats_found" not in st.session_state:
    st.session_state.threats_found = 0
if "system_logs" not in st.session_state:
    st.session_state.system_logs = ["[SYSTEM READY] All security modules loaded."]
if "history" not in st.session_state:
    st.session_state.history = []

def add_log(msg):
    st.session_state.system_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def add_history(target, task, risk):
    time_now = datetime.now().strftime("%H:%M")
    st.session_state.history.insert(0, [time_now, target, task, risk])

# 4. Tool Definitions
def run_nmap(ip):
    try:
        res = subprocess.run(["nmap", "-F", "-sV", ip], capture_output=True, text=True)
        return res.stdout if res.stdout else "Nmap executed but returned no output."
    except Exception as e: 
        return f"Nmap Execution Error: {str(e)}"

def run_whois(dom):
    try:
        res = subprocess.run(["whois", dom], capture_output=True, text=True)
        return res.stdout[:2500] if res.stdout else "No WHOIS data found."
    except Exception as e: 
        return f"Whois Execution Error: {str(e)}"

# 5. UI Sidebar
with st.sidebar:
    st.title("🛡️ COPILOT PRO")
    st.markdown("---")
    st.button("📊 Overview Dashboard", use_container_width=True)
    st.button("🔍 Threat Hunting", use_container_width=True)
    st.button("📄 Export Reports", use_container_width=True)
    st.markdown("<br><br><br><br><br><br>", unsafe_allow_html=True)
    st.info(f"**Status:** Operational\n\n**IP:** 192.168.x.x\n\n**Agent:** Llama3")

# 6. Main Dashboard
col_dash, col_chat = st.columns([1.9, 1.1])

with col_dash:
    st.title("Security Command Center")
    
    # Metrics Row
    m1, m2, m3 = st.columns(3)
    with m1: st.markdown(f'<div class="metric-card"><h3>{st.session_state.total_scans}</h3><p>Network Scans</p></div>', unsafe_allow_html=True)
    with m2: st.markdown(f'<div class="metric-card"><h3 style="color:#EF4444;">{st.session_state.threats_found}</h3><p>Threat Alerts</p></div>', unsafe_allow_html=True)
    with m3: st.markdown('<div class="metric-card"><h3 style="color:#10B981;">Active</h3><p>AI Engine Status</p></div>', unsafe_allow_html=True)
    
    # Event Stream (Top)
    st.markdown("<br>", unsafe_allow_html=True)
    st.subheader("📟 Live Event Stream")
    logs_html = "<br>".join(st.session_state.system_logs[::-1][:8])
    st.markdown(f'<div class="log-box">{logs_html}</div>', unsafe_allow_html=True)
    
    # Recent Activity Table (Bottom)
    st.subheader("🕵️ Recent Analysis History")
    if not st.session_state.history:
        st.write("No activity recorded yet.")
    else:
        table_html = """<table class="report-table">
                        <tr><th>TIME</th><th>TARGET</th><th>OPERATION</th><th>RISK LEVEL</th></tr>"""
        for row in st.session_state.history[:6]:
            risk_class = "badge-info"
            if row[3] == "CRITICAL": risk_class = "badge-critical"
            elif row[3] == "MEDIUM": risk_class = "badge-medium"
            elif row[3] == "LOW": risk_class = "badge-low"
            
            table_html += f"""<tr>
                <td>{row[0]}</td>
                <td>{row[1]}</td>
                <td>{row[2]}</td>
                <td><span class="badge {risk_class}">{row[3]}</span></td>
            </tr>"""
        table_html += "</table>"
        st.markdown(table_html, unsafe_allow_html=True)

# 7. AI Chat Terminal
with col_chat:
    st.subheader("💬 AI Terminal")
    chat_box = st.container(height=520)
    
    with chat_box:
        for m in st.session_state.messages:
            with st.chat_message(m["role"]): st.markdown(m["content"])

    if prompt := st.chat_input("Enter Command..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with chat_box: 
            with st.chat_message("user"): st.markdown(prompt)
            
        # FIXED: Highly strict System-level routing instructions
        instr = f"""You are a strict backend command routing machine. 
        Analyze the user input and output ONLY the exact tool string matching the rules below. 
        Do NOT write introductions, explanations, thoughts, or multiple parts. 

        Rules:
        1. If user wants to scan an IP or port -> output exactly: TOOL: nmap <IP>
        2. If user wants to check/analyze logs -> output exactly: TOOL: log_analyzer <PATH>
        3. If user wants a WHOIS or domain lookup -> output exactly: TOOL: whois <DOMAIN>
        4. If it's a greeting or a general technical question -> just respond normally.

        User Input: {prompt}
        Output:"""
        
        with chat_box:
            with st.chat_message("assistant"):
                with st.spinner("AI Processing..."):
                    decision = llm.invoke(instr).strip()
                
                # --- HANDLERS (With robust fallback extraction) ---
                
                # 1. NMAP SCAN MODIFIED
                if "TOOL: nmap" in decision or "nmap" in decision.lower() or "scan" in prompt.lower():
                    # Fallback: Agar decision mein IP nahi mila to user prompt se nikal lo
                    ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", decision) or re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", prompt)
                    
                    if ip_match:
                        target = ip_match.group(1)
                        add_log(f"Starting Vulnerability & CVE Recon on {target}")
                        st.session_state.total_scans += 1
                        
                        with st.spinner(f"Executing Nmap port discovery on {target}..."):
                            raw = run_nmap(target)
                        
                        cve_prompt = f"""
                        You are an expert Vulnerability Researcher. Analyze these raw Nmap scan results:
                        {raw}
                        
                        For each service found:
                        1. Map it against known CVEs up to 2026.
                        2. Identify available Metasploit modules.
                        3. Assess overall risk level.
                        Format clean and professional with markdown headers.
                        """
                        
                        with st.spinner("Mapping service versions to CVE databases..."):
                            res = llm.invoke(cve_prompt)
                            
                        st.markdown(res)
                        st.session_state.messages.append({"role": "assistant", "content": res})
                        
                        risk_level = "LOW"
                        if any(x in res.upper() for x in ["CRITICAL", "HIGH", "EXPLOIT"]):
                            risk_level = "CRITICAL"
                            st.session_state.threats_found += 1
                        elif "MEDIUM" in res.upper():
                            risk_level = "MEDIUM"
                            st.session_state.threats_found += 1
                            
                        add_history(target, "Vulnerability Scan", risk_level)
                        add_log(f"CVE Assessment generated for {target}")
                    else:
                        st.error("Could not extract a valid target IP address.")

                # 2. LOG ANALYZER MODIFIED
                elif "TOOL: log_analyzer" in decision or "log" in prompt.lower():
                    path_match = re.search(r"TOOL: log_analyzer\s+(.+)", decision) or re.search(r"([\w./-]+\.log)", prompt)
                    if path_match:
                        path = path_match.group(1).strip().replace("<", "").replace(">", "")
                        if os.path.exists(path):
                            add_log(f"Analyzing Log: {path}")
                            st.session_state.threats_found += 1
                            with open(path, "r") as f: 
                                content = "".join(f.readlines()[-40:])
                            
                            with st.spinner("Hunting attack patterns..."):
                                res = llm.invoke("Identify threats in these logs and summarize (Incident Level, Summary, Evidence):\n" + content)
                            st.markdown(res)
                            st.session_state.messages.append({"role": "assistant", "content": res})
                            risk = "CRITICAL" if any(x in res.upper() for x in ["CRITICAL", "HIGH"]) else "MEDIUM"
                            add_history(os.path.basename(path), "Log Analysis", risk)
                            add_log(f"Threat Map Generated for {path}")
                        else:
                            st.error(f"Log file path '{path}' not found on disk.")
                    else:
                        st.error("Could not parse log file path.")

                # 3. WHOIS LOOKUP MODIFIED
                elif "TOOL: whois" in decision or "whois" in prompt.lower():
                    dom_match = re.search(r"TOOL: whois\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", decision) or re.search(r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", prompt)
                    if dom_match:
                        dom = dom_match.group(1)
                        add_log(f"OSINT Lookup: {dom}")
                        
                        with st.spinner(f"Querying WHOIS for {dom}..."):
                            raw = run_whois(dom)
                        with st.spinner("Analyzing domain records..."):
                            res = llm.invoke(f"Summarize WHOIS data for {dom}:\n{raw}")
                        st.markdown(res)
                        st.session_state.messages.append({"role": "assistant", "content": res})
                        add_history(dom, "Domain OSINT", "INFO")
                        add_log(f"WHOIS lookup completed for {dom}")
                    else:
                        st.error("Could not parse domain name.")

                # 4. GENERAL CHAT
                else:
                    st.markdown(decision)
                    st.session_state.messages.append({"role": "assistant", "content": decision})
        st.rerun()
