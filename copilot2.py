import streamlit as st
from langchain_ollama import OllamaLLM
import subprocess
import re

# Page Configuration (Wide Layout)
st.set_page_config(page_title="AI Security Copilot Pro", layout="wide", initial_sidebar_state="expanded")

# Custom Dark Theme CSS Injection
st.markdown("""
    <style>
    .stApp { background-color: #0B0F19; color: #FFFFFF; }
    div[data-testid="stSidebar"] { background-color: #070A12; }
    .metric-card {
        background-color: #111827; border: 1px solid #1F2937;
        padding: 15px; border-radius: 10px; text-align: center;
    }
    </style>
""", unsafe_allow_html=True)

# Cache model so it loads ONLY ONCE
@st.cache_resource
def load_model():
    return OllamaLLM(model="llama3")

llm = load_model()

# Left Sidebar Setup (Like the image)
with st.sidebar:
    st.title("🛡️ AI Security Copilot Pro")
    st.markdown("---")
    st.subheader("Navigation")
    st.button("📊 Dashboard", use_container_width=True)
    st.button("🔍 Vulnerability Explorer", use_container_width=True)
    st.button("📋 Reports", use_container_width=True)
    st.markdown("---")
    st.caption("Status: Secure")
    st.caption("Engine: Llama3 (Local)")

# Main Layout: Split into Dashboard (Left) and AI Chatbot (Right)
col_dash, col_chat = st.columns([2, 1.2]) # 2 parts dashboard, 1.2 parts chat

with col_dash:
    st.header("Dashboard Overview")
    st.write("Monitor your security posture and analysis in real time.")
    
    # Top Row Metrics (Cards like the image)
    m1, m2, m3 = st.columns(3)
    with m1:
        st.markdown('<div class="metric-card"><h3>1,248</h3><p style="color:#9CA3AF;">Logs Analyzed</p></div>', unsafe_allow_html=True)
    with m2:
        st.markdown('<div class="metric-card"><h3 style="color:#EF4444;">37</h3><p style="color:#9CA3AF;">Alerts Detected</p></div>', unsafe_allow_html=True)
    with m3:
        st.markdown('<div class="metric-card"><h3 style="color:#F59E0B;">68</h3><p style="color:#9CA3AF;">Risk Score (Medium)</p></div>', unsafe_allow_html=True)
    
    st.markdown("### Recent Activities & Scan Logs")
    # Placeholder for static/dynamic scan summaries
    st.text_area("Live Terminal Events", value="[INFO] System idle...\n[READY] Awaiting target inputs.", height=300)

with col_chat:
    st.header("💬 AI Copilot")
    
    # Session state to store chat history
    if "messages" not in st.session_state:
        st.session_state.messages = [{"role": "assistant", "content": "Hello Cyber Analyst! I'm your local AI Security Copilot. Give me an IP to scan or ask a query."}]
    
    # Display chat history
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            
    # Chat Input Box
    if user_query := st.chat_input("Ask anything about security..."):
        st.session_state.messages.append({"role": "user", "content": user_query})
        with st.chat_message("user"):
            st.markdown(user_query)
            
        # Agent Logic inside UI
        system_instruction = "You are an expert Cybersecurity AI Copilot. If user asks to scan an IP, reply exactly: TOOL: nmap <IP>. Query: " + user_query
        
        with st.spinner("AI thinking..."):
            ai_decision = llm.invoke(system_instruction).strip()
            
            if "TOOL: nmap" in ai_decision:
                ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", ai_decision)
                if ip_match:
                    target_ip = ip_match.group(1)
                    with st.spinner(f"Running live Nmap scan on {target_ip}..."):
                        # Subprocess run
                        result = subprocess.run(["nmap", "-F", target_ip], capture_output=True, text=True)
                        scan_results = result.stdout
                    
                    # Analyze results
                    analysis_prompt = f"Analyze these Nmap results for {target_ip} and give professional security fixes:\n{scan_results}"
                    final_report = llm.invoke(analysis_prompt)
                    
                    st.session_state.messages.append({"role": "assistant", "content": f"**Scan Result for {target_ip}:**\n\n" + final_report})
                else:
                    st.session_state.messages.append({"role": "assistant", "content": "Could not extract valid IP."})
            else:
                st.session_state.messages.append({"role": "assistant", "content": ai_decision})
                
        st.rerun()
