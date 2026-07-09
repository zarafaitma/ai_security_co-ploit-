from langchain_ollama import OllamaLLM
import subprocess
import re
import os
from datetime import datetime

if not os.path.exists("reports"):
    os.makedirs("reports")

print("Loading Llama3 Model... please wait.")
llm = OllamaLLM(model="llama3")
print("AI Security Copilot Pro Ready!")
print("Commands:")
print("1. Scan IPs (e.g., 'Scan 192.168.1.1')")
print("2. Analyze Logs (e.g., 'Analyze log file web_access.log')")
print("3. Domain Recon (e.g., 'Whois lookup for hackthebox.com')")
print("Type 'exit' to quit.\n")

# --- TOOL 1: NMAP SCAN ---
def execute_nmap_advanced(ip_address):
    print(f"\n[SYSTEM ACTION] Executing Advanced Nmap Scan (-F -sV) on: {ip_address}")
    try:
        result = subprocess.run(["nmap", "-F", "-sV", ip_address], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error running nmap: {str(e)}"

# --- TOOL 2: LOG ANALYZER ---
def analyze_log_file(file_path):
    print(f"\n[SYSTEM ACTION] Reading log file from: {file_path}")
    if not os.path.exists(file_path):
        return f"Error: File '{file_path}' not found."
    try:
        with open(file_path, "r") as f:
            lines = f.readlines()
            log_content = "".join(lines[-40:])
        return log_content
    except Exception as e:
        return f"Error reading log file: {str(e)}"

# --- TOOL 3: WHOIS LOOKUP ---
def execute_whois(domain_name):
    print(f"\n[SYSTEM ACTION] Executing WHOIS Lookup on: {domain_name}")
    try:
        # Running native Linux whois command
        result = subprocess.run(["whois", domain_name], capture_output=True, text=True)
        # Truncating response to 3000 chars to save AI context window
        return result.stdout[:3000]
    except Exception as e:
        return f"Error running whois: {str(e)}"

# System prompt updated for 3 tools + general chat
system_instruction = """
You are an expert Cybersecurity AI Copilot. Analyze the user's request and categorize it strictly.

1. If the user wants to scan an IP address or check ports, respond EXACTLY with:
TOOL: nmap <IP_ADDRESS>

2. If the user wants to analyze a log file or provides a log file path, respond EXACTLY with:
TOOL: log_analyzer <FILE_PATH>

3. If the user wants to do a WHOIS lookup, domain investigation, or check domain ownership, respond EXACTLY with:
TOOL: whois <DOMAIN_NAME>

4. If it's a general cybersecurity or networking question, just reply normally.

User Input: {user_input}
"""

while True:
    try:
        user_query = input("\nCopilot CLI > ").strip()
        if user_query.lower() in ['exit', 'quit', 'clear']:
            print("Exiting Copilot. Stay safe!")
            break
        if not user_query:
            continue

        # AI Router Decision
        formatted_prompt = system_instruction.format(user_input=user_query)
        ai_decision = llm.invoke(formatted_prompt).strip()

        # --- CASE 1: NMAP SCAN ---
        if "TOOL: nmap" in ai_decision:
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", ai_decision)
            if ip_match:
                target_ip = ip_match.group(1)
                scan_results = execute_nmap_advanced(target_ip)
                
                analysis_prompt = f"You are a Cybersecurity AI Copilot. Review these Nmap scan results for target {target_ip} and give a professional security assessment:\n{scan_results}"
                print("[SYSTEM] AI is analyzing the scan results...")
                final_report = llm.invoke(analysis_prompt)
                
                print("\n=== COPILOT SECURITY REPORT ===")
                print(final_report)
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                with open(f"reports/scan_{target_ip}_{timestamp}.txt", "w") as f:
                    f.write(final_report)
                print(f"\n[SUCCESS] Scan report saved.")
            else:
                print("\n[ERROR] Valid IP not found.")

        # --- CASE 2: LOG ANALYZER ---
        elif "TOOL: log_analyzer" in ai_decision:
            path_match = re.search(r"TOOL: log_analyzer\s+(.+)", ai_decision)
            if path_match:
                file_path = path_match.group(1).strip()
                raw_logs = analyze_log_file(file_path)
                
                if "Error:" in raw_logs:
                    print(raw_logs)
                    continue
                
                log_prompt = """
                You are an elite Incident Response and SOC Analyst. Analyze these raw logs (SSH or Apache Web logs).
                Identify attack patterns (Brute Force, SQLi, XSS, Directory Traversal) and output in this template:
                📊 LOG TYPE IDENTIFIED: 
                🔥 INCIDENT LEVEL: 
                📝 THREAT SUMMARY: 
                🎯 DETECTED EVIDENCE: (IPs, Payloads, Timestamps)
                🛡️ ACTIONABLE REMEDIATION:
                """
                print("[SYSTEM] AI is parsing logs and hunting for attack patterns...")
                log_analysis_report = llm.invoke(f"{log_prompt}\n\nRaw Logs:\n{raw_logs}")
                
                print("\n=== AI LOG ANALYSIS REPORT ===")
                print(log_analysis_report)
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                log_filename = os.path.basename(file_path).replace('.', '_')
                with open(f"reports/log_analysis_{log_filename}_{timestamp}.txt", "w") as f:
                    f.write(log_analysis_report)
                print(f"\n[SUCCESS] Log threat analysis report saved.")

        # --- CASE 3: WHOIS LOOKUP (NEW!) ---
        elif "TOOL: whois" in ai_decision:
            # Extract domain (e.g., example.com)
            domain_match = re.search(r"TOOL: whois\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", ai_decision)
            if domain_match:
                target_domain = domain_match.group(1)
                whois_raw_data = execute_whois(target_domain)
                
                whois_prompt = f"""
                You are an expert Cyber OSINT Analyst. Review this raw WHOIS lookup data for the domain '{target_domain}'.
                Extract and summarize the key intelligence fields professionally:
                1. Domain Registrar & Owner Organization
                2. Important Dates (Creation, Expiry, Last Updated)
                3. Name Servers (NS Records)
                4. Operational Security Insights (Is the owner data redacted/hidden for privacy? Are there any anomalies?)
                
                Raw WHOIS Data:
                {whois_raw_data}
                """
                print("[SYSTEM] AI is analyzing WHOIS records for threat intelligence...")
                whois_report = llm.invoke(whois_prompt)
                
                print("\n=== AI OSINT DOMAIN REPORT ===")
                print(whois_report)
                
                # Auto-Save OSINT Report
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                with open(f"reports/whois_{target_domain}_{timestamp}.txt", "w") as f:
                    f.write(whois_report)
                print(f"\n[SUCCESS] OSINT Domain report saved.")
            else:
                print("\n[ERROR] Valid domain name could not be parsed.")

        # --- CASE 4: GENERAL CHAT ---
        else:
            print("\n=== COPILOT RESPONSE ===")
            print(ai_decision)

    except KeyboardInterrupt:
        print("\nExiting gracefully...")
        break
