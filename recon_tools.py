"""
recon_tools.py  (NEW — supports Phase 3 / Phase 4)
--------------------------------------------------------------------------
Why this file exists: app.py's run_nmap / run_whois / run_dig / run_headers
/ run_subdomain_brute_force are plain, Streamlit-free functions -- but they
are defined *inside* app.py, which also runs top-level Streamlit calls
(st.set_page_config, the CSS st.markdown blocks, the login gate's
st.stop(), etc.) the moment it's imported. A FastAPI process or a
background worker thread can't safely `import app` to reach those
functions without also triggering all of that Streamlit-only code outside
a real Streamlit script run.

So this module is a byte-for-byte mirror of those five functions only,
so backend/api.py and job_queue.py have something safe to import. app.py
itself is completely untouched and keeps using its own copies for the
Streamlit UI -- nothing here is wired back into app.py.

If the two copies ever drift, that's the tradeoff of not touching app.py;
the long-term fix would be a one-line edit in app.py to import from here
instead of defining them inline, which I have NOT done without sign-off.
--------------------------------------------------------------------------
"""

import subprocess
import socket


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
