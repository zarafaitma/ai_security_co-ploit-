"""
backend/api.py  (Phase 3 hotfix — versioned FastAPI REST layer)
--------------------------------------------------------------------------
A separate process from the existing Streamlit app (app.py). Does not
import, modify, or touch app.py in any way -- Streamlit keeps running
exactly as it does today, completely independent of this file.

Imports ONLY the existing, unmodified database.py functions for users/
scans/logs (create_user, get_user, verify_password, save_scan,
get_scan_history, save_log, get_logs), plus the Phase 4 job-tracking
functions added to database.py (create_job/update_job_status/
get_job_status/get_pending_jobs, used indirectly via job_queue.py) and
the two support modules:
    recon_tools.py  -- byte-identical mirrors of app.py's 5 scan functions
                       (see that file's docstring for why a literal
                       `import app` isn't safe to do from here)
    job_queue.py    -- ThreadPoolExecutor-based background runner whose
                       state is persisted via database.py (Phase 4)

Run with EITHER of:
    uvicorn backend.api:app --reload --port 8000
    uvicorn backend.main:app --reload --port 8000      (thin re-export, see backend/main.py)

All endpoints are versioned under /api/v1.

Endpoints
---------
GET    /api/v1/health              {"status": "ok", "service": "AI Security Copilot API"}

POST   /api/v1/users               create a user                      (database.create_user)
GET    /api/v1/users/{username}    fetch user info (no password hash) (database.get_user)
POST   /api/v1/users/login         verify credentials                  (database.get_user + verify_password)

POST   /api/v1/scans               trigger a scan -> background job, returns job_id immediately
GET    /api/v1/scans/history       fetch persisted scan history        (database.get_scan_history)
GET    /api/v1/scans/{job_id}      poll a specific scan job's status/result (database.get_job_status,
                                    via job_queue.get_status -- job_id is the UUID string returned
                                    by POST /api/v1/scans)

GET    /api/v1/logs                fetch system logs                   (database.get_logs)
POST   /api/v1/logs                append a system log                 (database.save_log)

POST   /api/v1/chat                SOC assistant -- identical routing rules & prompt text to
                                    app.py's ROUTE 7 / ROUTE 1 / ROUTE 8 (reproduced verbatim
                                    below, without the Streamlit-only calls)

GET    /api/v1/reports/summary     on-demand aggregate report (risk distribution + recents)
GET    /api/v1/reports/{scan_id}   a single scan_history row formatted as a "report" (there is
                                    no stored report artifact anywhere in the system -- this is
                                    computed from existing scan_history data)
--------------------------------------------------------------------------
"""

import json as _json
import re
import socket
import traceback
from datetime import datetime
from typing import Any, Dict, List, Optional

from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import database
import recon_tools
from queue_factory import job_queue, QUEUE_BACKEND  # Phase 6, Part B: was `from job_queue import job_queue`;
                                                      # job_queue.py itself is unmodified, this just lets the
                                                      # backend pick memory (default) or redis via QUEUE_BACKEND.
from backend.auth import (
    create_access_token,
    create_refresh_token,
    access_token_expires_in_seconds,
    decode_token,
    get_current_user,
    require_role,
    authenticate_user,
)
from backend.rate_limit import RateLimitAndAuditMiddleware
from backend.logging_config import logger, RequestLoggingMiddleware  # Phase 6, Part F
from backend.health_checks import full_health_report  # Phase 6, Part E

try:
    from langchain_ollama import OllamaLLM
    _llm = OllamaLLM(model="qwen2.5:3b")
except Exception:
    _llm = None


# Phase 6, Part F: startup/shutdown logging. Additive -- doesn't change
# any existing route or app behavior, just logs around the process
# lifecycle so ops can see in the logs exactly when the API came up, with
# what config, and when/why it went down.
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        f"AI Security Copilot API starting up | DB_BACKEND={database.DB_BACKEND} "
        f"| QUEUE_BACKEND={QUEUE_BACKEND} | LLM={'online' if _llm else 'offline'}"
    )
    yield
    logger.info("AI Security Copilot API shutting down")


app = FastAPI(
    title="AI Security Copilot API",
    version="1.0.0",
    description="Versioned FastAPI REST layer sitting alongside the existing Streamlit app.",
    lifespan=lifespan,
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Phase 6, Part F: error logging. Only catches exceptions that
    escape every route's own try/except and FastAPI's own HTTPException
    handling (those still behave exactly as before) -- this is purely a
    safety net so an unexpected bug logs a full traceback instead of
    surfacing as an unexplained connection reset."""
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


# Phase 5, Task 4: per-IP + per-user sliding-window rate limiting, plus
# the "API access" item of Task 3's audit logging. Applies to every
# request except the exempt paths defined inside rate_limit.py
# (/api/v1/health, /openapi.json, /docs, /redoc).
app.add_middleware(RateLimitAndAuditMiddleware)

# Phase 6, Part F: plain operational request logging (method/path/status/
# duration), independent of the audit_logs database trail above.
app.add_middleware(RequestLoggingMiddleware)

router = APIRouter(prefix="/api/v1")

DOMAIN_RE = re.compile(r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")
VALID_SCAN_TYPES = ("nmap", "whois", "dig", "headers", "subdomain")

# Exact same SOC-rules prompt templates used in app.py's chat panel (ROUTE 7 / ROUTE 1),
# copied verbatim so the "never hallucinate a CVE / conservative terminology" rules are
# identical regardless of whether the request comes in through Streamlit or this API.
CHAIN_ANALYSIS_PROMPT_TEMPLATE = """
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
{header_data}
--- DNS ZONE DATA ---
{dns_data}
--- NMAP PORT SCAN ---
{nmap_data}
"""

HEADER_ANALYSIS_SCHEMA_PROMPT_TEMPLATE = """
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


# ==============================================================================
# Pydantic request/response models (structured responses + input validation)
# ==============================================================================
class HealthResponse(BaseModel):
    status: str
    service: str


class UserCreate(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1)
    role: str = Field(default="analyst", pattern="^(analyst|admin)$")


class UserLogin(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class UserPublic(BaseModel):
    id: int
    username: str
    role: str
    created_at: str


class LoginResponse(BaseModel):
    username: str
    role: str


# --- NEW (Phase 5, Task 1): JWT auth models, used only by the new
# /api/v1/auth/* routes. The existing UserLogin + LoginResponse models
# above are untouched and still back the original /api/v1/users/login. ---
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    username: str
    role: str


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=1)


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class CurrentUserResponse(BaseModel):
    username: str
    role: str


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=255)
    scan_type: str = Field(..., description=f"One of: {', '.join(VALID_SCAN_TYPES)}")


class ScanTriggerResponse(BaseModel):
    job_id: str
    status: str


class LogCreate(BaseModel):
    message: str = Field(..., min_length=1)


class LogCreateResponse(BaseModel):
    id: int


class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1)


class ChatResponse(BaseModel):
    role: str
    content: Any


class ReportSummaryResponse(BaseModel):
    generated_at: str
    total_scans_in_history: int
    risk_distribution: Dict[str, int]
    recent_scans: List[Dict[str, Any]]
    recent_logs: List[Dict[str, Any]]


def _to_public_user(user: dict) -> UserPublic:
    """Strips password_hash before this ever leaves the process."""
    return UserPublic(id=user["id"], username=user["username"], role=user["role"], created_at=user["created_at"])


# ==============================================================================
# GET /api/v1/health
# ==============================================================================
@router.get("/health", response_model=HealthResponse)
def health_check():
    return HealthResponse(status="ok", service="AI Security Copilot API")


# ==============================================================================
# GET /api/v1/system/health  (NEW — Phase 6, Part E)
# Deeper health check than the simple one above: reports API + database +
# Redis + queue status individually, via backend/health_checks.py. Each
# sub-check is defensive (never raises), so this endpoint always returns
# 200 with a clear picture, even when something downstream is down --
# that's the point of a health endpoint: report the truth, don't crash.
# Open (no auth) like /health, since uptime monitors/load balancers need
# to hit it without a token; also exempt from rate limiting and access
# audit logging (see backend/rate_limit.py's _EXEMPT_PATHS).
# ==============================================================================
@router.get("/system/health")
def system_health_check():
    return full_health_report()


# ==============================================================================
# /api/v1/users  (database.create_user / get_user / verify_password — unmodified)
# Phase 5, Task 2: admin-only. Phase 5, Task 3: audit-logs "user_created".
# ==============================================================================
@router.post("/users", response_model=UserPublic, status_code=201)
def create_user_endpoint(payload: UserCreate, request: Request, current_user: dict = Depends(require_role("admin"))):
    new_id = database.create_user(payload.username, payload.password, payload.role)
    if new_id is None:
        raise HTTPException(status_code=409, detail="Username already exists or creation failed.")
    user = database.get_user(payload.username)
    if not user:
        raise HTTPException(status_code=500, detail="User created but could not be re-fetched.")
    database.save_audit_log(
        "user_created",
        username=current_user["username"],
        ip_address=request.client.host if request.client else None,
        detail=f"created user '{payload.username}' with role '{payload.role}'",
        success=True,
    )
    return _to_public_user(user)


@router.get("/users/{username}", response_model=UserPublic)
def get_user_endpoint(username: str, current_user: dict = Depends(require_role("admin"))):
    user = database.get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return _to_public_user(user)


@router.post("/users/login", response_model=LoginResponse)
def login_endpoint(payload: UserLogin):
    user = database.get_user(payload.username)
    if not user or not database.verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    return LoginResponse(username=user["username"], role=user["role"])


# ==============================================================================
# /api/v1/auth  (NEW — Phase 5, Task 1: JWT issuance/refresh/identity)
# Completely additive. /api/v1/users/login directly above is untouched and
# keeps working exactly as before -- it just doesn't issue tokens. These
# three routes are the JWT-aware entry points; everything they validate
# against (database.get_user / database.verify_password, via
# backend.auth.authenticate_user) is the same existing, unmodified
# credential check.
# ==============================================================================
@router.post("/auth/login", response_model=TokenResponse)
def auth_login(payload: UserLogin, request: Request):
    ip = request.client.host if request.client else None
    user = authenticate_user(payload.username, payload.password)
    if not user:
        database.save_audit_log("login_failed", username=payload.username, ip_address=ip, detail="invalid credentials", success=False)
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    access_token = create_access_token(user["username"], user["role"])
    refresh_token = create_refresh_token(user["username"])
    database.save_audit_log("login_success", username=user["username"], ip_address=ip, detail="issued access+refresh token", success=True)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=access_token_expires_in_seconds(),
        username=user["username"],
        role=user["role"],
    )


@router.post("/auth/refresh", response_model=AccessTokenResponse)
def auth_refresh(payload: RefreshRequest):
    decoded = decode_token(payload.refresh_token)
    if decoded.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="A refresh token is required for this endpoint.")
    username = decoded.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid refresh token payload.")

    # Re-fetch the CURRENT role rather than trusting any role claim on the
    # refresh token (it doesn't carry one) -- if an admin demotes this
    # user between login and refresh, the new access token reflects that
    # immediately instead of preserving stale elevated access.
    user = database.get_user(username)
    if not user:
        raise HTTPException(status_code=401, detail="User no longer exists.")

    new_access_token = create_access_token(user["username"], user["role"])
    return AccessTokenResponse(access_token=new_access_token, expires_in=access_token_expires_in_seconds())


@router.get("/auth/me", response_model=CurrentUserResponse)
def auth_me(current_user: dict = Depends(get_current_user)):
    return CurrentUserResponse(username=current_user["username"], role=current_user["role"])


# ==============================================================================
# /api/v1/scans  (trigger -> database-backed background job via job_queue;
#                 history -> database.get_scan_history)
# Phase 5, Task 2: admin OR analyst. Phase 5, Task 3: audit-logs
# "scan_created" / "scan_completed" / "scan_failed".
# ==============================================================================
def _run_scan_and_persist(scan_type: str, target: str, submitted_by: Optional[str] = None) -> Any:
    """Runs the requested recon tool and records it to scan_history,
    mirroring what app.py's add_history() does -- this is the job_queue
    worker payload. Wraps recon_tools' functions unmodified. Runs on a
    worker thread (via job_queue), so it also reports its own outcome to
    audit_logs since trigger_scan() returns long before this finishes."""
    try:
        if scan_type == "nmap":
            result = recon_tools.run_nmap(target)
        elif scan_type == "whois":
            result = recon_tools.run_whois(target)
        elif scan_type == "dig":
            result = recon_tools.run_dig(target)
        elif scan_type == "headers":
            result = recon_tools.run_headers(target)
        elif scan_type == "subdomain":
            result = recon_tools.run_subdomain_brute_force(target)
        else:
            raise ValueError(f"Unknown scan_type: {scan_type}")

        database.save_scan(target, scan_type, "LOW", str(result))
        database.save_audit_log(
            "scan_completed", username=submitted_by, detail=f"{scan_type}:{target}", success=True
        )
        return result
    except Exception as e:
        database.save_audit_log(
            "scan_failed", username=submitted_by, detail=f"{scan_type}:{target} -> {e}", success=False
        )
        raise


@router.post("/scans", response_model=ScanTriggerResponse, status_code=202)
def trigger_scan(payload: ScanRequest, request: Request, current_user: dict = Depends(require_role("admin", "analyst"))):
    scan_type = payload.scan_type.lower().strip()
    if scan_type not in VALID_SCAN_TYPES:
        raise HTTPException(status_code=400, detail=f"scan_type must be one of: {', '.join(VALID_SCAN_TYPES)}")
    job_id = job_queue.submit(
        _run_scan_and_persist, scan_type, payload.target, current_user["username"],
        target=payload.target, scan_type=scan_type,
    )
    if job_id is None:
        raise HTTPException(status_code=500, detail="Failed to create background job.")
    database.save_audit_log(
        "scan_created",
        username=current_user["username"],
        ip_address=request.client.host if request.client else None,
        detail=f"{scan_type}:{payload.target} (job_id={job_id})",
        success=True,
    )
    return ScanTriggerResponse(job_id=job_id, status="PENDING")


@router.get("/scans/history")
def scan_history_endpoint(limit: int = 50, current_user: dict = Depends(require_role("admin", "analyst"))):
    return database.get_scan_history(limit=limit)


@router.get("/scans/{job_id}")
def scan_job_status(job_id: str, current_user: dict = Depends(require_role("admin", "analyst"))):
    job = job_queue.get_status(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found.")
    return job


# ==============================================================================
# /api/v1/logs  (database.get_logs / save_log — unmodified)
# Phase 5, Task 2: admin only.
# ==============================================================================
@router.get("/logs")
def get_logs_endpoint(limit: int = 100, current_user: dict = Depends(require_role("admin"))):
    return database.get_logs(limit=limit)


@router.post("/logs", response_model=LogCreateResponse, status_code=201)
def append_log_endpoint(payload: LogCreate, current_user: dict = Depends(require_role("admin"))):
    new_id = database.save_log(payload.message)
    if new_id is None:
        raise HTTPException(status_code=500, detail="Failed to save log.")
    return LogCreateResponse(id=new_id)


# ==============================================================================
# /api/v1/chat  (same routing rules + prompts as app.py's panel; see module docstring)
# Phase 5, Task 2: admin OR analyst.
# ==============================================================================
@router.post("/chat", response_model=ChatResponse)
def chat_endpoint(payload: ChatRequest, current_user: dict = Depends(require_role("admin", "analyst"))):
    if not _llm:
        raise HTTPException(status_code=503, detail="AI language model core link offline.")

    prompt = payload.prompt
    prompt_lower = prompt.lower()

    # ROUTE 7: automated infrastructure chain analysis
    if "analyze" in prompt_lower or "fullscan" in prompt_lower:
        dom_match = DOMAIN_RE.search(prompt)
        if not dom_match:
            raise HTTPException(status_code=400, detail="Please provide a valid domain target (e.g. analyze target.com)")
        target_domain = dom_match.group(1)
        database.save_log(f"[API] Chain automation triggered for target: {target_domain}")

        header_data = recon_tools.run_headers(target_domain)
        dns_data = recon_tools.run_dig(target_domain)
        try:
            resolved_ip = socket.gethostbyname(target_domain)
            nmap_data = recon_tools.run_nmap(resolved_ip)
        except Exception:
            resolved_ip = "Unresolved"
            nmap_data = "No responses matched scan footprint thresholds."
            dns_data = "DNS query failed from scanning environment."

        chain_prompt = CHAIN_ANALYSIS_PROMPT_TEMPLATE.format(
            target_domain=target_domain,
            resolved_ip=resolved_ip,
            header_data=header_data if header_data else "No Headers Retrieved",
            dns_data=dns_data,
            nmap_data=nmap_data,
        )
        master_report = _llm.invoke(chain_prompt)
        chain_raw_result = f"--- HTTP HEADERS ---\n{header_data}\n\n--- DNS ZONE DATA ---\n{dns_data}\n\n--- NMAP PORT SCAN ---\n{nmap_data}"
        database.save_scan(target_domain, "Automated Chain Scan", "MEDIUM", chain_raw_result)
        return ChatResponse(role="assistant", content=master_report)

    # ROUTE 1: HTTP response security header audit
    elif "header" in prompt_lower or "http" in prompt_lower:
        dom_match = DOMAIN_RE.search(prompt)
        if not dom_match:
            raise HTTPException(status_code=400, detail="Please provide a valid domain target (e.g. header target.com)")
        target_domain = dom_match.group(1)
        database.save_log(f"[API] HTTP header probe issued to target: {target_domain}")
        captured_raw = recon_tools.run_headers(target_domain)

        if not captured_raw:
            return ChatResponse(role="assistant", content={"error": "No HTTP headers provided for analysis", "status": "insufficient_data"})

        header_prompt = HEADER_ANALYSIS_SCHEMA_PROMPT_TEMPLATE.format(target_domain=target_domain, captured_raw=captured_raw)
        header_report = _llm.invoke(header_prompt)
        clean_json = header_report.replace("```json", "").replace("```", "").strip()
        try:
            json_data = _json.loads(clean_json)
            database.save_scan(target_domain, "HTTP Header Audit", json_data.get("risk_weight", "LOW"), header_report)
            return ChatResponse(role="assistant", content=json_data)
        except Exception:
            database.save_scan(target_domain, "HTTP Header Audit", "LOW", header_report)
            return ChatResponse(role="assistant", content=header_report)

    # ROUTE 8: general chat fallback
    else:
        response = _llm.invoke(prompt)
        return ChatResponse(role="assistant", content=response)


# ==============================================================================
# /api/v1/reports  (computed on demand from existing scan_history/system_logs --
#                    there is no stored "report" entity anywhere in the system)
# Phase 5, Task 2: admin only.
# ==============================================================================
@router.get("/reports/summary", response_model=ReportSummaryResponse)
def report_summary(current_user: dict = Depends(require_role("admin"))):
    history = database.get_scan_history(limit=200)
    logs = database.get_logs(limit=20)
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for row in history:
        if row["risk_level"] in counts:
            counts[row["risk_level"]] += 1
    return ReportSummaryResponse(
        generated_at=datetime.now().isoformat(timespec="seconds"),
        total_scans_in_history=len(history),
        risk_distribution=counts,
        recent_scans=history[:10],
        recent_logs=logs[:10],
    )


@router.get("/reports/{scan_id}")
def report_for_scan(scan_id: int, current_user: dict = Depends(require_role("admin"))):
    history = database.get_scan_history(limit=1000)
    match = next((row for row in history if row["id"] == scan_id), None)
    if not match:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return match


app.include_router(router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
