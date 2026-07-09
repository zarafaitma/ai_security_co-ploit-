"""
backend/rate_limit.py  (Phase 5, Task 4 + the "API access" item of Task 3)
--------------------------------------------------------------------------
Two cross-cutting concerns that apply uniformly to every request, so
unlike RBAC (route-by-route, see backend/auth.py) these are implemented
as a single real ASGI middleware:

  1. Rate limiting -- per-IP AND per-username sliding-window counters,
     configurable via RATE_LIMIT_REQUESTS_PER_MINUTE (default 100).
     Returns HTTP 429 when either limit is exceeded.

  2. API-access audit logging -- every non-exempt request gets one row in
     the audit_logs table (event_type="api_access") via
     database.save_audit_log(), satisfying Task 3's "API access" item.

In-memory only (no Redis -- consistent with earlier instructions not to
add Redis). This means rate limits are per-process: fine for the current
single uvicorn process; with multiple worker processes each would track
its own counters, so the effective limit becomes (configured limit x
worker count). Flagging that now rather than letting it be a surprise --
a correct multi-process limiter needs a shared store, out of scope here.

/api/v1/health and the OpenAPI/docs routes are exempt from both rate
limiting and access-audit logging (standard practice: don't let infra
health checks trip the limiter or flood the audit log).
--------------------------------------------------------------------------
"""

import os
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

import database
from backend.auth import decode_token_best_effort

RATE_LIMIT_REQUESTS_PER_MINUTE = int(os.environ.get("RATE_LIMIT_REQUESTS_PER_MINUTE", "100"))
RATE_LIMIT_WINDOW_SECONDS = 60

# Paths exempt from rate limiting AND access-audit logging.
_EXEMPT_PATHS = {"/api/v1/health", "/api/v1/system/health", "/openapi.json", "/docs", "/redoc"}


class SlidingWindowRateLimiter:
    """A minimal, dependency-free per-key sliding-window counter. The
    middleware below uses two independent instances of this class -- one
    keyed by client IP, one keyed by authenticated username."""

    def __init__(self, max_requests: int = RATE_LIMIT_REQUESTS_PER_MINUTE, window_seconds: int = RATE_LIMIT_WINDOW_SECONDS):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """Returns True if `key` is still under the limit (and records
        this call as a hit), False if the limit is already exceeded."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            bucket = self._hits[key]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                return False
            bucket.append(now)
            return True


_ip_limiter = SlidingWindowRateLimiter()
_user_limiter = SlidingWindowRateLimiter()


def _extract_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _extract_username_best_effort(request: Request) -> Optional[str]:
    """Reads a username off the Authorization header without ever raising
    -- an invalid/expired/missing token just means "no username for
    rate-limit/audit purposes"; the real 401 (if any) is still decided
    later by the route's own get_current_user() dependency."""
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return None
    token = auth_header[7:].strip()
    payload = decode_token_best_effort(token)
    return payload.get("sub") if payload else None


class RateLimitAndAuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in _EXEMPT_PATHS:
            return await call_next(request)

        ip = _extract_client_ip(request)
        username = _extract_username_best_effort(request)

        ip_ok = _ip_limiter.allow(f"ip:{ip}")
        user_ok = _user_limiter.allow(f"user:{username}") if username else True

        if not ip_ok or not user_ok:
            database.save_audit_log(
                "rate_limit_exceeded",
                username=username,
                ip_address=ip,
                detail=f"{request.method} {path}",
                success=False,
            )
            return JSONResponse(
                status_code=429,
                content={"detail": f"Rate limit exceeded ({RATE_LIMIT_REQUESTS_PER_MINUTE} requests/minute). Try again later."},
            )

        response = await call_next(request)

        database.save_audit_log(
            "api_access",
            username=username,
            ip_address=ip,
            detail=f"{request.method} {path} -> {response.status_code}",
            success=response.status_code < 400,
        )

        return response
