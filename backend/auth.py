"""
backend/auth.py  (NEW — Phase 5, Part A + Part B)
--------------------------------------------------------------------------
JWT issuance/validation and role-based-access-control (RBAC) dependencies
for the FastAPI backend (backend/api.py). Completely separate from
app.py's own Streamlit session-based login (Phase 1) -- that system is
untouched and keeps working exactly as before. This module only protects
the REST API.

Design notes:
  - Stateless JWTs (HS256, signed with JWT_SECRET_KEY). No server-side
    token store/blacklist, so no Redis/DB dependency is introduced here --
    consistent with earlier instructions not to add Redis. The tradeoff:
    a token can't be individually revoked before it expires. Keeping
    access tokens short-lived (default 30 min) is the usual mitigation.
  - Password verification itself is unchanged -- still PBKDF2-HMAC-SHA256
    via database.py's existing verify_password()/_hash_password(). This
    module only adds a token layer on TOP of that existing check.
  - RBAC is implemented as FastAPI dependency-injection guards
    (get_current_user / require_role), the idiomatic FastAPI approach for
    per-route authorization -- functionally equivalent to "middleware"
    that runs before each protected route, but more precise than a single
    global ASGI middleware would be, since required roles differ route by
    route. The cross-cutting concerns that genuinely apply uniformly to
    every request (audit logging of API access, rate limiting) are
    instead implemented as real ASGI middleware in backend/rate_limit.py.

Environment variables (all optional, sane defaults for local/dev use):
    JWT_SECRET_KEY                  default: an insecure dev-only constant
                                     (CHANGE THIS IN PRODUCTION)
    JWT_ALGORITHM                   default: "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES default: 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS   default: 7
--------------------------------------------------------------------------
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

import database

JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-only-insecure-secret-CHANGE-ME")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
JWT_REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7"))

_bearer_scheme = HTTPBearer(auto_error=True)


# ==============================================================================
# Token creation
# ==============================================================================
def create_access_token(username: str, role: str) -> str:
    """Short-lived token used to authorize API requests. Carries the role
    so route guards don't need a DB round-trip on every request."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token(username: str) -> str:
    """Longer-lived token used only to mint new access tokens. Deliberately
    does NOT carry a role claim -- /api/v1/auth/refresh re-fetches the
    user's CURRENT role from the database, so a role change takes effect
    immediately instead of waiting for the refresh token to also expire."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "type": "refresh",
        "iat": now,
        "exp": now + timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def access_token_expires_in_seconds() -> int:
    return JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60


# ==============================================================================
# Token validation
# ==============================================================================
def decode_token(token: str) -> dict:
    """Decodes + validates signature/expiry. Raises HTTPException(401) on
    any failure (expired, malformed, wrong signature)."""
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token.")


def decode_token_best_effort(token: str) -> Optional[dict]:
    """Same as decode_token(), but returns None instead of raising. Used
    by the audit/rate-limit middleware, which must never block a request
    just because its token happens to be invalid/expired -- that's the
    protected route's job via get_current_user() below."""
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.InvalidTokenError:
        return None


# ==============================================================================
# FastAPI dependencies (RBAC guards)
# ==============================================================================
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme)) -> dict:
    """Validates the bearer token and returns {"username": ..., "role": ...}.
    Use as a dependency on any route that simply requires *some*
    authenticated user, regardless of role."""
    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="An access token is required for this endpoint.")
    username = payload.get("sub")
    role = payload.get("role")
    if not username or not role:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload.")
    return {"username": username, "role": role}


def require_role(*allowed_roles: str):
    """Dependency factory: require_role("admin") or require_role("admin", "analyst").
    Returns a dependency that 403s if the authenticated user's role isn't
    in allowed_roles."""
    def _checker(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This endpoint requires one of these roles: {', '.join(allowed_roles)}.",
            )
        return user
    return _checker


def authenticate_user(username: str, password: str) -> Optional[dict]:
    """Looks up the user and verifies their password via the EXISTING,
    unmodified database.get_user()/verify_password() functions. Returns
    the user dict (including password_hash) on success, or None on
    failure -- this is the one place password verification happens; token
    issuance in backend/api.py only runs after this succeeds."""
    user = database.get_user(username)
    if not user or not database.verify_password(password, user["password_hash"]):
        return None
    return user
