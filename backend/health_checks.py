"""
backend/health_checks.py  (NEW — Phase 6, Part E)
--------------------------------------------------------------------------
Individual health-check functions, each returning a small dict and never
raising -- a failed check is reported as {"status": "down", ...}, not an
exception, so GET /api/v1/system/health can always return a 200 with a
clear picture of what's broken, rather than itself erroring out.
--------------------------------------------------------------------------
"""

import time
from typing import Any, Dict

import database
from queue_factory import job_queue, QUEUE_BACKEND


def check_database() -> Dict[str, Any]:
    """Confirms the configured database backend (SQLite or Postgres, per
    database.DB_BACKEND) is actually reachable, by running the cheapest
    real read already exposed: get_logs(limit=1)."""
    try:
        start = time.monotonic()
        database.get_logs(limit=1)
        latency_ms = round((time.monotonic() - start) * 1000, 2)
        return {"status": "up", "backend": database.DB_BACKEND, "latency_ms": latency_ms}
    except Exception as e:
        return {"status": "down", "backend": database.DB_BACKEND, "error": str(e)}


def check_redis() -> Dict[str, Any]:
    """Reports Redis status. If QUEUE_BACKEND isn't 'redis', Redis isn't
    part of this deployment at all -- reported as 'not_configured' rather
    than 'down', since "down" would wrongly imply something is broken."""
    if QUEUE_BACKEND != "redis":
        return {"status": "not_configured", "detail": "QUEUE_BACKEND is not 'redis'"}
    try:
        return job_queue.health()
    except Exception as e:
        return {"status": "down", "error": str(e)}


def check_queue() -> Dict[str, Any]:
    """Reports the active queue backend's basic reachability -- for the
    in-memory/DB-backed queue (Phase 4) that just means "can we read job
    state from the database", since that queue has no separate process to
    ping. For the Redis queue, this mirrors check_redis()."""
    try:
        if QUEUE_BACKEND == "redis":
            redis_health = job_queue.health()
            return {"status": redis_health.get("status", "down"), "backend": "redis", **redis_health}
        else:
            pending = database.get_pending_jobs(limit=1)
            return {"status": "up", "backend": "memory", "detail": "DB-backed job tracking reachable"}
    except Exception as e:
        return {"status": "down", "backend": QUEUE_BACKEND, "error": str(e)}


def full_health_report() -> Dict[str, Any]:
    db = check_database()
    redis_status = check_redis()
    queue = check_queue()

    overall_ok = db["status"] == "up" and queue["status"] == "up" and redis_status["status"] in ("up", "not_configured")

    return {
        "api": {"status": "up"},
        "database": db,
        "redis": redis_status,
        "queue": queue,
        "overall_status": "ok" if overall_ok else "degraded",
    }
