"""
backend/logging_config.py  (NEW — Phase 6, Part F)
--------------------------------------------------------------------------
Production-safe logging for the FastAPI backend. Separate from
audit_logs (Phase 5, in the database -- structured *security* events) and
separate from system_logs (Phase 1/4, Streamlit's own log feed) -- this
is operational/application logging: request lines, startup/shutdown,
and uncaught errors with tracebacks, written to a rotating file (and the
console).

Environment variables:
    LOG_LEVEL    default: "INFO"
    LOG_FORMAT   "text" (default, human-readable) or "json" (structured,
                 one JSON object per line -- recommended in production
                 for log-aggregation tools like ELK/Datadog/CloudWatch)
    LOG_DIR      default: "logs"   (created if missing)
    LOG_FILE     default: "api.log"
    LOG_MAX_BYTES     default: 10485760 (10 MB) per file before rotating
    LOG_BACKUP_COUNT  default: 5   (keep 5 rotated files = up to 60MB total)
--------------------------------------------------------------------------
"""

import json
import logging
import os
import time
from logging.handlers import RotatingFileHandler

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.environ.get("LOG_FORMAT", "text").lower()
LOG_DIR = os.environ.get("LOG_DIR", "logs")
LOG_FILE = os.environ.get("LOG_FILE", "api.log")
LOG_MAX_BYTES = int(os.environ.get("LOG_MAX_BYTES", str(10 * 1024 * 1024)))
LOG_BACKUP_COUNT = int(os.environ.get("LOG_BACKUP_COUNT", "5"))

LOGGER_NAME = "ai_security_copilot.api"


class JsonFormatter(logging.Formatter):
    """One JSON object per line -- easy for log shippers to parse, unlike
    multi-line tracebacks mixed into free text."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        extra_fields = getattr(record, "extra_fields", None)
        if extra_fields:
            payload.update(extra_fields)
        return json.dumps(payload)


def setup_logging() -> logging.Logger:
    """Idempotent -- safe to call more than once, won't duplicate handlers."""
    logger = logging.getLogger(LOGGER_NAME)
    if logger.handlers:
        return logger

    logger.setLevel(LOG_LEVEL)
    logger.propagate = False

    if LOG_FORMAT == "json":
        formatter = JsonFormatter()
    else:
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        file_handler = RotatingFileHandler(
            os.path.join(LOG_DIR, LOG_FILE),
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError as e:
        logger.warning(f"Could not set up file logging at {LOG_DIR}/{LOG_FILE}: {e}. Logging to console only.")

    return logger


logger = setup_logging()


from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Separate from backend/rate_limit.py's middleware (which writes
    structured *audit* rows to the database for security events) -- this
    writes plain operational log lines for every request, useful for
    ops/debugging independent of the audit trail."""

    async def dispatch(self, request: Request, call_next):
        start = time.monotonic()
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = round((time.monotonic() - start) * 1000, 2)
            logger.error(
                f"{request.method} {request.url.path} -> UNHANDLED EXCEPTION ({duration_ms}ms)",
                exc_info=True,
            )
            raise
        duration_ms = round((time.monotonic() - start) * 1000, 2)
        logger.info(f"{request.method} {request.url.path} -> {response.status_code} ({duration_ms}ms)")
        return response
