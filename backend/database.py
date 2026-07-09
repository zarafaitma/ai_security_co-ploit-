"""
database.py
--------------------------------------------------------------------------
Persistence layer for AI Security Copilot Pro / ReconToolkit.

Defaults to a local SQLite file (security_copilot.db, stdlib-only,
sqlite3 + hashlib) so the app keeps working out of the box with zero
configuration. Set DB_BACKEND=postgres in the environment to point the
exact same public functions at a PostgreSQL database instead -- function
names, signatures, and return shapes are identical either way; only the
storage backend changes.

Tables (users / scan_history / system_logs):
    users          - operator accounts (id, username, password_hash, role, created_at)
    scan_history   - every recon/scan operation run from the app
    system_logs    - the raw application log stream

Public API (all parameterized SQL -> no injection vectors), unchanged
regardless of backend:
    create_database()                                        -> bool
    save_scan(target, scan_type, risk_level, raw_result="")  -> int | None
    get_scan_history(limit=50)                                -> list[dict]
    save_log(log_message)                                      -> int | None
    get_logs(limit=100)                                          -> list[dict]
    create_user(username, password, role="analyst")          -> int | None
    get_user(username)                                          -> dict | None
    verify_password(password, stored_hash)                    -> bool

Environment variables (all optional -- SQLite is the default backend):
    DB_BACKEND      "sqlite" (default) or "postgres"
    DATABASE_URL    full PostgreSQL DSN, e.g. postgresql://user:pass@host:5432/dbname
                    (if set, this takes priority over the discrete PG_* vars below)
    PG_HOST         default "localhost"
    PG_PORT         default "5432"
    PG_DATABASE     default "security_copilot"
    PG_USER         default "postgres"
    PG_PASSWORD     default ""

If a .env file is present and python-dotenv happens to be installed, it's
loaded automatically. Neither PostgreSQL support nor dotenv are required
for the default SQLite mode -- psycopg2 is only imported if DB_BACKEND is
actually set to "postgres".
--------------------------------------------------------------------------
"""

import sqlite3
import hashlib
import os
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import psycopg2
    import psycopg2.extras
    import psycopg2.errors
    _PSYCOPG2_AVAILABLE = True
except ImportError:
    _PSYCOPG2_AVAILABLE = False

# DB file lives next to this module, so it doesn't matter which directory
# `streamlit run` is launched from. Only used in the (default) SQLite mode.
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_copilot.db")

# --------------------------------------------------------------------------
# Backend selection (NEW - Phase 2). Defaults to "sqlite" so any existing
# deployment with no environment configuration at all behaves exactly as
# it did before this file was touched.
# --------------------------------------------------------------------------
DB_BACKEND = os.environ.get("DB_BACKEND", "sqlite").strip().lower()

PG_DATABASE_URL = os.environ.get("DATABASE_URL")
PG_HOST = os.environ.get("PG_HOST", "localhost")
PG_PORT = os.environ.get("PG_PORT", "5432")
PG_DATABASE = os.environ.get("PG_DATABASE", "security_copilot")
PG_USER = os.environ.get("PG_USER", "postgres")
PG_PASSWORD = os.environ.get("PG_PASSWORD", "")

# Streamlit can touch shared resources from more than one thread across
# reruns. SQLite connections aren't safe to share across threads, so every
# function below opens its own short-lived connection, and writes are
# additionally serialized with this lock to avoid "database is locked"
# errors under concurrent access. Applied for both backends for simplicity.
_db_lock = threading.Lock()


@contextmanager
def _get_connection():
    """Yields a DB connection (SQLite by default, or PostgreSQL when
    DB_BACKEND=postgres) with sane defaults; commits/rolls back
    automatically either way. This is the ONLY place that knows which
    backend is active -- every public function below stays backend-agnostic."""
    if DB_BACKEND == "postgres":
        if not _PSYCOPG2_AVAILABLE:
            raise RuntimeError(
                "[database.py] DB_BACKEND=postgres but psycopg2 is not installed. "
                "Run: pip install psycopg2-binary"
            )
        conn = None
        try:
            if PG_DATABASE_URL:
                conn = psycopg2.connect(PG_DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
            else:
                conn = psycopg2.connect(
                    host=PG_HOST,
                    port=PG_PORT,
                    dbname=PG_DATABASE,
                    user=PG_USER,
                    password=PG_PASSWORD,
                    cursor_factory=psycopg2.extras.RealDictCursor,
                )
            yield conn
            conn.commit()
        except Exception as e:
            if conn:
                conn.rollback()
            raise RuntimeError(f"[database.py] PostgreSQL operation failed: {e}") from e
        finally:
            if conn:
                conn.close()
    else:
        conn = None
        try:
            conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
            conn.execute("PRAGMA foreign_keys = ON")
            conn.row_factory = sqlite3.Row
            yield conn
            conn.commit()
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            raise RuntimeError(f"[database.py] SQLite operation failed: {e}") from e
        finally:
            if conn:
                conn.close()


def _adapt_placeholders(sql: str) -> str:
    """Translates SQLite '?' parameter placeholders to psycopg2 '%s' when
    DB_BACKEND=postgres. Safe here because every query in this module uses
    '?' exclusively as a placeholder, never as literal data."""
    return sql.replace("?", "%s") if DB_BACKEND == "postgres" else sql


def _insert_and_get_id(cur, sqlite_sql: str, postgres_sql: str, params: tuple) -> Optional[int]:
    """Runs one INSERT and returns the new row's id, abstracting over the
    sqlite3 cursor.lastrowid vs PostgreSQL 'RETURNING id' difference."""
    if DB_BACKEND == "postgres":
        cur.execute(postgres_sql, params)
        row = cur.fetchone()
        return row["id"] if row else None
    cur.execute(sqlite_sql, params)
    return cur.lastrowid


def create_database() -> bool:
    """
    Creates the required tables/indexes for whichever backend is active
    (SQLite by default, or PostgreSQL when DB_BACKEND=postgres). Uses
    CREATE TABLE IF NOT EXISTS, so it's safe to call on every app startup
    either way. Returns True on success, False on failure.
    """
    try:
        with _db_lock, _get_connection() as conn:
            cur = conn.cursor()
            if DB_BACKEND == "postgres":
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id            SERIAL PRIMARY KEY,
                        username      TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        role          TEXT NOT NULL DEFAULT 'analyst',
                        created_at    TEXT NOT NULL DEFAULT (NOW()::TEXT)
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id          SERIAL PRIMARY KEY,
                        target      TEXT NOT NULL,
                        scan_type   TEXT NOT NULL,
                        risk_level  TEXT NOT NULL,
                        timestamp   TEXT NOT NULL DEFAULT (NOW()::TEXT),
                        raw_result  TEXT
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS system_logs (
                        id          SERIAL PRIMARY KEY,
                        log_message TEXT NOT NULL,
                        created_at  TEXT NOT NULL DEFAULT (NOW()::TEXT)
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS jobs (
                        id            SERIAL PRIMARY KEY,
                        job_id        TEXT NOT NULL UNIQUE,
                        target        TEXT,
                        scan_type     TEXT,
                        status        TEXT NOT NULL DEFAULT 'PENDING',
                        created_at    TEXT NOT NULL DEFAULT (NOW()::TEXT),
                        updated_at    TEXT NOT NULL DEFAULT (NOW()::TEXT),
                        result        TEXT,
                        error_message TEXT
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id          SERIAL PRIMARY KEY,
                        event_type  TEXT NOT NULL,
                        username    TEXT,
                        ip_address  TEXT,
                        detail      TEXT,
                        success     INTEGER NOT NULL DEFAULT 1,
                        created_at  TEXT NOT NULL DEFAULT (NOW()::TEXT)
                    )
                """)
            else:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id            INTEGER PRIMARY KEY AUTOINCREMENT,
                        username      TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        role          TEXT NOT NULL DEFAULT 'analyst',
                        created_at    TEXT NOT NULL DEFAULT (datetime('now'))
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        target      TEXT NOT NULL,
                        scan_type   TEXT NOT NULL,
                        risk_level  TEXT NOT NULL,
                        timestamp   TEXT NOT NULL DEFAULT (datetime('now')),
                        raw_result  TEXT
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS system_logs (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        log_message TEXT NOT NULL,
                        created_at  TEXT NOT NULL DEFAULT (datetime('now'))
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS jobs (
                        id            INTEGER PRIMARY KEY AUTOINCREMENT,
                        job_id        TEXT NOT NULL UNIQUE,
                        target        TEXT,
                        scan_type     TEXT,
                        status        TEXT NOT NULL DEFAULT 'PENDING',
                        created_at    TEXT NOT NULL DEFAULT (datetime('now')),
                        updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
                        result        TEXT,
                        error_message TEXT
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type  TEXT NOT NULL,
                        username    TEXT,
                        ip_address  TEXT,
                        detail      TEXT,
                        success     INTEGER NOT NULL DEFAULT 1,
                        created_at  TEXT NOT NULL DEFAULT (datetime('now'))
                    )
                """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_history(timestamp)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_created ON system_logs(created_at)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_logs(event_type)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at)")
        return True
    except Exception as e:
        print(f"[database.py] create_database() failed: {e}")
        return False


def save_scan(target: str, scan_type: str, risk_level: str, raw_result: str = "") -> Optional[int]:
    """Inserts one scan_history row. Returns the new row id, or None on failure."""
    try:
        with _db_lock, _get_connection() as conn:
            cur = conn.cursor()
            params = (target, scan_type, risk_level, datetime.now().isoformat(timespec="seconds"), raw_result)
            return _insert_and_get_id(
                cur,
                "INSERT INTO scan_history (target, scan_type, risk_level, timestamp, raw_result) VALUES (?, ?, ?, ?, ?)",
                "INSERT INTO scan_history (target, scan_type, risk_level, timestamp, raw_result) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                params,
            )
    except Exception as e:
        print(f"[database.py] save_scan() failed: {e}")
        return None


def get_scan_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Returns up to `limit` most recent scan_history rows (newest first) as plain dicts."""
    try:
        with _db_lock, _get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                _adapt_placeholders(
                    """
                    SELECT id, target, scan_type, risk_level, timestamp, raw_result
                    FROM scan_history
                    ORDER BY id DESC
                    LIMIT ?
                    """
                ),
                (limit,),
            )
            return [dict(row) for row in cur.fetchall()]
    except Exception as e:
        print(f"[database.py] get_scan_history() failed: {e}")
        return []


def save_log(log_message: str) -> Optional[int]:
    """Inserts one system_logs row. Returns the new row id, or None on failure."""
    try:
        with _db_lock, _get_connection() as conn:
            cur = conn.cursor()
            params = (log_message, datetime.now().isoformat(timespec="seconds"))
            return _insert_and_get_id(
                cur,
                "INSERT INTO system_logs (log_message, created_at) VALUES (?, ?)",
                "INSERT INTO system_logs (log_message, created_at) VALUES (%s, %s) RETURNING id",
                params,
            )
    except Exception as e:
        print(f"[database.py] save_log() failed: {e}")
        return None


def get_logs(limit: int = 100) -> List[Dict[str, Any]]:
    """Returns up to `limit` most recent system_logs rows (newest first)."""
    try:
        with _db_lock, _get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                _adapt_placeholders(
                    """
                    SELECT id, log_message, created_at
                    FROM system_logs
                    ORDER BY id DESC
                    LIMIT ?
                    """
                ),
                (limit,),
            )
            return [dict(row) for row in cur.fetchall()]
    except Exception as e:
        print(f"[database.py] get_logs() failed: {e}")
        return []


# --------------------------------------------------------------------------
# User-account helpers (wired into app.py's new login screen / Phase 1).
# --------------------------------------------------------------------------

def _hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """PBKDF2-HMAC-SHA256, stdlib only. Stored as 'salt_hex:hash_hex'."""
    if salt is None:
        salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"{salt.hex()}:{derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Checks a plaintext password against a stored 'salt_hex:hash_hex' string."""
    try:
        salt_hex, hash_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
        return derived.hex() == hash_hex
    except Exception:
        return False


def create_user(username: str, password: str, role: str = "analyst") -> Optional[int]:
    """Inserts one user with a securely hashed password. Returns new id, or None on failure
    (including when the username already exists, for either backend)."""
    try:
        with _db_lock, _get_connection() as conn:
            cur = conn.cursor()
            params = (username, _hash_password(password), role, datetime.now().isoformat(timespec="seconds"))
            return _insert_and_get_id(
                cur,
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (%s, %s, %s, %s) RETURNING id",
                params,
            )
    except Exception as e:
        # _get_connection() wraps the original driver error in a RuntimeError
        # (see "raise ... from e" above), so the original exception is on
        # __cause__ rather than being `e` itself -- check there for a
        # duplicate-username violation on either backend.
        cause = e.__cause__
        is_duplicate = isinstance(cause, sqlite3.IntegrityError) or (
            _PSYCOPG2_AVAILABLE and isinstance(cause, psycopg2.errors.UniqueViolation)
        )
        if is_duplicate:
            print(f"[database.py] create_user() failed: username '{username}' already exists")
        else:
            print(f"[database.py] create_user() failed: {e}")
        return None


def get_user(username: str) -> Optional[Dict[str, Any]]:
    """Fetches one user row by username, or None if not found."""
    try:
        with _db_lock, _get_connection() as conn:
            cur = conn.cursor()
            cur.execute(_adapt_placeholders("SELECT * FROM users WHERE username = ?"), (username,))
            row = cur.fetchone()
            return dict(row) if row else None
    except Exception as e:
        print(f"[database.py] get_user() failed: {e}")
        return None


# --------------------------------------------------------------------------
# Background job persistence (NEW — Phase 4 hotfix). Backs job_queue.py so
# job state survives process restarts / Streamlit reruns, instead of living
# only in an in-memory dict. None of the functions above this line were
# changed to add this -- the only edits anywhere else in this file are the
# new `jobs` CREATE TABLE statements inside create_database() (both
# backends) and the new `import uuid` at the top.
# --------------------------------------------------------------------------

def create_job(target: str, scan_type: str) -> Optional[str]:
    """Creates one job row with status='PENDING' and a freshly generated
    UUID job_id (the external identifier other functions/endpoints use to
    look the job up). Returns the new job_id string, or None on failure."""
    try:
        job_id = uuid.uuid4().hex
        now = datetime.now().isoformat(timespec="seconds")
        with _db_lock, _get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                _adapt_placeholders(
                    """
                    INSERT INTO jobs (job_id, target, scan_type, status, created_at, updated_at)
                    VALUES (?, ?, ?, 'PENDING', ?, ?)
                    """
                ),
                (job_id, target, scan_type, now, now),
            )
        return job_id
    except Exception as e:
        print(f"[database.py] create_job() failed: {e}")
        return None


def update_job_status(
    job_id: str,
    status: str,
    result: Optional[str] = None,
    error_message: Optional[str] = None,
) -> bool:
    """Updates a job's status (+ updated_at timestamp). `result` and
    `error_message` are only overwritten when explicitly provided (via
    COALESCE), so e.g. transitioning to RUNNING doesn't blank out a
    previously stored value. Valid statuses: PENDING, RUNNING, COMPLETED,
    FAILED (not enforced at the DB layer, same convention as risk_level
    elsewhere in this file). Returns True on success, False on failure."""
    try:
        now = datetime.now().isoformat(timespec="seconds")
        with _db_lock, _get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                _adapt_placeholders(
                    """
                    UPDATE jobs
                    SET status = ?,
                        updated_at = ?,
                        result = COALESCE(?, result),
                        error_message = COALESCE(?, error_message)
                    WHERE job_id = ?
                    """
                ),
                (status, now, result, error_message, job_id),
            )
        return True
    except Exception as e:
        print(f"[database.py] update_job_status() failed: {e}")
        return False


def get_job_status(job_id: str) -> Optional[Dict[str, Any]]:
    """Fetches one job row by job_id, or None if not found."""
    try:
        with _db_lock, _get_connection() as conn:
            cur = conn.cursor()
            cur.execute(_adapt_placeholders("SELECT * FROM jobs WHERE job_id = ?"), (job_id,))
            row = cur.fetchone()
            return dict(row) if row else None
    except Exception as e:
        print(f"[database.py] get_job_status() failed: {e}")
        return None


def get_pending_jobs(limit: int = 50) -> List[Dict[str, Any]]:
    """Returns up to `limit` PENDING jobs, oldest first -- intended for a
    worker (or a recovery routine on process restart) to pick up."""
    try:
        with _db_lock, _get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                _adapt_placeholders(
                    """
                    SELECT * FROM jobs
                    WHERE status = 'PENDING'
                    ORDER BY created_at ASC
                    LIMIT ?
                    """
                ),
                (limit,),
            )
            return [dict(row) for row in cur.fetchall()]
    except Exception as e:
        print(f"[database.py] get_pending_jobs() failed: {e}")
        return []


# --------------------------------------------------------------------------
# Audit logging (NEW — Phase 5 Part C). A separate `audit_logs` table from
# the existing `system_logs` table -- system_logs (and its save_log/
# get_logs functions above) are completely untouched. audit_logs is for
# structured, queryable security events (logins, scan lifecycle, user
# management, API access) consumed by backend/api.py's auth/audit/
# rate-limit layer.
# --------------------------------------------------------------------------

def save_audit_log(
    event_type: str,
    username: Optional[str] = None,
    ip_address: Optional[str] = None,
    detail: Optional[str] = None,
    success: bool = True,
) -> Optional[int]:
    """Inserts one audit_logs row. Returns the new row id, or None on
    failure. `success` is stored as 1/0 (works identically on SQLite and
    Postgres, avoiding any backend-specific boolean type handling)."""
    try:
        now = datetime.now().isoformat(timespec="seconds")
        with _db_lock, _get_connection() as conn:
            cur = conn.cursor()
            params = (event_type, username, ip_address, detail, 1 if success else 0, now)
            return _insert_and_get_id(
                cur,
                "INSERT INTO audit_logs (event_type, username, ip_address, detail, success, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                "INSERT INTO audit_logs (event_type, username, ip_address, detail, success, created_at) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                params,
            )
    except Exception as e:
        print(f"[database.py] save_audit_log() failed: {e}")
        return None


def get_audit_logs(limit: int = 100) -> List[Dict[str, Any]]:
    """Returns up to `limit` most recent audit_logs rows (newest first)."""
    try:
        with _db_lock, _get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                _adapt_placeholders(
                    """
                    SELECT id, event_type, username, ip_address, detail, success, created_at
                    FROM audit_logs
                    ORDER BY id DESC
                    LIMIT ?
                    """
                ),
                (limit,),
            )
            return [dict(row) for row in cur.fetchall()]
    except Exception as e:
        print(f"[database.py] get_audit_logs() failed: {e}")
        return []


if __name__ == "__main__":
    # Manual smoke test: `python3 database.py` (respects DB_BACKEND like everything else)
    print(f"Backend: {DB_BACKEND}")
    print("create_database():", create_database())
    print("save_log():", save_log("Manual smoke test entry"))
    print("get_logs(5):", get_logs(5))
    print("save_scan():", save_scan("example.com", "Smoke Test", "LOW", "raw output sample"))
    print("get_scan_history(5):", get_scan_history(5))
    print("create_user():", create_user("test_operator", "Tmp_P@ssw0rd!"))
    u = get_user("test_operator")
    print("get_user():", u)
    print("verify_password() correct:", verify_password("Tmp_P@ssw0rd!", u["password_hash"]))
    print("verify_password() wrong:", verify_password("wrong-password", u["password_hash"]))


def update_user_password(username: str, new_password: str) -> bool:
    try:
        with _db_lock, _get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                _adapt_placeholders(
                    "UPDATE users SET password_hash = ? WHERE username = ?"
                ),
                (_hash_password(new_password), username)
            )
        return True
    except Exception as e:
        print(f"[database.py] update_user_password failed: {e}")
        return False
