"""
redis_queue.py  (NEW — Phase 6, Part B)
--------------------------------------------------------------------------
An OPTIONAL Redis-backed alternative to job_queue.py's in-process
ThreadPoolExecutor queue. job_queue.py itself is completely untouched --
this is a second, independent implementation living in its own file,
selected at runtime via queue_factory.py (also new) based on the
QUEUE_BACKEND environment variable. Nothing about job_queue.py's class,
methods, or behavior changed to make this exist.

Why this exists alongside job_queue.py rather than replacing it: the
in-memory/DB-backed queue from Phase 4 is simple, has zero extra
infrastructure dependencies, and is exactly right for a single-process
deployment. Redis becomes valuable once you want job state visible to
OTHER processes/containers (e.g. multiple API replicas behind nginx, or a
dedicated worker container) without them all hitting the SQL database for
queue bookkeeping, plus Redis gives cheap building blocks for retry
counters and queue-depth health checks. Both are legitimate choices for
different deployment sizes, so both are kept, picked via config.

Design:
  - Job metadata (status, target, scan_type, result, error, retry count,
    timestamps) is stored as a Redis HASH at key `job:{job_id}`.
  - Pending work items are pushed as job_ids onto a Redis LIST
    (`job_queue:pending`); a background consumer thread BLPOPs from that
    list and executes the job.
  - Tasks are referenced by a string name (not a raw Python function --
    those can't survive being read back by a separate worker process),
    resolved through a small in-process task registry. submit() accepts
    an actual callable for interface-compatibility with job_queue.py's
    JobQueue.submit(), and auto-registers it under its
    `__module__.__qualname__` the first time it's submitted.
  - Honesty about scope: the consumer thread that executes jobs runs
    INSIDE this same Python process (started once, on import) -- this is
    not yet a separate multi-process/multi-container worker fleet. The
    data layout (Redis list + hash) is exactly what a standalone worker
    process would also use, so splitting the consumer out into its own
    container later is a config/deployment change, not a redesign -- but
    that split hasn't been done here, and I'm not claiming it has.
  - Retry support: on an unhandled exception, the job is requeued (pushed
    back onto the pending list) up to REDIS_QUEUE_MAX_RETRIES times
    (default 3) before being marked FAILED for good.

Environment variables:
    REDIS_URL                  default: redis://localhost:6379/0
    REDIS_QUEUE_MAX_RETRIES    default: 3
    REDIS_QUEUE_KEY_PREFIX     default: "job"      (hash keys: job:{id})
    REDIS_QUEUE_LIST_KEY       default: "job_queue:pending"
--------------------------------------------------------------------------
"""

import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

try:
    import redis as _redis_lib
    _REDIS_AVAILABLE = True
except ImportError:
    _REDIS_AVAILABLE = False

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
REDIS_QUEUE_MAX_RETRIES = int(os.environ.get("REDIS_QUEUE_MAX_RETRIES", "3"))
REDIS_QUEUE_KEY_PREFIX = os.environ.get("REDIS_QUEUE_KEY_PREFIX", "job")
REDIS_QUEUE_LIST_KEY = os.environ.get("REDIS_QUEUE_LIST_KEY", "job_queue:pending")

VALID_STATUSES = ("PENDING", "RUNNING", "COMPLETED", "FAILED")

_task_registry: Dict[str, Callable] = {}


def _task_key(func: Callable) -> str:
    return f"{func.__module__}.{func.__qualname__}"


def register_task(name: str, func: Callable) -> None:
    """Explicitly registers a callable under a stable name. submit() also
    auto-registers by qualified name, but a worker running in a fresh
    process needs its tasks registered (imported) before it can execute
    anything it pops off the list -- call this at process startup for any
    task you expect a separate worker process to run."""
    _task_registry[name] = func


class RedisJobQueue:
    """Drop-in alternative to job_queue.JobQueue -- same four public
    methods (submit/get_status/get_result/list_pending), backed by Redis
    instead of an in-process dict + the SQL `jobs` table."""

    def __init__(self, redis_url: str = REDIS_URL, max_retries: int = REDIS_QUEUE_MAX_RETRIES, start_consumer: bool = True):
        if not _REDIS_AVAILABLE:
            raise RuntimeError("redis_queue.py requires the 'redis' package. Run: pip install redis")
        self.max_retries = max_retries
        self._client = _redis_lib.from_url(redis_url, decode_responses=True)
        self._consumer_thread: Optional[threading.Thread] = None
        if start_consumer:
            self._start_consumer()

    # ---- internal helpers ----------------------------------------------
    def _job_key(self, job_id: str) -> str:
        return f"{REDIS_QUEUE_KEY_PREFIX}:{job_id}"

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _start_consumer(self) -> None:
        self._consumer_thread = threading.Thread(target=self._consume_loop, name="redis-queue-consumer", daemon=True)
        self._consumer_thread.start()

    def _consume_loop(self) -> None:
        while True:
            try:
                popped = self._client.blpop(REDIS_QUEUE_LIST_KEY, timeout=5)
                if popped is None:
                    continue
                _, job_id = popped
                self._execute(job_id)
            except _redis_lib.exceptions.ConnectionError:
                # Redis unreachable -- back off and retry rather than
                # crashing the consumer thread permanently.
                time.sleep(2)
            except Exception:
                # Defensive: never let the consumer thread die from an
                # unexpected error in bookkeeping; the job itself already
                # has its own try/except in _execute().
                time.sleep(0.5)

    def _execute(self, job_id: str) -> None:
        key = self._job_key(job_id)
        job = self._client.hgetall(key)
        if not job:
            return  # job hash expired or was never created -- nothing to do

        task_name = job.get("task_name")
        func = _task_registry.get(task_name)
        if func is None:
            self._client.hset(key, mapping={
                "status": "FAILED",
                "error_message": f"No task registered for '{task_name}' in this process.",
                "updated_at": self._now(),
            })
            return

        self._client.hset(key, mapping={"status": "RUNNING", "updated_at": self._now()})
        try:
            args = json.loads(job.get("args", "[]"))
            kwargs = json.loads(job.get("kwargs", "{}"))
            result = func(*args, **kwargs)
            self._client.hset(key, mapping={
                "status": "COMPLETED",
                "result": str(result),
                "updated_at": self._now(),
            })
        except Exception as e:
            retries = int(job.get("retries", "0"))
            if retries < self.max_retries:
                self._client.hset(key, mapping={
                    "status": "PENDING",
                    "retries": retries + 1,
                    "error_message": f"Attempt {retries + 1} failed: {e}",
                    "updated_at": self._now(),
                })
                self._client.rpush(REDIS_QUEUE_LIST_KEY, job_id)
            else:
                self._client.hset(key, mapping={
                    "status": "FAILED",
                    "error_message": f"Failed after {retries + 1} attempt(s): {e}",
                    "updated_at": self._now(),
                })

    # ---- public interface (mirrors job_queue.JobQueue) -----------------
    def submit(self, func: Callable, *args, target: str, scan_type: str, **kwargs) -> Optional[str]:
        """Creates a job hash + pushes it onto the pending list. Auto-
        registers `func` under its qualified name so this same process's
        consumer thread can resolve and run it."""
        task_name = _task_key(func)
        register_task(task_name, func)

        job_id = uuid.uuid4().hex
        now = self._now()
        self._client.hset(self._job_key(job_id), mapping={
            "job_id": job_id,
            "task_name": task_name,
            "target": target,
            "scan_type": scan_type,
            "status": "PENDING",
            "created_at": now,
            "updated_at": now,
            "result": "",
            "error_message": "",
            "retries": 0,
            "args": json.dumps(list(args)),
            "kwargs": json.dumps(kwargs),
        })
        self._client.rpush(REDIS_QUEUE_LIST_KEY, job_id)
        return job_id

    def get_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        job = self._client.hgetall(self._job_key(job_id))
        if not job:
            return None
        job["retries"] = int(job.get("retries", "0"))
        job["result"] = job.get("result") or None
        job["error_message"] = job.get("error_message") or None
        return job

    def get_result(self, job_id: str) -> Any:
        job = self.get_status(job_id)
        if not job:
            return None
        if job["status"] == "FAILED":
            raise RuntimeError(job["error_message"])
        if job["status"] == "COMPLETED":
            return job["result"]
        return None

    def list_pending(self, limit: int = 50) -> List[Dict[str, Any]]:
        ids = self._client.lrange(REDIS_QUEUE_LIST_KEY, 0, limit - 1)
        jobs = [self.get_status(jid) for jid in ids]
        return [j for j in jobs if j is not None]

    # ---- health check (Phase 6, Part E) ---------------------------------
    def health(self) -> Dict[str, Any]:
        """Used by GET /api/v1/system/health. Never raises -- any failure
        to reach Redis is reported as status='down' instead of bubbling
        up as a 500 from the health endpoint itself."""
        try:
            start = time.monotonic()
            pong = self._client.ping()
            latency_ms = round((time.monotonic() - start) * 1000, 2)
            queue_depth = self._client.llen(REDIS_QUEUE_LIST_KEY)
            return {
                "status": "up" if pong else "down",
                "latency_ms": latency_ms,
                "queue_depth": queue_depth,
            }
        except Exception as e:
            return {"status": "down", "error": str(e)}
