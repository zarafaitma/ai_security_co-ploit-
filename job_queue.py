"""
job_queue.py  (Phase 4 hotfix — database-backed job queue)
--------------------------------------------------------------------------
Background worker system built on Python's stdlib
concurrent.futures.ThreadPoolExecutor. Threads (not asyncio) were chosen
because the wrapped functions (recon_tools.run_nmap/run_whois/run_dig/
run_headers/run_subdomain_brute_force) are blocking calls built on
subprocess.run() / socket.gethostbyname() -- wrapping them this way means
NONE of those functions had to be touched or rewritten.

Unlike an in-memory dict, every bit of job state here is persisted via
database.py's create_job() / update_job_status() / get_job_status() /
get_pending_jobs() (backed by the new `jobs` table, SQLite or Postgres
depending on DB_BACKEND -- see database.py). That means:
  - job status survives a process restart or a Streamlit rerun
  - any other process (e.g. backend/api.py, or a future recovery script)
    can see the exact same job state just by reading the database

This module does not import app.py and does not modify any existing scan
function -- it only wraps whatever callable is handed to submit().

Job lifecycle (matches database.py's jobs.status column):
    PENDING -> RUNNING -> COMPLETED
                        -> FAILED

Usage:
    from job_queue import job_queue
    import recon_tools

    job_id = job_queue.submit(recon_tools.run_nmap, "1.2.3.4",
                               target="1.2.3.4", scan_type="nmap")
    job_queue.get_status(job_id)   # -> dict (the raw `jobs` row) or None
    job_queue.get_result(job_id)   # -> result once COMPLETED, raises
                                    #    RuntimeError if FAILED, None if
                                    #    still PENDING/RUNNING or unknown
--------------------------------------------------------------------------
"""

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional

import database

VALID_STATUSES = ("PENDING", "RUNNING", "COMPLETED", "FAILED")


class JobQueue:
    """A ThreadPoolExecutor-backed task runner whose job state lives
    entirely in the database (via database.py), not in this process's
    memory. One instance is meant to be shared (see the module-level
    `job_queue` singleton below) across every caller in the process."""

    def __init__(self, max_workers: int = 4):
        if max_workers < 1:
            raise ValueError("max_workers must be >= 1")
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="job-worker")

    def _run_job(self, job_id: str, func: Callable, args: tuple, kwargs: dict) -> None:
        database.update_job_status(job_id, "RUNNING")
        try:
            result = func(*args, **kwargs)
            database.update_job_status(job_id, "COMPLETED", result=str(result))
        except Exception as e:
            database.update_job_status(job_id, "FAILED", error_message=str(e))

    def submit(self, func: Callable, *args, target: str, scan_type: str, **kwargs) -> Optional[str]:
        """Creates a persisted PENDING job row (via database.create_job)
        and schedules func(*args, **kwargs) to run on the thread pool.
        Returns the job_id immediately (does not block), or None if the
        job record itself couldn't be created."""
        job_id = database.create_job(target=target, scan_type=scan_type)
        if job_id is None:
            return None
        self._executor.submit(self._run_job, job_id, func, args, kwargs)
        return job_id

    def get_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Returns the job's current row from the database, or None if
        job_id is unknown. This is a direct passthrough to
        database.get_job_status() -- the database is the single source of
        truth, there is no separate in-memory copy to go stale."""
        return database.get_job_status(job_id)

    def get_result(self, job_id: str) -> Any:
        """Returns the job's result once status == 'COMPLETED'. Raises
        RuntimeError (wrapping the stored error_message) if the job
        failed. Returns None if the job is unknown or still
        PENDING/RUNNING -- check get_status() first if you need to
        distinguish those."""
        job = database.get_job_status(job_id)
        if not job:
            return None
        if job["status"] == "FAILED":
            raise RuntimeError(job["error_message"])
        if job["status"] == "COMPLETED":
            return job["result"]
        return None

    def list_pending(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns up to `limit` PENDING jobs, oldest first -- a direct
        passthrough to database.get_pending_jobs(), useful for a recovery
        routine after a process restart."""
        return database.get_pending_jobs(limit=limit)


# Shared singleton -- import this, don't construct your own JobQueue(),
# so every caller in the process (FastAPI included) schedules work on the
# same thread pool.
job_queue = JobQueue(max_workers=4)
