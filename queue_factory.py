"""
queue_factory.py  (NEW — Phase 6, Part B)
--------------------------------------------------------------------------
Selects which job-queue implementation the rest of the app talks to,
based on the QUEUE_BACKEND environment variable:

    QUEUE_BACKEND=memory (default)  -> job_queue.job_queue (Phase 4, untouched)
    QUEUE_BACKEND=redis             -> redis_queue.RedisJobQueue instance

Both implementations expose the exact same four methods (submit/
get_status/get_result/list_pending), so backend/api.py only needs to
change ONE import line (`from job_queue import job_queue` ->
`from queue_factory import job_queue`) to become backend-agnostic --
every route's actual call to job_queue.submit(...)/get_status(...) etc.
is completely unchanged.

job_queue.py itself was NOT modified to make this work.
--------------------------------------------------------------------------
"""

import os

QUEUE_BACKEND = os.environ.get("QUEUE_BACKEND", "memory").strip().lower()

if QUEUE_BACKEND == "redis":
    from redis_queue import RedisJobQueue
    job_queue = RedisJobQueue()
else:
    from job_queue import job_queue  # noqa: F401  (Phase 4's existing singleton, untouched)
