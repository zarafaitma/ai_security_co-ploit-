import os
import time

db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_copilot.db")
if os.path.exists(db_path):
    os.remove(db_path)

import database
database.create_database()

from job_queue import job_queue

def slow_success(n, delay=0.3):
    time.sleep(delay)
    return n * 2

def slow_failure(delay=0.2):
    time.sleep(delay)
    raise ValueError("boom")

print("=== 1. Basic lifecycle: PENDING -> RUNNING -> COMPLETED, persisted in DB ===")
jid = job_queue.submit(slow_success, 21, target="21", scan_type="test_success")
status = job_queue.get_status(jid)
assert status["status"] in ("PENDING", "RUNNING"), status  # worker may pick it up almost instantly
assert job_queue.get_result(jid) is None
time.sleep(0.05)
status = job_queue.get_status(jid)
assert status["status"] in ("RUNNING", "COMPLETED"), status
time.sleep(0.5)
status = job_queue.get_status(jid)
assert status["status"] == "COMPLETED", status
assert status["result"] == "42", status  # stored as TEXT
assert job_queue.get_result(jid) == "42"
# Independently confirm via database.py directly (not just job_queue's passthrough)
direct = database.get_job_status(jid)
assert direct["status"] == "COMPLETED" and direct["result"] == "42"
print("PASS")

print("=== 2. Failure path: status=FAILED, get_result raises ===")
jid2 = job_queue.submit(slow_failure, target="n/a", scan_type="test_failure")
time.sleep(0.5)
status2 = job_queue.get_status(jid2)
assert status2["status"] == "FAILED", status2
assert "boom" in status2["error_message"]
try:
    job_queue.get_result(jid2)
    raise AssertionError("expected RuntimeError")
except RuntimeError as e:
    assert "boom" in str(e)
print("PASS")

print("=== 3. Unknown job_id -> None, no exception ===")
assert job_queue.get_status("nope") is None
assert job_queue.get_result("nope") is None
print("PASS")

print("=== 4. Concurrency: many jobs across the thread pool all complete ===")
def instant(x):
    return x
ids = [job_queue.submit(instant, i, target=str(i), scan_type="test_concurrency") for i in range(15)]
time.sleep(1.0)
statuses = [job_queue.get_status(i)["status"] for i in ids]
assert all(s == "COMPLETED" for s in statuses), statuses
print("PASS")

print("=== 5. 'Survives restart' simulation: status is readable from a FRESH process-like import ===")
# Simulate a totally separate process by re-reading status purely through
# database.py functions, with no reference to the original job_queue
# instance's in-memory state (there isn't any -- that's the point).
fresh_job = database.get_job_status(jid)
assert fresh_job["status"] == "COMPLETED" and fresh_job["result"] == "42"
print("PASS: job state independently readable from the database alone")

print("=== 6. list_pending() reflects only not-yet-finished jobs ===")
slow_id = job_queue.submit(slow_success, 5, delay=2.0, target="5", scan_type="test_pending")
time.sleep(0.05)
pending = job_queue.list_pending(limit=50)
pending_ids = [j["job_id"] for j in pending]
# It may already be RUNNING by the time we check (race), so just confirm
# completed ones from step 4 are NOT in the pending list.
assert ids[0] not in pending_ids
print("PASS:", f"{len(pending)} still-pending job(s) visible")

print("\nALL JOB_QUEUE.PY TESTS PASSED (DB-backed)")
