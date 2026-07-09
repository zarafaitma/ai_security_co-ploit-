import os
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_copilot.db")
if os.path.exists(db_path):
    os.remove(db_path)

import database

print("=== create_database() ===")
assert database.create_database() is True
print("PASS")

print("=== REGRESSION: all pre-existing functions still work ===")
assert database.save_log("regression check") is not None
assert len(database.get_logs(5)) == 1
assert database.save_scan("example.com", "Regression Scan", "LOW", "raw") is not None
assert len(database.get_scan_history(5)) == 1
uid = database.create_user("reg_user", "RegPass123!", "analyst")
assert uid is not None
u = database.get_user("reg_user")
assert u is not None and u["role"] == "analyst"
assert database.verify_password("RegPass123!", u["password_hash"]) is True
assert database.verify_password("wrong", u["password_hash"]) is False
assert database.create_user("reg_user", "AnotherPass1!") is None  # duplicate -> None
assert database.update_user_password("reg_user", "NewPass456!") is True
u2 = database.get_user("reg_user")
assert database.verify_password("NewPass456!", u2["password_hash"]) is True
print("PASS: every pre-existing function behaves exactly as before")

print("\n=== create_job() returns a job_id string, row exists with status=PENDING ===")
job_id = database.create_job(target="example.com", scan_type="nmap")
assert isinstance(job_id, str) and len(job_id) > 0
job = database.get_job_status(job_id)
assert job is not None
assert job["status"] == "PENDING"
assert job["target"] == "example.com"
assert job["scan_type"] == "nmap"
assert job["result"] is None
assert job["error_message"] is None
assert job["created_at"] == job["updated_at"]
print("PASS:", job)

print("=== update_job_status() -> RUNNING (no result/error provided, must stay NULL) ===")
ok = database.update_job_status(job_id, "RUNNING")
assert ok is True
job = database.get_job_status(job_id)
assert job["status"] == "RUNNING"
assert job["result"] is None and job["error_message"] is None
assert job["updated_at"] >= job["created_at"]
print("PASS:", job)

print("=== update_job_status() -> COMPLETED with a result; result persists ===")
ok = database.update_job_status(job_id, "COMPLETED", result="22/tcp open ssh")
assert ok is True
job = database.get_job_status(job_id)
assert job["status"] == "COMPLETED"
assert job["result"] == "22/tcp open ssh"
assert job["error_message"] is None
print("PASS:", job)

print("=== A later status-only update must NOT clobber the stored result (COALESCE check) ===")
database.update_job_status(job_id, "COMPLETED")  # no result passed this time
job = database.get_job_status(job_id)
assert job["result"] == "22/tcp open ssh", "result was wrongly clobbered to NULL"
print("PASS: result preserved across a status-only update")

print("=== Failure path: update_job_status() -> FAILED with error_message ===")
job_id_2 = database.create_job(target="badtarget.invalid", scan_type="whois")
database.update_job_status(job_id_2, "RUNNING")
database.update_job_status(job_id_2, "FAILED", error_message="WHOIS internal registration lookup exception: timed out")
job2 = database.get_job_status(job_id_2)
assert job2["status"] == "FAILED"
assert "timed out" in job2["error_message"]
assert job2["result"] is None
print("PASS:", job2)

print("=== get_job_status() on unknown job_id returns None ===")
assert database.get_job_status("does-not-exist") is None
print("PASS")

print("=== get_pending_jobs() only returns PENDING jobs, oldest first ===")
job_id_3 = database.create_job(target="third.com", scan_type="dig")
job_id_4 = database.create_job(target="fourth.com", scan_type="subdomain")
pending = database.get_pending_jobs(limit=10)
pending_ids = [j["job_id"] for j in pending]
# job_id (COMPLETED) and job_id_2 (FAILED) must NOT appear; job_id_3/4 (still PENDING) must.
assert job_id not in pending_ids
assert job_id_2 not in pending_ids
assert job_id_3 in pending_ids
assert job_id_4 in pending_ids
idx3 = pending_ids.index(job_id_3)
idx4 = pending_ids.index(job_id_4)
assert idx3 < idx4, "expected oldest-first ordering"
print("PASS:", pending_ids)

print("=== get_pending_jobs(limit=1) respects the limit ===")
limited = database.get_pending_jobs(limit=1)
assert len(limited) == 1
print("PASS")

print("\nALL DATABASE.PY JOB-FUNCTION TESTS PASSED (SQLite)")
