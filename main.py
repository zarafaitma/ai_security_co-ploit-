"""
backend/main.py  (Phase 3 hotfix — conventional entrypoint)
--------------------------------------------------------------------------
Some FastAPI tooling/deploy scripts default to looking for `backend.main`
rather than `backend.api`. This file just re-exports the real `app`
object defined in backend/api.py -- no logic lives here.

Run with either:
    uvicorn backend.api:app  --reload --port 8000
    uvicorn backend.main:app --reload --port 8000
--------------------------------------------------------------------------
"""

from backend.api import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
