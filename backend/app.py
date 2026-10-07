"""
CyberSentinel Test Website — FastAPI Backend
============================================
Purpose  : Serve the frontend and log all incoming HTTP requests.
Future   : Traffic-capture middleware and ML integration will plug in here.
"""

import asyncio
import json
import logging
import math
import os
import pickle
import queue
import time
import urllib.parse
import urllib.request
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

logger = logging.getLogger("novatech")

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
MAX_LOG_ENTRIES = 500          # Keep the last N entries in memory
LOG_STORE: deque[dict[str, Any]] = deque(maxlen=MAX_LOG_ENTRIES)
FLOW_STORE: queue.Queue = queue.Queue(maxsize=2000)
PREDICTION_HISTORY: deque[dict[str, Any]] = deque(maxlen=500)

# CyberSentinel backend URL for forwarding incoming requests for analysis
CYBERSENTINEL_API_URL = os.getenv(
    "CYBERSENTINEL_API_URL", "http://127.0.0.1:8000/api/traffic-events"
).strip()

# ---------------------------------------------------------------------------
# Load feature columns (the 78 CIC-IDS2017 feature names from the trained model)
# ---------------------------------------------------------------------------

_FEATURE_COLS_PATH = Path(__file__).parent / "feature_columns.pkl"
with open(_FEATURE_COLS_PATH, "rb") as _f:
    FEATURE_COLUMNS: list[str] = pickle.load(_f)

assert len(FEATURE_COLUMNS) == 78, (
    f"feature_columns.pkl must contain exactly 78 names, got {len(FEATURE_COLUMNS)}"
)

# ---------------------------------------------------------------------------
# Load ML Model and Label Encoder
# ---------------------------------------------------------------------------
import joblib

try:
    _MODEL_PATH = Path(__file__).parent / "cybersentinel_model.pkl"
    _LE_PATH = Path(__file__).parent / "label_encoder.pkl"
    MODEL = joblib.load(_MODEL_PATH)
    LABEL_ENCODER = joblib.load(_LE_PATH)
    print(f"[*] CyberSentinel Model & Label Encoder loaded successfully.")
except Exception as e:
    print(f"[!] Warning: ML model failed to load. Error: {e}")
    MODEL = None
    LABEL_ENCODER = None

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CyberSentinel Test Website",
    description=(
        "A realistic small-business website used as the protected/test target "
        "for the CyberSentinel AI intrusion-detection project."
    ),
    version="1.0.0",
)

# Allow the React/Vue dev-server during local development if needed later
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Forward incoming requests to deployed CyberSentinel backend
# ---------------------------------------------------------------------------

async def forward_to_cybersentinel(entry: dict[str, Any]) -> None:
    """
    Asynchronously forwards incoming request metadata to the deployed CyberSentinel
    backend without blocking NovaTech's HTTP response.
    """
    target = os.getenv("CYBERSENTINEL_API_URL", CYBERSENTINEL_API_URL).strip()
    if not target:
        return

    url = target.rstrip("/")
    parsed = urllib.parse.urlparse(url)
    if not parsed.path or parsed.path == "/":
        url = f"{url}/api/traffic-events"
    elif parsed.path.endswith("/api/ingest-flow"):
        url = url[:-len("/api/ingest-flow")] + "/api/traffic-events"

    # Forward authentic HTTP request metadata only — no fabricated CIC-IDS2017 features
    payload = {
        "id": entry["id"],
        "timestamp": entry["timestamp"],
        "method": entry["method"],
        "path": entry["path"],
        "query": entry["query"],
        "client_ip": entry["client_ip"],
        "user_agent": entry["user_agent"],
        "status_code": entry["status_code"],
        "response_time_ms": entry["response_time_ms"],
    }

    def _post():
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "NovaTech-Forwarder/1.0",
                "X-Forwarded-From": "NovaTech-Test-Website",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.status

    try:
        await asyncio.to_thread(_post)
    except Exception as exc:
        logger.debug(f"[forwarder] Forwarding to CyberSentinel ({url}) failed: {exc}")

# ---------------------------------------------------------------------------
# Request-logging middleware
# ---------------------------------------------------------------------------

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """
    Intercepts every HTTP request and records key metadata.
    This hook is intentionally separate from the business-logic routes
    so that a traffic-capture / feature-extraction layer can be inserted
    here later without touching the rest of the code.
    """
    start_time = time.perf_counter()

    response = await call_next(request)

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)

    # Resolve real client IP (handles X-Forwarded-For for reverse proxies)
    forwarded_for = request.headers.get("x-forwarded-for")
    client_ip = forwarded_for.split(",")[0].strip() if forwarded_for else (
        request.client.host if request.client else "unknown"
    )

    entry: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "method": request.method,
        "path": str(request.url.path),
        "query": str(request.url.query) if request.url.query else None,
        "client_ip": client_ip,
        "user_agent": request.headers.get("user-agent", "unknown"),
        "status_code": response.status_code,
        "response_time_ms": elapsed_ms,
    }

    LOG_STORE.append(entry)

    # Forward to CyberSentinel backend asynchronously if configured
    asyncio.create_task(forward_to_cybersentinel(entry))

    # Add a custom response header so CyberSentinel can trace the log entry
    response.headers["X-Log-ID"] = entry["id"]
    response.headers["X-Response-Time"] = f"{elapsed_ms}ms"

    return response


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@app.get("/health", tags=["monitoring"])
async def health_check():
    """Returns the current server health status."""
    return {
        "status": "ok",
        "service": "CyberSentinel Test Website",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "log_entries_stored": len(LOG_STORE),
        "cybersentinel_forwarding_configured": bool(os.getenv("CYBERSENTINEL_API_URL", CYBERSENTINEL_API_URL)),
    }


@app.get("/api/request-log", tags=["monitoring"])
async def get_request_log(limit: int = 100):
    """
    Returns the most recent request log entries.

    Query params:
        limit (int): Maximum number of entries to return (default 100, max 500).

    Future integration point:
        Each entry here will be enriched with 78 CIC-IDS2017 features
        and passed through the Random Forest model before being returned.
    """
    limit = max(1, min(limit, MAX_LOG_ENTRIES))
    entries = list(LOG_STORE)[-limit:]
    return JSONResponse(content={
        "total_stored": len(LOG_STORE),
        "returned": len(entries),
        "entries": entries,
    })


@app.get("/api/feature-columns", tags=["ml-pipeline"])
async def get_feature_columns():
    """
    Returns the 78 CIC-IDS2017 feature names in their exact trained order.
    This is the ground truth for what the ML layer expects.
    """
    return JSONResponse(content={
        "count": len(FEATURE_COLUMNS),
        "feature_columns": FEATURE_COLUMNS,
    })


@app.post("/api/ingest-flow", tags=["ml-pipeline"])
async def ingest_flow(feat_dict: dict[str, Any]):
    """
    Receives a single network flow feature vector from the capture process,
    runs the ML model prediction, and stores it in the queue.
    """
    actual_keys = list(feat_dict.keys())
    if actual_keys != FEATURE_COLUMNS:
        raise HTTPException(
            status_code=400, 
            detail="Feature mismatch. Must be exactly 78 features in correct order."
        )
    
    X_single = []
    for k in FEATURE_COLUMNS:
        v = feat_dict[k]
        if not isinstance(v, (int, float)):
            raise HTTPException(status_code=400, detail=f"Feature '{k}' must be numeric")
        if math.isnan(v) or math.isinf(v):
            raise HTTPException(status_code=400, detail=f"Feature '{k}' cannot be NaN or Infinite")
        X_single.append(v)
            
    if MODEL and LABEL_ENCODER:
        try:
            pred_idx = MODEL.predict([X_single])[0]
            label = LABEL_ENCODER.inverse_transform([pred_idx])[0]
            
            risk_level = "Low" if label == "BENIGN" else "High"
            
            feat_dict["prediction"] = label
            feat_dict["risk_level"] = risk_level
        except Exception as e:
            feat_dict["prediction"] = "Error"
            feat_dict["risk_level"] = "Unknown"
            print(f"[!] Prediction error: {e}")
    else:
        feat_dict["prediction"] = "Model Not Loaded"
        feat_dict["risk_level"] = "Unknown"

    try:
        FLOW_STORE.put_nowait(feat_dict)
    except queue.Full:
        try:
            FLOW_STORE.get_nowait()
            FLOW_STORE.put_nowait(feat_dict)
        except queue.Empty:
            pass

    PREDICTION_HISTORY.append(feat_dict)
            
    return {"status": "ok", "message": "Flow ingested and predicted"}


@app.get("/api/flow-features", tags=["ml-pipeline"])
async def get_flow_features(limit: int = 50):
    """
    Returns recently completed network-flow feature vectors (each with 78 features).
    """
    flows = []
    max_count = max(1, min(limit, 200))
    for _ in range(max_count):
        try:
            flows.append(FLOW_STORE.get_nowait())
        except queue.Empty:
            break

    return JSONResponse(content={
        "note": "These are real CIC-IDS2017 features enriched with ML predictions.",
        "returned": len(flows),
        "feature_count": 78,
        "feature_columns": FEATURE_COLUMNS,
        "flows": flows,
    })


@app.get("/api/live-predictions", tags=["ml-pipeline"])
async def live_predictions(limit: int = 50):
    """
    Alias to flow-features, intended for the frontend to poll for live ML predictions.
    """
    return await get_flow_features(limit=limit)


@app.get("/api/recent-predictions", tags=["ml-pipeline"])
async def get_recent_predictions(limit: int = 50):
    """
    Read-only endpoint: returns the latest predictions without removing anything
    from PREDICTION_HISTORY or draining FLOW_STORE.
    """
    limit = max(1, min(limit, 500))
    entries = list(PREDICTION_HISTORY)[-limit:]
    return JSONResponse(content={
        "total_stored": len(PREDICTION_HISTORY),
        "returned": len(entries),
        "feature_count": len(FEATURE_COLUMNS),
        "feature_columns": FEATURE_COLUMNS,
        "predictions": entries,
        "flows": entries,
    })


@app.get("/api/capture-status", tags=["ml-pipeline"])
async def capture_status():
    """
    Returns the current state of the traffic capture component.
    """
    return JSONResponse(content={
        "capture_running": True,  # Always true or unknown, FastAPI doesn't track process state directly anymore
        "queued_feature_vectors": FLOW_STORE.qsize(),
        "feature_columns_loaded": len(FEATURE_COLUMNS),
    })


# ---------------------------------------------------------------------------
# Frontend static-file serving
# ---------------------------------------------------------------------------
# Mount AFTER the API routes so /api/* is never shadowed.

if FRONTEND_DIR.exists():
    # Serve CSS, JS, images, etc.
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    # Serve the SPA shell for every non-API, non-static path
    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_frontend(full_path: str):
        # Try the exact file first (e.g. /styles.css → frontend/styles.css)
        requested = FRONTEND_DIR / full_path
        if requested.is_file():
            return FileResponse(str(requested))
        # Fall back to index.html for client-side routing
        return FileResponse(str(FRONTEND_DIR / "index.html"))


# ---------------------------------------------------------------------------
# Entry point (used when running directly: python app.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
