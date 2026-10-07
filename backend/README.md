# CyberSentinel Test Website — Backend

## Purpose
This FastAPI server acts as the HTTP backend for the **CyberSentinel Test Website** — a realistic small-business site used as the protected/test target for the CyberSentinel AI intrusion-detection project.

## What it does
- Serves the frontend (`../frontend/`) as static files
- Logs every incoming HTTP request (timestamp, method, path, client IP, user-agent, status code, response time)
- Exposes two monitoring endpoints:
  - `GET /health` — server status
  - `GET /api/request-log?limit=N` — last N request log entries as JSON

## Future integration points (not yet implemented)
- Traffic capture & 78 CIC-IDS2017 feature extraction → plug into the `log_requests` middleware in `app.py`
- Random Forest model inference → enrich `/api/request-log` entries with predictions

## Quick start

```bash
# 1. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the server
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

The website is then available at **http://localhost:8000**.

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Returns `{ "status": "ok", ... }` |
| `/api/request-log` | GET | Returns last request logs as JSON. Add `?limit=N` (default 100). |
| `/docs` | GET | Auto-generated Swagger UI |
| `/redoc` | GET | Auto-generated ReDoc UI |
