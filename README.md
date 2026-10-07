# CyberSentinel Test Website

> **Protected/Test Website for the CyberSentinel AI Intrusion Detection Project**

This is a standalone, realistic small-business website ("NovaTech Solutions") that acts as the **target** being monitored by CyberSentinel AI. It is completely separate from the CyberSentinel AI dashboard and must not be confused with it.

---

## Project Structure

```
cybersentinel-test/
├── backend/
│   ├── app.py              # FastAPI server — serves frontend + logs all requests
│   ├── requirements.txt    # Python dependencies
│   └── README.md           # Backend-specific documentation
├── frontend/
│   ├── index.html          # Single-page website (5 pages: Home, About, Products, Login, Contact)
│   ├── styles.css          # Full responsive stylesheet
│   └── script.js           # SPA navigation, animations, form handlers
└── README.md               # ← You are here
```

---

## Quick Start (macOS)

### 1 — Prerequisites

```bash
# Verify Python 3.9+ is installed
python3 --version
```

### 2 — Set up the backend

```bash
cd cybersentinel-test/backend

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3 — Run the server

```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

The website is now live at **[http://localhost:8000](http://localhost:8000)**.

---

## Verify Everything Works

Open a second terminal tab and run these checks:

```bash
# 1. Health endpoint
curl -s http://localhost:8000/health | python3 -m json.tool

# 2. Generate some traffic by hitting the site, then check the log
curl -s "http://localhost:8000/api/request-log?limit=20" | python3 -m json.tool

# 3. Visit the auto-generated API docs
open http://localhost:8000/docs
```

Expected `/health` response:
```json
{
  "status": "ok",
  "service": "CyberSentinel Test Website",
  "timestamp": "...",
  "log_entries_stored": 2
}
```

---

## Monitoring Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Server health status |
| `/api/request-log?limit=N` | GET | Last N logged requests (default 100) |
| `/docs` | GET | Interactive Swagger UI |
| `/redoc` | GET | ReDoc API documentation |

---

## Request Log Schema

Each entry in `/api/request-log` contains:

```json
{
  "id":               "uuid",
  "timestamp":        "ISO 8601 UTC",
  "method":           "GET | POST | ...",
  "path":             "/some/path",
  "query":            "param=value",
  "client_ip":        "127.0.0.1",
  "user_agent":       "Mozilla/5.0 ...",
  "status_code":      200,
  "response_time_ms": 3.142
}
```

---

## Future Architecture

```
User
 ↓
CyberSentinel Test Website  ← this project
 ↓
Incoming Network Traffic
 ↓
Traffic Capture             ← plug in here: log_requests middleware in app.py
 ↓
Extract 78 CIC-IDS2017-compatible features
 ↓
Existing CyberSentinel Random Forest Model
 ↓
Attack Classification
 ↓
CyberSentinel Dashboard
```

### Integration points in `backend/app.py`

| Location | What to add |
|---|---|
| `log_requests` middleware | CIC-IDS2017 feature extraction from raw request data |
| `GET /api/request-log` | Enrich entries with model predictions before returning |

---

## Website Pages

| Page | Route (SPA hash) | Description |
|---|---|---|
| Home | `/#home` | Hero, features, testimonials, CTA |
| About | `/#about` | Mission, team, company values |
| Products | `/#products` | ERP, CRM, Analytics — with pricing |
| Login | `/#login` | Auth form with SSO buttons |
| Contact | `/#contact` | Contact form + office locations |

---

## Notes

- All logs are stored **in memory** (capped at 500 entries). For production or long-term capture, replace `deque` with a database or log file.
- The login and contact forms are **frontend-only demos** — no credentials are stored.
- This project is intentionally **isolated** from the CyberSentinel AI frontend/backend.
