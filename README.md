# ThreatLens

AI-driven hybrid machine learning intrusion detection system for network threat analysis, evidence-based incident investigation, and adaptive reliability monitoring.

## Mission

Turn suspicious network activity into explainable, evidence-backed, prioritized, and measurable security investigations.

ThreatLens is a final-year research prototype for students, researchers, and analysts who want to study an intrusion-detection workflow. It is not an enterprise security platform and it is not a live network defence system.

## Current status

Present now:

- Python package (`src/threatlens`) with data intake, cleaning, and 66-feature preparation
- Random Forest and Isolation Forest baselines with saved artifacts under `artifacts/models/`
- Hybrid decision engine, risk scoring, and explainable alerts
- End-to-end inference via `predict_alerts`
- FastAPI HTTP API: `GET /health`, `GET /schema`, `POST /predict`
- SQLite alert history: `GET /alerts`, `GET /alerts/stats`, `GET /alerts/{record_id}` (persisted after successful predict)
- Mycelium-inspired investigation UI at `GET /` (cream paper, two-colour headlines, mono labels)
- React cybersecurity dashboard in `frontend/` (Overview, Alert History, Traffic Analysis, About)

Not implemented yet:

- Authentication or multi-user incident ledger
- Live packet capture or traffic blocking
- Drift monitoring / automated retraining loops

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — system design, data flow, endpoints, and limitations
- [Evaluation report](docs/EVALUATION.md) — measured RF, Isolation Forest, and hybrid results from saved artifacts

## Run the API

```powershell
cd C:\Users\mr\IDS
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m uvicorn threatlens.api.app:app --host 127.0.0.1 --port 8000
```

Then open [http://127.0.0.1:8000/](http://127.0.0.1:8000/) for the static investigation UI.

- Static UI: `/`
- Health: `/health` (models + database readiness)
- Schema: `/schema`
- Predict: `POST /predict` (also persists successful alerts)
- Alert history: `GET /alerts?limit=50&offset=0` (includes `total`), `GET /alerts/{record_id}`
- OpenAPI docs: `/docs`

## Run the React dashboard

Terminal 1 — API:

```powershell
cd C:\Users\mr\IDS
.\.venv\Scripts\python.exe -m uvicorn threatlens.api.app:app --host 127.0.0.1 --port 8000
```

Terminal 2 — dashboard:

```powershell
cd C:\Users\mr\IDS\frontend
node "C:\Program Files\nodejs\node_modules\npm\bin\npm-cli.js" install
node "C:\Program Files\nodejs\node_modules\npm\bin\npm-cli.js" run dev
```

Open [http://127.0.0.1:5173/](http://127.0.0.1:5173/).

Vite proxies `/health`, `/schema`, `/predict`, `/alerts`, and `/alerts/stats` to `127.0.0.1:8000`. Optional direct API URL: copy `frontend/.env.example` to `.env` and set `VITE_API_BASE_URL=http://127.0.0.1:8000`.

Database path defaults to `artifacts/threatlens_alerts.sqlite3` (override with `THREATLENS_DB_PATH`). Clients cannot supply DB paths.

A successful health check means the process is up and artifacts/database are ready. It does **not** prove detection accuracy. Risk scores are prioritization heuristics (0–100), not attack probabilities.

CORS allows only the Vite development origins `http://127.0.0.1:5173` and `http://localhost:5173`.

Overview decision/risk charts use **`GET /alerts/stats`** (full SQLite aggregates), not a truncated page sample. The recent-activity table still uses a short `GET /alerts` page.

## Integration testing

The complete research workflow covered by automated tests is:

1. Input / feature validation
2. Random Forest + Isolation Forest inference
3. Hybrid decision + risk score + explanation
4. SQLite persistence of each occurrence
5. Alert list / detail / full-database stats retrieval
6. Dashboard empty / error / ready view-state helpers
7. Browser smoke coverage of the React dashboard

Python (uses the project venv; temporary SQLite; no artifact retrain):

```powershell
cd C:\Users\mr\IDS
.\.venv\Scripts\python.exe -m pytest -q tests/test_integration_workflow.py
.\.venv\Scripts\python.exe -m pytest -q
```

Frontend unit helpers + build + Playwright smoke:

```powershell
cd C:\Users\mr\IDS\frontend
node "C:\Program Files\nodejs\node_modules\npm\bin\npm-cli.js" test
node "C:\Program Files\nodejs\node_modules\npm\bin\npm-cli.js" run build
node "C:\Program Files\nodejs\node_modules\npm\bin\npm-cli.js" run test:e2e
```

`tests/test_integration_workflow.py` asserts the API contract the React dashboard depends on (`total`, `/alerts/stats`, `record_id`, decision, risk score, explanation, model fields). Frontend `src/lib/viewState.test.js` covers empty/error/ready helpers. `frontend/e2e/` exercises navigation and backend-unavailable UI in Chromium.

## Design note

The static investigation page at `/` follows the visual language of the public [Mycelium](https://mycelium.nandanadileep.com/) site as a **design reference only**. Mycelium’s code and product are not part of this repository. The React dashboard under `frontend/` uses a separate dark operations theme.
