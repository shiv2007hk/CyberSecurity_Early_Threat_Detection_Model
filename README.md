# CyberGuard AI

**CyberGuard AI — AI-Driven Cyber Threat Intelligence & Risk Analytics Platform**

CyberGuard AI is a full-stack cyber threat intelligence and risk analytics platform. It ingests fragmented reporting, classifies and correlates records, validates which registered assets are genuinely exposed, scores prioritisation risk with an inspectable model, raises evidence-backed warnings and recommends defensive action.

Every stored record carries its source, retrieval timestamp and provenance, and every exposure or risk claim is traceable back to those records. Aegis AI, the embedded assistant, answers analyst questions from records retrieved from the platform database over a server-side DeepSeek connection, and attaches citations to the records it used.

---

## What is implemented

| Layer | Included |
| --- | --- |
| Ingestion | Source registry, freshness and failure state, manual import, optional server-side NVD / CISA KEV / EPSS sync, enrichment lookup |
| Analysis | Deterministic NLP classification, entity extraction, grounded summaries, weighted-Jaccard correlation |
| Exposure | Product mapping plus affected-version validation against registered assets; `needs verification` is never counted as exposure |
| Risk | Explainable weighted model with stored factor breakdown, configurable weights and thresholds |
| Early warning | Deterministic rules (KEV exposure, corroboration, repeated indicators, velocity, critical-asset intersection) with 7-day dedupe and analyst workflow |
| Response | Advisory recommendations with priority, owner, due date and workflow state; nothing executes automatically |
| Analytics | Temporal series, severity distributions, heatmaps, exposure matrix, anomaly comparison, source behaviour, indicator geography |
| Visual analysis | Attack lab with ATT&CK technique matrix, attack technique library with a searchable class/technique index, global threat map workspace (country search, render modes, full-screen), correlation investigation wall (search, zoom/pan, path tracing), monitoring and anomaly detection, what-if risk simulator and evidence provenance graph — every figure computed from stored records |
| Reporting | Six report templates, request-time generation, print stylesheet and CSV exports |
| Aegis AI | DeepSeek chat assistant: bounded retrieval from platform records, streamed Markdown replies, numbered inline citations that open the cited record, persisted per-user conversations |
| Governance | JWT auth, viewer/analyst/admin RBAC, user administration, append-only audit trail, classifier evaluation history, system configuration |
| Scenarios | Three deterministic end-to-end scenarios that exercise the whole pipeline and write through the normal ingestion path |

The complete frontend includes a cinematic two-climate interface: a pale glacial landing page with a rotating faceted glass cube over procedural terrain, oversized condensed statements, floating evidence cards and alternating light/dark sections; a cinematic authentication stage with the same cube and terrain behind a frosted glass form; and an operator console with midnight-navy glass panels, a diffused blue glow, a "Total visibility. Total control." command centre with five click-through metric cards, attack lab, attack technique library, count-scaled global threat map with marker and density modes plus a full-screen map workspace, correlation investigation wall with zoom/pan and retained-edge path tracing, monitoring and anomaly detection, what-if simulator, evidence provenance explorer, interactive charts, evidence drawers and global search (`Ctrl / Cmd + K`).

---

## Data sources and coverage

Records reach the platform through three paths, all of which write the same tables:

- **Connector sync** — operator-triggered, server-side fetches from NVD, CISA KEV, FIRST EPSS and MITRE ATT&CK. AlienVault OTX, VirusTotal, AbuseIPDB and GreyNoise back indicator enrichment. Each connector has its own toggle, key, freshness state and ingestion log.
- **Import** — manual advisory ingestion and CSV asset-inventory import.
- **Initial corpus** — `backend/app/seed.py` loads the baseline intelligence dataset into an empty database on first start: sources, vulnerabilities, threat reports, assets, risk assessments, alerts, recommendations and operator accounts.

No third-party feed content is redistributed in this repository; connector data is retrieved only when a sync runs. A failed retrieval is stored as a failure and leaves existing records untouched.

---

## Stack

- **Backend:** Python 3.12, FastAPI, SQLAlchemy 2, SQLite (PostgreSQL compatible), Pydantic 2, PyJWT, PBKDF2-SHA256
- **Chat:** DeepSeek completions API via httpx, streamed to the console as Server-Sent Events
- **Frontend:** React 18, TypeScript, Vite 6, Tailwind CSS 3, TanStack Query 5, React Router 6, Recharts 2, Three.js, Framer Motion, Lucide
- **Tests:** pytest (API contract, RBAC, engines)

---

## Quick start

### 1. Backend

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r backend/requirements.txt

cp backend/.env.example backend/.env
# Edit backend/.env. Change JWT_SECRET_KEY before any shared deployment,
# and set DEEPSEEK_API_KEY to enable the Aegis AI chat.

cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

On first start the SQLite database is created under `backend/` and populated with the initial corpus described above. Interactive API docs are served at `http://127.0.0.1:8000/api/docs` outside production mode.

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The dev server proxies `/api` to `http://127.0.0.1:8000`.

### 3. Production build

```bash
cd frontend
npm run build
```

FastAPI automatically serves `frontend/dist` when it exists, so a single process can host the API and the SPA. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for reverse-proxy, environment and hardening guidance.

### Initial operator accounts

The seed creates six operator accounts across three organisations: one administrator, three analysts and two viewers. Their addresses and passwords are defined in `backend/app/seed.py` and are not reproduced here.

| Role | Sign in with |
| --- | --- |
| Administrator | `<admin email from your seed>` |
| Security analyst | `<analyst email from your seed>` |
| Viewer | `<viewer email from your seed>` |

Change every seeded password before a shared deployment. The seeded-account endpoint returns `404` when `APP_ENV=production`, and interactive API docs are disabled in the same mode.

---

## Tests

```bash
cd backend
../.venv/Scripts/python.exe -m pytest -q     # Windows venv layout
python -m pytest -q                          # activated venv / other platforms
```

Tests use an isolated temporary database and never touch the operational one. The current suite covers authentication, RBAC, dashboard/intelligence contracts, exposure validation, risk, alerts, analytics, reports, the assistant and chat endpoints, admin actions and the packaged scenarios.

---

## Truthfulness rules built into the product

These are product constraints, not marketing copy:

1. **Provenance is recorded, not implied.** Every stored row carries the path it arrived through — connector retrieval, cached fetch, manual import, initial corpus or scenario run — and the interface surfaces it.
2. **A text match is never an exposure claim.** Exposure requires product mapping plus affected-version validation. Anything ambiguous stays `needs verification`.
3. **Risk is prioritisation, not prediction.** The score orders attention. Exploitation status, urgency and evidence confidence are reported separately.
4. **No unsupported attribution.** Correlation and indicator geography describe metadata overlap; they do not prove a common actor or campaign.
5. **No automated response.** Recommendations are advisory. The platform never blocks, patches, isolates or executes containment.
6. **Failures are explicit.** A failed connector is displayed as failed; the platform does not silently substitute placeholder or generated content.
7. **Secrets stay server-side.** Connector keys and the DeepSeek key are read from the backend environment and are never returned to the browser.
8. **Evaluation claims are bounded.** Classifier precision/recall/F1 describe a small author-labelled corpus and are never presented as generalisation.
9. **Aegis AI is grounded per turn.** The model receives only the bounded record set retrieved for that question, cites it inline, and states when the platform holds no record of something.

---

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — modules, data model, request flow, RBAC
- [Detection and risk methodology](docs/METHODOLOGY.md) — classification, correlation, exposure validation, scoring, early-warning rules
- [Deployment and operations](docs/DEPLOYMENT.md) — environment variables, production mode, backup, hardening
- [Design system](DESIGN.md) — tokens, typography, layout, components and usage rules
- [Product context](PRODUCT.md) — audience, purpose and constraints

## Repository layout

```
backend/
  app/
    routers/        API endpoints by module
    services/       ingestion, NLP, correlation, exposure, risk, alerts, analytics, reports, assistant, chat, scenarios
    models.py       SQLAlchemy models
    seed.py         initial intelligence corpus and operator accounts
    security.py     hashing, JWT, password policy
  tests/
frontend/
  src/
    components/     shell, UI primitives, charts, Three.js globe
    pages/          landing, auth, operator modules
    lib/            API client, formatting, exports
docs/
```

---

## Licence and attribution

The organisations, assets, vulnerabilities, indicators and incidents in the initial corpus are fictional, so the platform can be operated without describing a real estate. External source names appear only to describe connector shape; no third-party feed content is bundled or redistributed here. Connector and model-provider access remains subject to each party's own terms.
