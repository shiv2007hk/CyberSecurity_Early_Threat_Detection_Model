# Architecture

## Shape of the system

```
Browser (React SPA)
  ├── Landing + auth-aware navigation
  └── Operator console (viewer / analyst / admin)
        │  fetch + JWT (Bearer)
        ▼
FastAPI application
  ├── Routers: auth, public, dashboard, threats, vulnerabilities, assets,
  │            exposure, alerts, risk, analytics, recommendations,
  │            sources, reports, assistant, chat, search, scenarios, admin
  ├── Dependencies: authentication, RBAC, audit writer, rate limiting
  ├── Services: classifier, correlation, exposure, risk, early_warning,
  │             analytics, reports, assistant, chat retrieval, deepseek,
  │             integrations, scenario runs
  └── SQLAlchemy models
        ├── SQLite by default (WAL)
        └── PostgreSQL via DATABASE_URL
```

The SPA and API can run as one process in production: FastAPI serves `frontend/dist` and falls back to `index.html` for client-side routes. `/api/*` remains the API namespace.

## Backend modules

| Router | Responsibility |
| --- | --- |
| `public.py` | Landing statistics, connector provenance, corpus summary, health |
| `auth.py` | Login, registration, profile, password change, logout, seeded-account lookup |
| `dashboard.py` | Command-centre aggregation across intelligence, exposure, risk, alerts |
| `threats.py` | Filtering, detail, classification, notes, status, CSV export |
| `vulnerabilities.py` | CVE catalogue, CVSS/EPSS/KEV views, affected products, assessment creation |
| `assets.py` | Inventory, CSV import/export, per-asset exposure and scoring |
| `exposure.py` | Validated matches, analyst verification, scan execution |
| `alerts.py` | Alert queue, rule catalogue, scan trigger, status and assignment workflow |
| `risk.py` | Assessment list/detail, model configuration, rescoring, analyst feedback |
| `analytics.py` | Aggregations, correlation graph, anomaly series, geo activity, CSV export |
| `recommendations.py` | Remediation queue, status workflow, ownership |
| `sources.py` | Connector state, toggle, sync, ingestion logs, indicator enrichment |
| `reports.py` | Template catalogue, request-time reports, CSV export |
| `assistant.py` | Suggested questions, intent routing and retrieval-grounded answers |
| `chat.py` | Aegis AI: conversations, streamed DeepSeek replies, citation payloads, provider status probe |
| `search.py` | Cross-entity global search |
| Scenario router | Catalogue and execution of the three packaged end-to-end scenarios |
| `admin.py` | Users, roles, audit trail, classifier evaluation runs, system/configuration state |

Common helpers live in `routers/common.py` (pagination, range parsing, multi-value filters, CSV responses).

## Service responsibilities

- **`classifier.py`** — lexicon-based category scoring, entity extraction (CVE, IP, domain, hash, technique), evidence-linked summaries. Deterministic and in-process.
- **`correlation.py`** — weighted similarity across shared CVEs, products, indicators and lexical tokens; produces a graph with explicit reasons.
- **`exposure.py`** — maps advisories to inventory by product and then validates versions. Confidence reflects match strength; ambiguity is recorded rather than promoted.
- **`risk.py`** — weighted five-factor model, normalisation, bands, factor explanations and human feedback.
- **`early_warning.py`** — deterministic rules with evidence payloads, thresholds, suppression/dedupe and alert lifecycle helpers.
- **`analytics.py`** — all series and distributions are computed from stored rows at request time; no pre-baked chart data.
- **`reports.py`** — assembles report sections from the same records used by the modules and records generation provenance.
- **`assistant.py`** — intent routing, retrieval, facts/inference separation and citations that route back to evidence drawers.
- **`chat.py` / `chat_retrieval.py`** — Aegis AI. Each turn selects a bounded, ranked set of stored records (26 records maximum inside a fixed character budget), fences them as untrusted evidence, hands them to the configured DeepSeek endpoint and streams the reply back with numbered citations that open the cited record.
- **`deepseek.py`** — chat-completion client and connection probe. The key is read from the backend environment only; retries happen before the first token, so a half-delivered answer is never duplicated.
- **`integrations.py`** — server-side connector configuration and optional sync/enrichment. Failures return explicit errors; placeholder content is never substituted for a failed retrieval.
- **Scenario runner** — three deterministic scenarios that make no outbound calls and write through the same pipeline as normal ingestion.

## Core data model

| Table | Purpose |
| --- | --- |
| `users`, `organisations` | Identity, role, organisation scope, notification preferences |
| `threat_sources`, `ingestion_logs` | Connector state, freshness, reliability, retrieval history |
| `threats` | Normalised reports with classification, entities, provenance, score and workflow state |
| `vulnerabilities` | CVE records with CVSS, EPSS, KEV evidence, affected products and remediation |
| `assets` | Registered estate with software, version, exposure, criticality and owner |
| `asset_vulnerabilities` | Version-validated exposure links plus match confidence and verification state |
| `risk_assessments` | Stored factor breakdown, score, explanation and model version |
| `threat_correlations` | Undirected similarity edges with method and reasons |
| `alerts` | Rule-generated warnings with trigger evidence, severity, status and assignee |
| `recommendations` | Advisory actions with priority, owner, due date and lifecycle |
| `chat_conversations`, `chat_messages` | Per-user Aegis AI threads: prompt and reply pairs, citation payloads, retrieved record count, model name, latency and completion status |
| `analyst_notes`, `audit_logs`, `model_evaluations`, `settings` | Investigation notes, append-only audit, bounded classifier-evaluation history, runtime settings |

Foreign keys and indexes support the list endpoints and dashboard aggregates. Timestamps are stored in UTC; the UI formats them for display.

## Request and authorization flow

1. The SPA attaches `Authorization: Bearer <JWT>` to `/api` calls.
2. `deps.get_current_user` verifies the token and loads the active user.
3. `deps.require_role(minimum)` enforces the role ranking `viewer < analyst < admin`.
4. Mutating endpoints write an `AuditLog` row in the same transaction as the change.
5. The frontend mirrors gating for navigation and controls, but the API remains authoritative.
6. Login attempts are rate-limited per client address and email; successful logins clear the counter.
7. Chat turns run under a tighter rate budget than the rest of the API because they spend provider credit.

Roles:

- **Viewer** — read-only intelligence, dashboards, analytics, reports, assistant suggestions, own chat history.
- **Analyst** — viewer plus triage, notes, assessments, scans, scenario runs, assistant queries, chat replies, source reads.
- **Admin** — analyst plus user administration, audit trail, connector toggles/sync and classifier evaluation runs.

## Frontend structure

- `components/AppShell.tsx` — sidebar, command bar, global search, notifications, account menu, provenance banner.
- `components/ui.tsx` — panel primitives, buttons, fields, chips, badges, pagination, modal/drawer, skeletons, toasts.
- `components/charts.tsx` — trend, area, donut, line, bar, heatmap, radar/status visuals and the asset correlation graph, built on Recharts/SVG.
- `components/analytics-charts.tsx` — analytical primitives shared by the console: scatter plot with quadrants, priority matrix, waterfall, treemap, daily bars, radar and risk hex ramp.
- `components/visuals/Globe.tsx` — restrained Three.js globe used on the landing and auth surfaces, with a static fallback when WebGL is unavailable.
- `pages/app/shared.tsx` — drawer sections, evidence lists, score chips, filter labels and section headings shared by modules.
- The Aegis AI workspace holds the per-user conversation list, the streamed reply pane, numbered citation chips that open the cited record drawer, and a provider status probe that reports the configured model and host without exposing the key.

Console modules are grouped by question rather than by data table:

| Route | Module | Analytical visuals |
| --- | --- | --- |
| `/app` | Security overview | KPI ledger, trend area, distribution donut, risk gauges, asset treemap, severity heatmap |
| `/app/alerts` | Early warning | Severity charts, risk/confidence scatter, triage priority matrix, stacked alert timeline, risk-load waterfall |
| `/app/risk` | Risk scoring | CVSS × EPSS scatter, exploitation × band matrix, exposure scatter, factor waterfall |
| `/app/assets` | Asset exposure | Exposure × band matrix, criticality bubbles, category treemap, exposure donut, correlation map |
| `/app/vulnerabilities` | CVE explorer | Severity histogram, product treemap, publication timeline, affected-product graph |
| `/app/threats` | Threat intelligence | Feed timeline, category treemap, source health matrix, contribution bars |
| `/app/sources` | Sources & provenance | Ingestion timeline, source contribution bars, category treemap, source health matrix |
| `/app/monitoring` | Monitoring & anomalies | Anomaly scatter, event timeline, login heatmap, baseline comparison |
| `/app/attack-lab` | Attack lab | ATT&CK matrix, technique heatmap, stage timeline, technique graph |
| `/app/techniques` | Attack technique library | Searchable class × ATT&CK index, tactic chain, class coverage heatmap, severity donut |
| `/app/threat-map` | Global threat map | World indicator map, origin ranking, category donut, publication timeline, source coverage |
| `/app/simulator` | What-if simulator | Before/after gauges, scenario comparison, risk waterfall, interactive graph |
| `/app/provenance` | Evidence graph | Evidence graph, source coverage matrix, decision timeline, risk waterfall |

Every figure on these pages is computed in the browser from records returned by the authorised API; where a view has no stored records it renders an empty state instead of a placeholder series. Range tabs offer only windows the API resolves (7d, 30d, 90d) so a label never overstates the data behind it.

- TanStack Query keys follow `[module, params]`; mutations invalidate the affected modules rather than refetching the world.
- Deep links use `?focus=<ref>` so notifications, search results and assistant citations open the correct evidence drawer.

## Failure behaviour

- API errors render a module-level error state with a retry action; the shell stays usable.
- Loading uses skeletons sized to the eventual content to avoid layout jumps.
- Empty results explain what is missing and offer the next sensible action.
- Connector failures and unavailable live data are shown explicitly; there is no silent fallback.
- Role-gated surfaces return a clear permission panel rather than a broken screen.

## Deliberate limits

- SQLite is the zero-setup default; concurrent writes should use PostgreSQL.
- Background scheduling is out of scope; sync, scans and classifier evaluation runs are explicit operator actions.
- Aegis AI needs a reachable DeepSeek endpoint. Without `DEEPSEEK_API_KEY` the chat returns a configuration error rather than an answer, and a provider outage surfaces as a failed turn instead of an invented reply.
- Chat answers are limited to the records retrieved for that turn; the assistant browses nothing and performs no action on the platform.
- The platform never executes containment; it produces advisory recommendations only.
