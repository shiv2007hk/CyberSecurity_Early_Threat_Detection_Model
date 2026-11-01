# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

delegated: React + TypeScript + Vite single-page application, Tailwind CSS for tokens, TanStack Query for server state, React Router, Recharts for analytical charts, Three.js for the faceted glass cube and labelled globe preview, Framer Motion for motion. FastAPI + SQLite backend already exists in `backend/`; the frontend consumes its `/api` contract.

## Users

Cyber threat analysts, incident coordinators and duty officers working a watch floor; security leads at critical-infrastructure organisations who receive warnings; administrators who govern users, sources and model configuration. Viewers receive read-only intelligence briefings.

## Product Purpose

CyberGuard AI turns fragmented cyber threat reporting into early, evidence-backed warnings. It ingests external intelligence, classifies and correlates records, validates whether registered assets are genuinely exposed, scores risk explainably, raises warnings with traceable evidence, and recommends defensive action. Success means an analyst can move from a raw advisory to a defensible, prioritised response without overstating what the evidence proves.

## Positioning

Every warning is traceable to stored evidence and every exposure claim requires product/version validation. The platform separates observation from inference, keeps connector-retrieved, imported and corpus-authored records distinguishable by provenance, and exposes its risk formula and rule logic instead of producing an opaque score. Aegis AI answers analyst questions from records retrieved from the platform database and cites them. It recommends actions; it never executes disruptive operations on real infrastructure.

## Operating Context

A dark operations room, large monitors, sustained reading of dense telemetry. Analysts triage threat feeds and alerts, validate inventory exposure, investigate correlations, coordinate remediation through recommendations, brief leadership with generated reports, and audit actions. Packaged scenarios let an operator run the complete pipeline end to end against the stored corpus.

## Capabilities and Constraints

Implemented: source registry with explicit failure handling; deterministic NLP classification and entity extraction; correlation graph with a full-screen investigation workspace (search, zoom/pan/fit, cluster listing, retained-edge path tracing); validated exposure matching; explainable risk model with configurable weights; early-warning rules with deduplication; recommendations; analytics; CSV export; report generation; Aegis AI chat with bounded retrieval, streamed answers and citations; user/audit/admin; packaged pipeline scenarios.

Constraints: never present a retrieved-record answer as verified outside the platform; never assert an asset is vulnerable from loose text matching; no automated containment; no fabricated AI accuracy claims; risk is prioritisation, not prediction; connector and chat provider keys stay server-side; production deployments disable the seeded-account endpoint and interactive docs.

## Brand Commitments

Name CyberGuard AI. Tagline “CyberGuard AI — AI-Driven Cyber Threat Intelligence & Risk Analytics Platform.” Assistant module Aegis AI. Pinned visual direction: two related climates — a pale glacier public surface (#DCEAF4, #0A1728, #627C94) with oversized condensed statements and a rotating glass cube over procedural terrain, and a midnight-navy command centre (#06101F, #081A2E, #0C1F36, #102A45) with electric blue #49B8FF, signal cyan #64D8FF, crystal #8BE4FF, provenance violet #9A8CFF; critical #FF4D5E, high #FF963D, medium #FFD166, low #42C98A, informational #78B7FF. Premium frosted navy glass with a diffused left blue glow, Barlow Condensed headlines, and authored data scenes (glass cube, terrain, count-scaled global threat map, correlation wall), operational not gamified.

## Evidence on Hand

`backend/app/seed.py` loads the platform's initial intelligence corpus — threats, vulnerabilities, assets, risk assessments, alerts, recommendations, sources and operator accounts — and exposes it through the verified API contract. Connector keys, the DeepSeek key and SMTP credentials are supplied per deployment. No customer names, benchmark results or certifications are claimed anywhere in the product; future work must not invent them.

## Product Principles

1. Evidence before alarm: every warning shows its trigger, evidence and confidence.
2. Validation before exposure: text matches are never treated as confirmed vulnerability.
3. Explain the machine: formulas, rules and limitations are visible in the interface.
4. Label provenance everywhere: connector-retrieved, cached, imported and corpus-authored records never blur together.
5. Recommend, never act: response stays human-controlled and non-disruptive.
6. Cite or say nothing: an Aegis AI answer points at the records it used, and names the gap when there are none.

## Accessibility & Inclusion

Keyboard-operable navigation and dialogs, visible focus rings, contrast-conscious text on dark surfaces, reduced-motion support, responsive layouts for laptop and mobile review.
