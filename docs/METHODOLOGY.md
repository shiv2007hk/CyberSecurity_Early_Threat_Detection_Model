# Detection, exposure and risk methodology

This document states exactly what the detection, correlation, exposure and risk engines do, what they do not do, and how their outputs should be read. It is the reference for the language used in the interface.

## 1. Ingestion and normalisation

- Records enter through a registered connector, a manual import, or the initial corpus loaded by `backend/app/seed.py`. Each record stores its source, retrieval timestamp, provenance (`recorded`, `live`, `cached` or `uploaded`) and normalised severity.
- Deduplication uses source identity plus a fingerprint of the advisory's stable fields. Re-observation updates freshness rather than creating duplicate records.
- Supported time windows are 24 hours, 7 days, 30 days and 90 days depending on the module.
- A failed connector is recorded as failed. A failed retrieval is never backfilled: only the corpus loader and the packaged scenarios write records that did not come from a connector or an import, and both leave an ingestion log beside the rows they create.

## 2. Classification and entity extraction

The classifier is a deterministic lexicon model. It runs in-process and does not call a model provider.

- Each category has weighted lexical and phrase cues; the highest-scoring category wins.
- Confidence is derived from the strength and margin of matched cues, then bounded.
- Extracted entities include CVE identifiers, IP addresses, domains, file hashes, ATT&CK technique references and named products.
- The generated summary is extractive/structured: it restates the source, category, severity evidence and entities, and explicitly states that the source text is not independently verified.
- Classification describes the text, not the world. A category or confidence value is not a claim that an incident occurred.

**Classifier evaluation.** `POST /api/admin/model-evaluations/run` scores the lexicon against an author-labelled corpus of 30 short descriptions. Reported precision/recall/F1 describe that corpus only. Because the corpus was written alongside the lexicon, a high score measures coverage of those phrasings rather than generalisation; the interface and the stored run notes say so. Predictions outside the ten defined categories are counted in an explicit `Other` row.

**Hint policy.** `classify(text, hint=...)` accepts a category only when it comes from outside the platform — an upstream feed's own label. A record's stored category is never passed back in as a hint, because that would make the prediction a restatement of the value being predicted; corpus records are classified from text alone, with the authored label kept in `category` and the independent result stored in `ai_category`.

## 3. Correlation

For a pair of threat records, similarity is a weighted overlap across:

- shared CVE identifiers,
- shared affected products,
- shared indicators,
- lexical overlap of normalised text (weighted Jaccard).

The pair is retained only above the configured minimum score. Every edge stores its score, method and reasons. Correlation is symmetric and undirected for display purposes.

**Interpretation:** an edge means two reports overlap. It does **not** prove a common actor, campaign, incident or intent. Shared libraries, hosting providers and generic indicators produce benign overlap. The interface repeats this caveat.

## 4. Exposure validation

Exposure is deliberately conservative:

1. **Product mapping.** The asset's software is compared with the advisory's affected products and known aliases.
2. **Version validation.** The asset's version must fall inside the affected range (`start`/`end`), match an `exact` list, or the advisory must explicitly state `all_versions`. Version comparison is component-wise and numeric-aware.
3. **Result.** A validated match is stored as `potentially_exposed` with confidence `96` (reduced by `6` for alias-only product matches). A product match without usable version evidence is stored as `needs_verification` with confidence `58` and is **never counted in exposure totals or warnings**.
4. **Human verification.** Analysts can confirm or dismiss a match; confirmed and dismissed states are distinct from the engine's initial `potentially_exposed` state.

A negative result means "no match in the registered inventory", not "no system anywhere is affected".

## 5. Risk model

The scoring engine is a fixed five-factor linear model:

```
score = 10 × Σ(weight_i × factor_i)
factors are normalised to 0–10
```

| Factor | Default weight | Source |
| --- | ---: | --- |
| Severity | 0.25 | CVSS, with a severity fallback |
| Exploitability | 0.20 | EPSS and known-exploited evidence |
| Exposure | 0.20 | Asset exposure and internet reachability |
| Asset criticality | 0.20 | Operator-assigned 1–5 |
| Evidence strength | 0.15 | Source reliability and corroboration |

Bands: **low** 0–25, **medium** 25–50, **high** 50–75, **critical** 75–100. Weights must sum to 1.0 and thresholds must be strictly increasing; the API validates both.

Every assessment stores its factor values, weights, urgency, exploitation status, evidence confidence, explanation and model version, so a score can be reproduced from its recorded inputs. Changing weights rescores records rather than hiding the old calculation.

**Interpretation:** the score prioritises analyst attention. It is not a probability of compromise and carries no external certification. Exploitation status and evidence confidence are reported separately.

### Divergence from the six-factor brief

An earlier specification described a six-factor model (severity 25, exploitation 25, KEV 10, criticality 25, exposure 5, relevance 10) with bands at 85/65/40 and a Log4Shell worked example of 99.4 CRITICAL. The shipped engine is a five-factor model, and the difference is deliberate rather than an oversight — it is recorded here and pinned by `backend/tests/test_risk_engine_validation.py` instead of being reconciled silently.

| Brief factor | Shipped handling |
| --- | --- |
| Severity 25 | Severity 25 — CVSS, with a documented severity fallback |
| Exploitation 25 | Exploitability 20 — EPSS or known-exploited; capped at 4/10 when neither exists |
| KEV 10 | Not a separate weight. A KEV listing pins exploitability to 10/10 and adds 1.0 to evidence strength, and it can raise urgency to `immediate` when the asset is internet-facing |
| Criticality 25 | Asset criticality 20 — operator-assigned 1–5 scaled to 0–10 |
| Exposure 5 | Exposure 20 — internet-facing 9.5, internal 5.0, air-gapped 1.5 |
| Relevance 10 | Not a separate weight. Asset-match confidence blends into evidence strength (`0.8 × evidence + 0.2 × match confidence`) |

Consequences worth knowing:

- Bands are **25/50/75**, not 85/65/40, so "Critical" is reachable at a lower absolute score and the four bands are roughly equal quarters of the range.
- The Log4Shell example scores **98.5 Critical** under this engine (severity 10, exploitability 10, exposure 9.5, criticality 10, evidence 9.65), not 99.4. Both are Critical; the gap is arithmetic, not a data problem.
- Known-exploited status cannot lift a score on its own when the asset is unreachable: the urgency floor requires internet-facing exposure. In the pinned case a weakly-evidenced KEV record scores 59.8/`immediate` on an internet-facing asset and 43.8/`monitored` on the air-gapped twin.

### Validation cases

The eight mandatory checks run as ordinary pytest cases and pass against the current engine: the Log4Shell worked example, not-affected version suppression, absent product, unknown version, known-exploited treatment with and without a CVSS, the missing-asset assumption flag, numeric-aware version ranges, and reconciliation of stored factor ledgers with stored scores. The last case allows a drift of 0.2 points because each contribution is rounded to 0.1 before it is summed.

## 6. Early warning

Rules are deterministic. Each candidate alert stores a trigger, evidence array, rule key, confidence, risk score and provenance. A fingerprint of `(rule_key, entity)` suppresses duplicate alerts for **7 days**.

| Rule key | Trigger |
| --- | --- |
| `kev-exposure` | A known-exploited vulnerability is version-validated against one or more registered assets |
| `multi-source-cve` | At least two distinct sources report the same CVE inside the window |
| `repeated-indicator` | The same domain/IP/hash appears in at least two independent reports |
| `velocity-technology` | Reports for a technology exceed `max(3, 2.2 × baseline rate)` in the window |
| `velocity-category` | The same velocity test applied to a threat category |
| `critical-asset-exposure` | A critical-severity, version-validated threat intersects an asset with criticality ≥ 4 |

Velocity is compared with a rolling baseline of the preceding days. A velocity alert states the observed count, baseline rate and ratio; it is a statistical observation, not a prediction that an attack will occur.

Alert lifecycle: `new → acknowledged → investigating → resolved` or `dismissed`. Resolution requires deliberate analyst action. Critical alerts generate a recommendation with a 24-hour due window; other alert-derived recommendations use 72 hours.

## 7. Recommendations

Recommendations are advisory and non-disruptive. They include priority, reason, action, evidence, owner and due date. The platform never blocks, patches, isolates or otherwise changes infrastructure. Lifecycle changes are audited.

## 8. Aegis AI

Aegis AI is the platform's chat assistant: a DeepSeek completion model grounded in records retrieved from the platform's own database. A turn runs in five steps.

1. Parse the question for identifiers (CVE, alert, threat, asset, ATT&CK technique reference) and topic terms, and select the record types that can answer it. The deterministic intent router behind `POST /api/assistant/query` covers the same six question shapes: alert explanation, exposure, KEV, emerging activity, remediation priority, CVE impact.
2. Retrieve a bounded, ranked set of stored rows for that turn — at most 26 records inside a fixed character budget — each serialised with its identifiers and provenance.
3. Hand that block, plus the recent turns of the conversation, to the model as evidence to quote from. The provider never receives a database dump; text inside stored records is fenced and inerted so anything in an advisory description that reads as an instruction is ignored.
4. Stream the reply to the console as Server-Sent Events and persist it with the thread, the model name, the retrieved-record count and the latency.
5. Attach numbered citations whose routes open the drawer of the cited record.

The grounding rules live in the system prompt: platform facts come only from the records supplied for the turn, record identifiers are quoted, risk scores are explained from their stored factors and never recomputed or overridden, and anything the records do not cover is stated as unrecorded before any general note is given. The assistant takes no action — it does not patch, block, isolate or ticket anything — and it needs `DEEPSEEK_API_KEY` on the server; with no key configured it returns a configuration error instead of an answer.

## 9. Analytics

All series, distributions, heatmaps, matrices and anomaly comparisons are computed from stored rows at request time. Geographic views use indicator metadata locations and state that they are not attacker attribution. Source reliability is a configured/observed score for connector comparison, not a guarantee of truth.

## 10. Packaged scenarios

Three scenarios run without outbound calls and write through the same ingestion, detection and scoring pipeline as connector data:

1. **High-risk vulnerability** — ingest, validate version, match a critical hospital asset, score, warn, recommend.
2. **Emerging pattern** — create correlated reports around a shared indicator, compare against baseline, raise an observation explicitly framed as not a prediction.
3. **No matching asset** — ingest a vulnerability for absent software and withhold any exposure claim; the assessment records the uncertainty.

## 11. Limitations

- The initial corpus is authored, not harvested: the organisations, assets, indicators and incidents in it are fictional. Counts describe engine behaviour over that corpus; they are not industry or national statistics.
- Lexicon classification is transparent but brittle on novel phrasing. The evaluation corpus is intentionally small.
- Correlation and geography support investigation; they do not establish attribution.
- Exposure depends on the completeness and accuracy of the registered inventory and software versions.
- The risk model is a configurable prioritisation heuristic without calibration against historical outcomes.
- Connector sync is an explicit operator action, and this repository bundles no third-party feed content; availability depends on each upstream.
- Aegis AI answers from the records retrieved for the current turn. It cannot see what retrieval did not select, and a fluent sentence is not evidence.

## 12. AI analysis scope and evidence limits

The analytics engines are deterministic and explainable: a weighted keyword lexicon, regular-expression entity extraction, weighted-Jaccard correlation and a configurable linear risk formula. The activity anomaly check is a two-sigma comparison over count buckets, not a learned detector. Adding a learned detector would replace a formula the interface currently explains factor by factor, so the engines stay rule-based until the evidence below supports otherwise. The one hosted-model dependency is the chat: Aegis AI sends the bounded retrieved context for a turn to the configured DeepSeek endpoint and relays the streamed reply.

**What the current corpus supports**

| Question | Available evidence | Verdict |
|---|---|---|
| Per-record risk history | 33 stored assessments across 126 threats; at most 2 revisions for any single threat | Too thin to fit or validate a time-series model |
| Labelled classification corpus | 126 records whose labels were written with the text | Labels are not independent of the text, so they cannot serve as ground truth |
| Vulnerability features | 45 records, all with CVSS and EPSS | Enough to describe, far too few to fit and hold out |
| Human-adjudicated labels | None | Blocks any supervised accuracy claim |
| Outcome labels (was the asset compromised?) | None; the platform has no incident outcome data by design | Blocks calibration of risk or urgency |

**What a defensible supervised model would require**

1. At least several hundred human-adjudicated records per category, drawn from real reporting and labelled by more than one analyst with measured inter-rater agreement.
2. A fixed train/validation/test split recorded before tuning, so the reported metrics are held out rather than fitted.
3. Repeated observations of the same entity over time for any temporal or anomaly model, with a documented collection cadence.
4. Outcome data linking prioritised records to confirmed exploitation, without which risk scores can be ranked but never calibrated.

Until those exist, the position the interface takes is the one stated here: scores and classifications are transparent rules, measured against a small author-labelled corpus, and no accuracy claim is made beyond it. Section 2 and the admin evaluation history view carry the same statement.
