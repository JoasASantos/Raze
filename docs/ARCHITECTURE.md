# Architecture

## Overview

```
                 ┌─────────────────────────────────────────────┐
                 │                 Raze                    │
                 │                (agent / harness)              │
                 │                                               │
  operator ─────▶│  authorization + scope gate                   │
  (human)        │        │                                      │
                 │        ▼                                      │
                 │   topic modules ──▶ tools (recon/web/net/...) │
                 │        │                    │                 │
                 │        ▼                    ▼                 │
                 │   Raze (System One)    raw evidence           │
                 │   typed judgment +          │                 │
                 │   probability               ▼                 │
                 │        │            deterministic validators  │
                 │        └────────────┬───────┘                 │
                 │                     ▼                          │
                 │              disposition (ranked, gated)       │
                 └─────────────────────────────────────────────┘
```

Raze never lets a model's probability be the last word. Every judgment passes through a **deterministic validator** before it reaches the operator's queue.

## Components

### Raze — the System One model (`src/raze/`)
A callable that maps `(context, state)` to a **typed judgment**: a Pydantic model plus a probability in `[0,1]`. It does one narrow thing per call (classify exploitability, rank paths, dedupe). It never plans autonomously and never executes tools.

- `judgments.py` — the typed judgment primitives.
- `model.py` — the `Raze` client (backend-agnostic; a stub `EchoBackend` ships so the scaffold runs offline).
- `backends/llm.py` — `LLMBackend`: provider-agnostic; you inject a `complete_fn` and it builds the System One prompt, extracts JSON, and validates it into the typed judgment.
- `backends/anthropic_backend.py` — `AnthropicBackend`: `LLMBackend` wired to the Anthropic SDK (Claude). Default model `claude-opus-5`.
- `calibration.py` — Expected Calibration Error over a labeled test set (aggregate only).
- `topics/` — the offensive-security topic taxonomy (`topics/taxonomy.py`) and analyzers.

### RazeAgent — the harness (`src/raze/agent.py`)
Orchestrates topic analyzers, calls the `Raze` model for decisions, runs validators, and enforces authorization.

- `agent.py` — the orchestration loop (propose → validate → queue).
- `validators.py` — deterministic checks that can downgrade or drop a finding.
- `authz.py` — scope/authorization gate.
- `cli.py` — entrypoint.

## Authorization & scope

The harness refuses to act on any target not present in an explicit, operator-supplied scope file, and records the authorization reference (engagement ID, rules of engagement) with every artifact. This is a **hard boundary in code**, not a model instruction — Raze never sees a request for an out-of-scope target because the gate rejects it first.

## Contribution status

Honest labeling per the review guidance — do not confuse design with measured result.

| Contribution | Status |
|--------------|--------|
| Typed judgment primitives (Raze schemas) | **implemented** (scaffold) |
| Deterministic validator gate | **implemented** (scaffold, minimal checks) |
| Authorization/scope boundary | **implemented** (scaffold) |
| Raze model backend (real inference) | **implemented** — `LLMBackend` (provider-agnostic) + `AnthropicBackend`; needs credentials to run |
| Calibration measurement (ECE) — the function | **implemented** — `raze.calibration.expected_calibration_error` |
| Probability calibrator (temperature scaling) | **implemented** — `raze.calibrator` (`fit_temperature`, `CalibratedBackend`) |
| Training-dataset export (fine-tune path) | **implemented** — `raze.dataset` (generic + messages JSONL) |
| Dedicated fine-tuned Raze model | **proposed** — export exists; no model trained |
| Calibration *results* on a fixed test set | **proposed** — no measured runs committed |
| Topic analyzers (all 11 topics) | **implemented** — deterministic detectors emit evidence signals; `PROPOSED_TOPICS == []` |
| Analyzer depth (more detectors per topic) | **partial** — web has 4; most topics have 1–2 |
| Active tool integrations (traffic-sending tools) | **partial** — `HeaderFetchTool` (scope-gated); framework in `raze.tools` |
| Comparative benchmark vs. Jev / Laya | **proposed** — see `benchmarks/README.md` for the required paired methodology |

## Non-goals

- Unattended / autonomous exploitation.
- Detection evasion for malicious use.
- Any action outside an authorized, scoped engagement.
