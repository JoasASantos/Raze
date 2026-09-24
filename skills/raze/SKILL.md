---
name: raze
description: >-
  Make typed, calibrated, gated offensive-security decisions with Raze — a System
  One model (Jev family) for AUTHORIZED pentest / red-team / bug-bounty / CTF work.
  Use when triaging a finding (exploitable? impact? novelty? severity?), prioritizing
  an engagement, grounding severity in CVSS/CWE, building or scoring attack chains,
  or running an adaptive attack-path swarm. Works over Claude, OpenAI/Codex, Gemini,
  a local model, or any harness. Offensive execution stays human-approved.
---

# Raze

Raze turns target/engagement state into **typed, schema-validated judgments** with
a calibrated probability, gated by deterministic validators and a hard
authorization boundary. It does not exploit anything by itself — it decides, ranks,
and proposes; a human approves offensive actions.

## When to use

- Triage a finding: exploitability, impact, reachability, novelty, severity.
- Prioritize a whole engagement into a ranked plan.
- Ground severity in **CVSS v3.1** and map to **CWE / vuln class**.
- Detect **attack chains** (one weakness enables the next).
- Run the **adaptive swarm**: score candidate attack strategies against live state; attention follows what lands.

## CLI (installed via `pip install -e .` in the Raze repo; `raze` or `python -m raze.cli`)

```bash
# Fast decision on one finding (one combined model call): verdict + priority + CVSS/CWE
raze decide finding.json --scope scope.json

# Whole engagement: decide all, correlate attack chains, rank a plan
raze plan findings.json --top 10

# Adaptive attack-path swarm: strategies per finding, scored vs live state
raze swarm findings.json --steps 20

# Granular per-judgment view
raze assess finding.json --json

# List covered topics/analyzers
raze topics
```

**Providers / harnesses** — every command: `--backend echo|anthropic|openai|gemini`
plus `--model` and (OpenAI-compatible) `--base-url`. Default `echo` runs offline.

```bash
raze decide finding.json --backend anthropic --model claude-opus-5
raze plan   findings.json --backend openai --model gpt-4o
raze swarm  findings.json --backend openai --base-url http://localhost:11434/v1 --model llama3.1
raze plan   findings.json --backend gemini
```

## Input shapes

Finding JSON (or a JSON array of these for `plan`/`swarm`):
```json
{"target":"app.example.com","topic":"web","title":"Reflected param",
 "has_reproduction":false,
 "state":{"param_value":"<svg onload=1>","response_body":"...<svg onload=1>...",
          "response_headers":{"Server":"nginx"}}}
```
Scope JSON (enforces the authorization boundary — required for real targets):
```json
{"engagement_id":"ENG-1","authorization_ref":"ROE-signed","targets":["*.example.com"]}
```
`topic` ∈ recon, web, network, ad, cloud, mobile, wireless, exploitdev, reversing, social, crypto.

## Library

```python
from raze import Raze, RazeAgent, Finding, Scope
from raze.backends import make_backend

agent = RazeAgent(raze=Raze(backend=make_backend("anthropic")),
                  scope=Scope("ENG-1","ROE",["*.example.com"]))
decision = agent.decide(Finding(target="app.example.com", topic="web", title="…",
                                state={...}))
print(decision.action, decision.priority, decision.vuln_class, decision.cwe, decision.cvss_score)
```

Any harness plugs in via `LLMBackend(complete_fn)` where `complete_fn(system, user) -> str`.

## Rules

- **Authorized use only.** Never act outside the operator-supplied scope; the gate rejects out-of-scope targets before any judgment.
- **Human-gated offense.** `technique_selection`, `go_no_go`, `next_pivot`, `privesc_path` require explicit human approval — Raze proposes, the operator disposes.
- **Honest metrics.** ECE is aggregate (not per-finding precision); measured accuracy/precision/recall are separate. Never invent results.
