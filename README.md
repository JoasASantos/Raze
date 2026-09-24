# OffSec One

**Offensive-security agent built on Raze — a System One model in the Jev family.**

OffSec One turns natural language and target/engagement state into **typed, calibrated judgments** that ordinary code can combine: *is this finding exploitable?*, *what is the real impact?*, *which attack path next?*, *is this a duplicate/known/theoretical issue?*

It is **not** an autonomous attack tool. It is a reasoning and triage layer for **authorized** offensive-security work (pentests, red-team engagements, bug-bounty triage, CTFs) that keeps a human and deterministic validators in the loop.

---

## The two layers

| Layer | Name | What it is |
|-------|------|------------|
| Model | **Raze** | A System One model: `state -> typed judgment + probability`. Small, composable, no free-form autonomy. |
| Product | **OffSec One** | An agent/harness that orchestrates Raze judgments, deterministic validators, and tools across the offensive-security topic surface. |

Lineage: inspired by `browser-use/jev-ultrafast`, `NandhaKishorM/laya`, `ikermoel/open-alternative-jev`, and TypeSafe's **System One / Jev** primitives.

---

## Topic coverage

Recon · Web app · Network · Active Directory · Cloud · Mobile · Wireless · Exploit dev · Reverse engineering · Social engineering · Cryptography

See [`docs/TOPICS.md`](docs/TOPICS.md).

---

## Design principles

1. **Typed over free-form.** Every Raze call returns a schema-validated judgment, never prose the caller has to parse.
2. **Calibrated, not confident.** Probabilities are reported and measured (ECE), and never re-interpreted as per-finding precision/recall. See [`benchmarks/README.md`](benchmarks/README.md).
3. **Deterministic validators gate model output.** A finding a validator can disprove (e.g. failed reproduction) is downgraded regardless of Raze's probability.
4. **Human-in-the-loop by default.** OffSec One proposes; the operator disposes. No unattended exploitation.
5. **Authorized use only.** Scope and authorization are enforced at the harness boundary. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#authorization--scope).

---

## Status

Early scaffold. Contributions marked honestly as **implemented / measured / proposed** — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#contribution-status).

## Quickstart

```bash
pip install -e .
python examples/triage_finding.py
```

## License

TBD (add before public release).
