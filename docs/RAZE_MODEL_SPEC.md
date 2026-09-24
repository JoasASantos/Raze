# Raze — System One Model Spec

**Raze** is a System One model: a small unit of AI intelligence used like a programming primitive. It maps application state to a **typed judgment** with a calibrated probability. Code combines many Raze calls; Raze itself does not plan, browse, or execute.

## Contract

```
Raze.judge(schema, context) -> Judgment[schema]
```

- **Input:** a target judgment schema + a `JudgmentContext` (task description, structured state, evidence).
- **Output:** an instance of the requested schema, plus `probability: float` and `rationale: str`.
- **Guarantee it does NOT make:** the probability is a model estimate, not a measured precision. It is only meaningful after calibration on a held-out set (see below).

## Core judgment types

| Judgment | Question | Typed output |
|----------|----------|--------------|
| `Exploitability` | Can this finding be exploited in this context? | `verdict: exploitable\|conditional\|not_exploitable` |
| `Impact` | What does exploitation grant? | `confidentiality/integrity/availability` + `severity` |
| `Novelty` | Is this new, known, or a duplicate? | `class: novel\|known\|duplicate\|theoretical` |
| `NextAction` | Which step advances the engagement? | ranked `candidates` |
| `Reachability` | Is the vulnerable code/endpoint reachable? | `reachable: bool` + `preconditions` |

All defined in [`src/raze/judgments.py`](../src/raze/judgments.py).

## Calibration (read this before trusting probabilities)

Raze reports a probability per judgment. Aggregate calibration is measured with **Expected Calibration Error (ECE)** over a fixed test set of `(judgment, ground-truth)` pairs.

**What ECE is:** the average gap between predicted confidence and observed accuracy, bucketed. An ECE of 0.081 means that, *on average across buckets*, confidence and empirical accuracy differ by ~8 points.

**What ECE is NOT:** it is **not** a ± band on a single prediction, and you **cannot** derive precision, recall, false-positive counts, or analyst-hours from it. Those require measured predictions and labels on the same test set. Do not repeat the "0.8 ± 0.081 for one finding" error — that is a category mistake.

## Backends

`src/raze/model.py` defines the `Backend` protocol. The scaffold ships `EchoBackend` (deterministic, offline, for wiring/tests). Real backends (TypeSafe System One SDK, a hosted Jev-family endpoint, or a local model) implement the same protocol.

## Safety scope of Raze

Raze inputs are influenced by the target (page content, banners, responses). Therefore:
- Raze output is **advisory**; a deterministic validator gates it.
- Adversarial/target-controlled input **can** bias Raze's selection and priority. Claims like "nothing to inject" are false for target-influenced input and are not made here.
- The validator's blocking conditions are explicit and testable — see [`src/offsec_one/validators.py`](../src/offsec_one/validators.py).
