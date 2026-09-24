# Adaptive attack-path scoring

A brute-force agent tries every path equally — slow and dumb. A real pentester
notices which approach is landing and pours effort there. Raze gives that instinct
to the swarm with `raze.adaptive`: candidate attack strategies are scored in a
single fast, deterministic, typed pass against the **live** engagement state, and
winning strategies accumulate signal so attention follows what works.

## The loop

```
exploration agent -> candidate Strategy list
        │
        ▼
AdaptiveScorer.rank(strategies, live)   # one fast deterministic pass, no LLM
        │
        ▼
next_best -> operator/agent executes (human-gated for offensive steps)
        │
        ▼
report_result(strategy, success) -> live state + signal update -> re-rank
```

```python
from raze.adaptive import AdaptiveEngagement, Strategy

eng = AdaptiveEngagement()
strategies = [
    Strategy("sqli-login", "login", "UNION-based SQLi on login", vuln_class="sqli"),
    Strategy("dcsync", "DC", "DCSync", vuln_class="dcsync", prerequisites=["domain_admin"]),
]
best = eng.next_best(strategies)          # dcsync discounted (prereq unmet)
eng.report_result(best.strategy, True)    # it lands -> sqli signal accumulates
# next rank pushes sqli-class strategies up; discoveries can unlock dcsync
```

## Scoring factors (every score is explainable)

| Factor | Effect |
|--------|--------|
| base | vuln class's typical CVSS score (×10), else 50 |
| runnable_mult | ×0.25 when prerequisites are not yet discovered |
| prereq_bonus | + when all prerequisites are satisfied |
| signal_bonus | + per prior success of this strategy's class (**reinforcement**) |
| chain_bonus | + when the strategy advances a known attack chain |
| fail_penalty | − per prior failure of this exact strategy |

`rank()` orders runnable strategies first, then by score.

## Why Raze goes further than a plain path scorer (the Jev/Pentest-Swarm line)

- **Same fast, typed pass** — deterministic, one pass, no LLM in the scoring loop.
- **Live-state prerequisites** — a strategy can be *not yet runnable*; discoveries unlock it, so the plan is causally ordered, not just ranked.
- **Signal reinforcement** — success bumps the class's signal; the swarm converges on what is landing.
- **Chain-aware** — advancing a known multi-step path (`raze.chaining`) is rewarded, not just per-finding score.
- **Calibrated + grounded** — scores are grounded in CVSS/CWE (`raze.cvss`, `raze.vulnclasses`) and probabilities are calibrated (`raze.calibrator`).
- **Explainable + gated** — every score shows its factors; offensive execution stays human-approved.
