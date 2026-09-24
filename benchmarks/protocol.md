# Paired comparison protocol

The only comparison this project will publish as a *result* (not an observation).
It exists because the review flagged: single runs, mixed code states, cross-paper
number transplants, and ECE misread as per-finding precision.

## Preconditions

1. **One code state.** Record `git rev-parse HEAD` and freeze it for the whole
   comparison. If the harness or prompts change, it is a new experiment — start over.
2. **Fixed parameters.** Model id, effort, temperature-equivalent settings, and
   dataset are pinned and written into every report's `metadata`.
3. **Labeled test set.** Each case carries a ground-truth `exploitable_truth`.
   Labels are decided before any run and never edited to match output.

## Procedure (per condition)

For each condition (e.g. `--backend echo` vs a real Raze backend, or Raze-on vs
Raze-off), run the same dataset:

```bash
python benchmarks/runner.py benchmarks/sample_dataset.json \
    --runs 10 --backend <cond> --out benchmarks/runs/<cond>.json
```

- **runs >= 10**, alternating case order (default) to cancel order effects.
- Report **mean ± stdev** of each disposition across runs, and aggregate **ECE**.
- Conditions run **paired**: same dataset, same code state, same machine.

## What may be claimed

- "On this dataset and code state, we **observed** condition A queued X ± s
  findings vs condition B's Y ± s." — allowed.
- A general-improvement or "N× faster / better calibrated" claim — only after the
  paired runs above show it with non-overlapping variance, and only for *this*
  task. Never transplant ECE/latency numbers published for Jev or Laya on other
  tasks/hardware; cite those as reported-by-source.

## What may never be claimed

- A result from a single run.
- A per-finding precision/recall/false-positive/analyst-hour figure derived from
  an aggregate ECE.
- A comparison across two different code states or datasets.
