# Benchmarks — methodology and honest-reporting rules

This directory holds evaluation harnesses and results. It exists to prevent the
reporting errors flagged in review. **Read before publishing any number.**

## Reporting rules (non-negotiable)

1. **Single runs are exploratory, not demonstrative.** One execution per condition
   on one target is an observation. Say *"we observed"*, never *"we demonstrated"*.
   A general-improvement claim requires multiple runs, alternated order, fixed
   parameters/versions, and reported variance.

2. **One experiment, one code state.** If prompt-chaining, evidence-field recovery,
   or data-type classification changed between runs, those runs are **different
   experiments**. Record the harness version and code state for every run. Post-fix
   tables never back-fill an earlier controlled comparison.

3. **ECE is aggregate, and only aggregate.** Do not turn an ECE value into a ± band
   on a single prediction, and do not derive precision, recall, false-positive
   counts, or analyst-hours from it. Any worked "100 findings" example is explicitly
   **hypothetical** and is not attributed to any model.

4. **No cross-paper number transplants.** ECE/latency figures published for Jev or
   Laya may come from different tasks, data, hardware, and configuration. Do not
   claim "better calibration" or "N× lower latency" for pentest unless measured
   **paired, on the same task, in this harness**. Otherwise cite them as
   *"reported by the source"* and do not extrapolate.

5. **Separate proposed from measured.** Architecture (decision points, RLHV,
   Raze/Jev-Offensive design) is not a result. Keep the implemented / measured /
   proposed table (see ../docs/ARCHITECTURE.md#contribution-status) current.

6. **Verify every reference and quantitative claim.** DOI/identifier, authors, date,
   version, and whether the source actually supports the claim — especially cost,
   speed, and ROI figures, and any 2026 preprints. No incomplete citations
   ("arXiv preprint, 2026"). Abstract and conclusion reflect only reproducible,
   attributed results.

## Layout

```
benchmarks/
  README.md          <- this file
  runs/              <- raw per-run outputs (gitignored; may contain target data)
  calibration/       <- ECE computation on a fixed, labeled test set
  protocol.md        <- (proposed) the exact paired protocol for any comparison
```

## Status

No measured runs are committed. The ECE tooling and paired protocol are
**proposed**. Do not cite results that do not exist here.
