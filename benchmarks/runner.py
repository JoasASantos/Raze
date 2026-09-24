"""Benchmark CLI.

Usage:
  python benchmarks/runner.py benchmarks/sample_dataset.json \
      --runs 5 --backend echo --out benchmarks/runs/latest.json

Dataset JSON: a list of cases, each
  {"finding": {"target","topic","title","state",...}, "exploitable_truth": bool}

The runner enforces >=2 runs and reports across-run variance and aggregate ECE.
It never claims a result from a single run. See benchmarks/README.md.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from offsec_one.agent import Finding, OffSecOne
from offsec_one.bench import BenchCase, run
from raze import Raze


def _load_cases(path: str) -> list[BenchCase]:
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    cases = []
    for entry in raw:
        cases.append(
            BenchCase(
                finding=Finding(**entry["finding"]),
                exploitable_truth=bool(entry["exploitable_truth"]),
            )
        )
    return cases


def _agent_factory(backend_name: str, model: str | None):
    def factory() -> OffSecOne:
        if backend_name == "anthropic":
            from raze.backends import AnthropicBackend

            backend = AnthropicBackend(model=model) if model else AnthropicBackend()
        else:
            backend = None
        return OffSecOne(raze=Raze(backend=backend))

    return factory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="benchmarks/runner.py")
    parser.add_argument("dataset", help="Path to labeled dataset JSON.")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--backend", choices=["echo", "anthropic"], default="echo")
    parser.add_argument("--model")
    parser.add_argument("--no-alternate", action="store_true")
    parser.add_argument("--out", help="Write full report JSON here.")
    args = parser.parse_args(argv)

    cases = _load_cases(args.dataset)
    report = run(
        cases,
        _agent_factory(args.backend, args.model),
        runs=args.runs,
        alternate=not args.no_alternate,
        backend_name=args.backend,
    )

    print(f"raze={report.metadata['raze_version']} rev={report.metadata['git_revision']} "
          f"backend={report.metadata['backend']} runs={report.metadata['n_runs']} "
          f"cases={report.metadata['n_cases']}")
    print(f"ECE={report.ece:.4f} over n={report.n_predictions} predictions (aggregate only)")
    print("disposition mean +/- stdev across runs:")
    for d in report.disposition_mean:
        print(f"  {d:9s} {report.disposition_mean[d]:.2f} +/- {report.disposition_stdev[d]:.2f}")
    print(f"note: {report.note}")

    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
