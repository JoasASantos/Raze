"""Export a labeled dataset to training JSONL for a dedicated Raze model.

Usage:
  python benchmarks/export_dataset.py benchmarks/sample_dataset.json \
      --format messages --out benchmarks/runs/train.jsonl

Dataset JSON is the same shape the benchmark runner consumes.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from raze.agent import Finding
from raze.bench import BenchCase
from raze.dataset import FORMATS, build_examples


def _load_cases(path: str) -> list[BenchCase]:
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    return [
        BenchCase(
            finding=Finding(**entry["finding"]),
            exploitable_truth=bool(entry["exploitable_truth"]),
            meta={k: v for k, v in entry.items() if k not in ("finding", "exploitable_truth")},
        )
        for entry in raw
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="benchmarks/export_dataset.py")
    parser.add_argument("dataset", help="Labeled dataset JSON.")
    parser.add_argument("--format", choices=sorted(FORMATS), default="messages")
    parser.add_argument("--no-analyzers", action="store_true")
    parser.add_argument("--out", help="Write JSONL here (else stdout).")
    args = parser.parse_args(argv)

    cases = _load_cases(args.dataset)
    examples = build_examples(cases, run_analyzers=not args.no_analyzers)
    text = FORMATS[args.format](examples)

    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"wrote {len(examples)} examples ({args.format}) to {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
