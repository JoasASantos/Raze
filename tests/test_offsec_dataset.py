"""Sanity checks for the shipped OffSec labeled dataset."""

import json
from pathlib import Path

from raze.agent import Finding
from raze.bench import BenchCase
from raze.dataset import build_examples

DATASET = Path(__file__).resolve().parents[1] / "benchmarks" / "offsec_dataset.json"


def _load():
    raw = json.loads(DATASET.read_text(encoding="utf-8"))
    return [
        BenchCase(Finding(**e["finding"]), exploitable_truth=bool(e["exploitable_truth"]))
        for e in raw
    ]


def test_dataset_loads_and_covers_many_topics():
    cases = _load()
    assert len(cases) >= 20
    topics = {c.finding.topic for c in cases}
    assert {"web", "network", "crypto", "ad", "cloud", "mobile", "wireless", "social"} <= topics


def test_dataset_has_both_labels():
    cases = _load()
    truths = [c.exploitable_truth for c in cases]
    assert any(truths) and not all(truths)  # nuanced: signals present != exploitable


def test_build_examples_over_dataset():
    examples = build_examples(_load())
    assert len(examples) == len(_load())
    assert all(e.target["verdict"] in ("exploitable", "not_exploitable") for e in examples)
