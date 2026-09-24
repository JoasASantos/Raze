"""Sanity checks for the shipped OffSec labeled dataset."""

import json
from pathlib import Path

from raze.agent import Finding
from raze.bench import BenchCase
from raze.dataset import build_examples

DATASET = Path(__file__).resolve().parents[1] / "benchmarks" / "offsec_dataset.json"


ALL_ELEVEN = {
    "web", "network", "crypto", "ad", "cloud", "mobile",
    "wireless", "exploitdev", "reversing", "social", "recon",
}


def _raw():
    return json.loads(DATASET.read_text(encoding="utf-8"))


def _load():
    return [
        BenchCase(Finding(**e["finding"]), exploitable_truth=bool(e["exploitable_truth"]))
        for e in _raw()
    ]


def test_dataset_is_robust_and_covers_all_topics():
    cases = _load()
    assert len(cases) >= 50
    assert {c.finding.topic for c in cases} == ALL_ELEVEN


def test_dataset_labels_are_balanced():
    truths = [c.exploitable_truth for c in _load()]
    pos = sum(truths)
    # Meaningfully balanced, not all-positive/all-negative.
    assert 0.3 <= pos / len(truths) <= 0.7


def test_dataset_has_hard_cases_and_metadata():
    raw = _raw()
    difficulties = {e["difficulty"] for e in raw}
    assert "hard" in difficulties
    assert all("cwe" in e and "label_rationale" in e for e in raw)


def test_hard_cases_include_signal_present_but_not_exploitable():
    raw = _raw()
    # e.g. missing mitigations / weak-but-not-broken labeled not-exploitable
    assert any(e["difficulty"] == "hard" and not e["exploitable_truth"] for e in raw)


def test_build_examples_over_dataset():
    examples = build_examples(_load())
    assert len(examples) == len(_load())
    assert all(e.target["verdict"] in ("exploitable", "not_exploitable") for e in examples)
