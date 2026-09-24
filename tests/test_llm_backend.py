"""LLMBackend tests using a fake complete_fn — no network, no provider."""

import json

import pytest

from raze import Raze
from raze.backends import JudgmentParseError, LLMBackend
from raze.judgments import Exploitability, ExploitVerdict, JudgmentContext


def _ctx():
    return JudgmentContext(task="assess", topic="web", evidence=["reflected input"])


def test_parses_clean_json():
    def complete(system, user):
        return json.dumps(
            {"probability": 0.82, "rationale": "reflected + no encoding",
             "verdict": "exploitable", "preconditions": []}
        )

    raze = Raze(backend=LLMBackend(complete))
    j = raze.judge(Exploitability, _ctx())
    assert j.verdict == ExploitVerdict.exploitable
    assert j.probability == 0.82


def test_extracts_json_from_surrounding_prose():
    def complete(system, user):
        return 'Sure:\n```json\n{"probability": 0.3, "verdict": "conditional"}\n```\ndone'

    raze = Raze(backend=LLMBackend(complete))
    j = raze.judge(Exploitability, _ctx())
    assert j.verdict == ExploitVerdict.conditional


def test_invalid_enum_raises_parse_error():
    def complete(system, user):
        return json.dumps({"probability": 0.5, "verdict": "definitely"})

    raze = Raze(backend=LLMBackend(complete))
    with pytest.raises(JudgmentParseError):
        raze.judge(Exploitability, _ctx())


def test_no_json_raises():
    raze = Raze(backend=LLMBackend(lambda s, u: "no json here"))
    with pytest.raises(JudgmentParseError):
        raze.judge(Exploitability, _ctx())


def test_system_prompt_marks_evidence_untrusted():
    captured = {}

    def complete(system, user):
        captured["system"] = system
        captured["user"] = user
        return json.dumps({"probability": 0.5, "verdict": "not_exploitable"})

    Raze(backend=LLMBackend(complete)).judge(Exploitability, _ctx())
    assert "not instructions" in captured["user"]
    assert "System One" in captured["system"]
