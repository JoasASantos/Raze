"""Training-dataset export tests."""

import json

from raze.agent import Finding
from raze.bench import BenchCase
from raze.dataset import build_examples, to_jsonl_generic, to_jsonl_messages


def _cases():
    return [
        BenchCase(
            Finding(
                target="app.example.com",
                topic="web",
                title="unescaped reflection",
                state={"param_value": "<x>", "response_body": "<x>"},
            ),
            exploitable_truth=True,
        ),
        BenchCase(
            Finding(target="corp.example.com", topic="crypto", title="jwt none",
                    state={"jwt_alg": "none"}),
            exploitable_truth=False,
        ),
    ]


def test_target_verdict_matches_ground_truth():
    ex = build_examples(_cases())
    assert ex[0].target["verdict"] == "exploitable"
    assert ex[1].target["verdict"] == "not_exploitable"


def test_input_uses_inference_prompts_and_signals():
    ex = build_examples(_cases())
    # System prompt carries the schema + System One framing.
    assert "System One" in ex[0].system and "Exploitability" in ex[0].system
    # Analyzer signals are folded into the user prompt as evidence.
    assert "unescaped-reflection" in ex[0].user


def test_generic_jsonl_parses():
    text = to_jsonl_generic(build_examples(_cases()))
    rows = [json.loads(line) for line in text.splitlines()]
    assert len(rows) == 2
    assert set(rows[0]) == {"input", "target", "meta"}
    assert set(rows[0]["input"]) == {"system", "user"}


def test_messages_jsonl_shape():
    text = to_jsonl_messages(build_examples(_cases()))
    row = json.loads(text.splitlines()[0])
    roles = [m["role"] for m in row["messages"]]
    assert roles == ["system", "user", "assistant"]
    # Assistant content is the target judgment as JSON.
    assert json.loads(row["messages"][2]["content"])["verdict"] == "exploitable"


def test_no_analyzers_flag_drops_signals():
    ex = build_examples(_cases(), run_analyzers=False)
    assert "unescaped-reflection" not in ex[0].user
