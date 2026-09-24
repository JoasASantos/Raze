"""Multi-provider backend tests (offline, fake clients)."""

import json
from types import SimpleNamespace

import pytest

from raze import Raze
from raze.backends import PROVIDERS, make_backend
from raze.backends.gemini_backend import GeminiBackend
from raze.backends.openai_backend import OpenAIBackend
from raze.judgments import Exploitability, ExploitVerdict, JudgmentContext

_JUDGMENT = json.dumps({"probability": 0.8, "rationale": "r", "verdict": "exploitable"})


def _ctx():
    return JudgmentContext(task="assess", topic="web")


def test_make_backend_echo_is_none_and_unknown_raises():
    assert make_backend("echo") is None
    with pytest.raises(ValueError):
        make_backend("nope")
    assert set(PROVIDERS) == {"echo", "anthropic", "openai", "gemini"}


def _fake_openai_client(content):
    def create(**kwargs):
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])
    return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))


def test_openai_backend_parses_judgment():
    be = OpenAIBackend(client=_fake_openai_client(_JUDGMENT), model="gpt-x")
    j = Raze(backend=be).judge(Exploitability, _ctx())
    assert j.verdict == ExploitVerdict.exploitable and j.probability == 0.8


def test_openai_backend_via_factory_with_client():
    be = make_backend("openai", client=_fake_openai_client(_JUDGMENT), model="gpt-x")
    assert isinstance(be, OpenAIBackend)
    assert Raze(backend=be).judge(Exploitability, _ctx()).verdict == ExploitVerdict.exploitable


def test_openai_empty_content_raises():
    be = OpenAIBackend(client=_fake_openai_client("  "), model="gpt-x")
    with pytest.raises(RuntimeError):
        Raze(backend=be).judge(Exploitability, _ctx())


def _fake_gemini_client(text):
    def generate_content(**kwargs):
        return SimpleNamespace(text=text)
    return SimpleNamespace(models=SimpleNamespace(generate_content=generate_content))


def test_gemini_backend_parses_judgment():
    be = GeminiBackend(client=_fake_gemini_client(_JUDGMENT), model="gemini-x")
    j = Raze(backend=be).judge(Exploitability, _ctx())
    assert j.verdict == ExploitVerdict.exploitable


def test_gemini_via_factory():
    be = make_backend("gemini", client=_fake_gemini_client(_JUDGMENT))
    assert isinstance(be, GeminiBackend)
