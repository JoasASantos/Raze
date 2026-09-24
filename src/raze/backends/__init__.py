"""Concrete Raze backends.

- `LLMBackend`: provider-agnostic. You supply a `complete_fn(system, user) -> str`
  that calls any LLM; the backend builds the System One prompt, extracts JSON,
  and validates it into the requested typed judgment.
- `AnthropicBackend`: an `LLMBackend` wired to the Anthropic SDK (Claude).

Any other provider (a TypeSafe System One SDK call, a local model, an OpenAI-style
endpoint) plugs in by writing its own `complete_fn` and passing it to `LLMBackend`.
"""

from raze.backends.llm import LLMBackend, JudgmentParseError, build_system_prompt, build_user_prompt

__all__ = [
    "LLMBackend",
    "JudgmentParseError",
    "build_system_prompt",
    "build_user_prompt",
]


def __getattr__(name: str):
    # Lazy import so importing the package never requires the anthropic SDK.
    if name == "AnthropicBackend":
        from raze.backends.anthropic_backend import AnthropicBackend

        return AnthropicBackend
    raise AttributeError(name)
