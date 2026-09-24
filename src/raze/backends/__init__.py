"""Concrete Raze backends — plug the model into any harness / provider.

- `LLMBackend`: provider-agnostic. Supply a `complete_fn(system, user) -> str`
  that calls any LLM; the backend builds the System One prompt, extracts JSON,
  and validates it into the requested typed judgment. This is the universal
  insertion point — a TypeSafe System One SDK call, a local model, or any harness
  plugs in here.
- `AnthropicBackend` (Claude), `OpenAIBackend` (OpenAI/Codex/Azure/OpenRouter/
  local via base_url), `GeminiBackend` (Google Gemini): ready-made wrappers.
- `make_backend(provider, ...)`: build one by name.
"""

from raze.backends.llm import JudgmentParseError, LLMBackend, build_system_prompt, build_user_prompt

__all__ = [
    "PROVIDERS",
    "JudgmentParseError",
    "LLMBackend",
    "build_system_prompt",
    "build_user_prompt",
    "make_backend",
]

PROVIDERS = ("echo", "anthropic", "openai", "gemini")


def make_backend(provider: str, **kwargs):
    """Return a backend by provider name. `echo` returns None (Raze() uses the
    offline EchoBackend). Extra kwargs (model, base_url, api_key, client) pass
    through to the chosen backend."""
    provider = provider.lower()
    if provider == "echo":
        return None
    if provider == "anthropic":
        from raze.backends.anthropic_backend import AnthropicBackend

        return AnthropicBackend(**kwargs)
    if provider == "openai":
        from raze.backends.openai_backend import OpenAIBackend

        return OpenAIBackend(**kwargs)
    if provider == "gemini":
        from raze.backends.gemini_backend import GeminiBackend

        return GeminiBackend(**kwargs)
    raise ValueError(f"Unknown provider {provider!r}; expected one of {PROVIDERS}")


def __getattr__(name: str):
    # Lazy import so importing the package never requires any provider SDK.
    if name == "AnthropicBackend":
        from raze.backends.anthropic_backend import AnthropicBackend

        return AnthropicBackend
    if name == "OpenAIBackend":
        from raze.backends.openai_backend import OpenAIBackend

        return OpenAIBackend
    if name == "GeminiBackend":
        from raze.backends.gemini_backend import GeminiBackend

        return GeminiBackend
    raise AttributeError(name)
