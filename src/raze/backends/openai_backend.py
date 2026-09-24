"""OpenAI-compatible backend for Raze (OpenAI / Codex / Azure / local / OpenRouter).

Works with any OpenAI-compatible Chat Completions endpoint via `base_url`, so the
same class covers OpenAI, Codex-style models, Azure OpenAI, OpenRouter, and local
servers (Ollama/vLLM in OpenAI mode). Requires the `openai` package.

    pip install "raze[openai]"
"""

from __future__ import annotations

from raze.backends.llm import LLMBackend


class OpenAIBackend(LLMBackend):
    def __init__(
        self,
        *,
        client=None,
        model: str = "gpt-4o",
        base_url: str | None = None,
        api_key: str | None = None,
        temperature: float = 0.0,
        system_preamble: str | None = None,
    ) -> None:
        if client is None:
            try:
                from openai import OpenAI
            except ImportError as exc:  # pragma: no cover - import guard
                raise ImportError(
                    'OpenAIBackend needs the openai SDK. Install: pip install "raze[openai]"'
                ) from exc
            kwargs = {}
            if base_url:
                kwargs["base_url"] = base_url
            if api_key:
                kwargs["api_key"] = api_key
            client = OpenAI(**kwargs)
        self.client = client
        self.model = model
        self.temperature = temperature
        super().__init__(self._complete, system_preamble=system_preamble)

    def _complete(self, system: str, user: str) -> str:
        resp = self.client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        content = resp.choices[0].message.content
        if not content or not content.strip():
            raise RuntimeError("OpenAI backend returned empty content for the judgment.")
        return content
