"""Google Gemini backend for Raze. Requires the `google-genai` package.

    pip install "raze[gemini]"
"""

from __future__ import annotations

from raze.backends.llm import LLMBackend


class GeminiBackend(LLMBackend):
    def __init__(
        self,
        *,
        client=None,
        model: str = "gemini-2.5-pro",
        api_key: str | None = None,
        system_preamble: str | None = None,
    ) -> None:
        if client is None:
            try:
                from google import genai
            except ImportError as exc:  # pragma: no cover - import guard
                raise ImportError(
                    'GeminiBackend needs google-genai. Install: pip install "raze[gemini]"'
                ) from exc
            client = genai.Client(api_key=api_key) if api_key else genai.Client()
        self.client = client
        self.model = model
        super().__init__(self._complete, system_preamble=system_preamble)

    def _complete(self, system: str, user: str) -> str:
        resp = self.client.models.generate_content(
            model=self.model,
            contents=user,
            config={
                "system_instruction": system,
                "response_mime_type": "application/json",
                "temperature": 0.0,
            },
        )
        text = getattr(resp, "text", None)
        if not text or not text.strip():
            raise RuntimeError("Gemini backend returned empty content for the judgment.")
        return text
