"""Anthropic (Claude) backend for Raze.

Wires the provider-agnostic LLMBackend to the Anthropic SDK. Requires the
`anthropic` package and credentials (ANTHROPIC_API_KEY or an `ant auth login`
profile). Install with: pip install "raze[anthropic]".

Default model is claude-opus-5. For high-volume bulk judging you can pass a
cheaper worker model (e.g. model="claude-sonnet-5" or "claude-haiku-4-5").
"""

from __future__ import annotations

from raze.backends.llm import LLMBackend


class AnthropicBackend(LLMBackend):
    def __init__(
        self,
        *,
        client=None,
        model: str = "claude-opus-5",
        max_tokens: int = 4096,
        effort: str = "high",
        system_preamble: str | None = None,
    ) -> None:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - import guard
            raise ImportError(
                'AnthropicBackend needs the anthropic SDK. Install: pip install "raze[anthropic]"'
            ) from exc

        self.client = client or anthropic.Anthropic()
        self.model = model
        self.max_tokens = max_tokens
        self.effort = effort
        super().__init__(self._complete, system_preamble=system_preamble)

    def _complete(self, system: str, user: str) -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            thinking={"type": "adaptive"},
            output_config={"effort": self.effort},
            system=system,
            messages=[{"role": "user", "content": user}],
        )

        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None)
            raise RuntimeError(f"Raze judgment refused by the model (category={category}).")

        text = "".join(
            block.text for block in response.content if getattr(block, "type", None) == "text"
        )
        if not text.strip():
            raise RuntimeError("Model returned no text content for the judgment.")
        return text
