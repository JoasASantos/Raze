# Harnesses & providers

Raze is a **model primitive**, not a monolith: the judgment model plugs into any
harness or LLM provider. The universal insertion point is `LLMBackend`.

## Ready-made providers

| Provider | Backend | Install | Covers |
|----------|---------|---------|--------|
| Claude | `AnthropicBackend` | `pip install "raze[anthropic]"` | Anthropic API |
| OpenAI / Codex | `OpenAIBackend` | `pip install "raze[openai]"` | OpenAI, Codex models, Azure OpenAI, OpenRouter, local (Ollama/vLLM) via `base_url` |
| Gemini | `GeminiBackend` | `pip install "raze[gemini]"` | Google Gemini |
| offline | `EchoBackend` | (built in) | tests / wiring |

```python
from raze import Raze
from raze.backends import make_backend

raze = Raze(backend=make_backend("openai", model="gpt-4o"))            # OpenAI
raze = Raze(backend=make_backend("openai", base_url="http://localhost:11434/v1",
                                 model="llama3.1"))                     # local, OpenAI-compat
raze = Raze(backend=make_backend("gemini", model="gemini-2.5-pro"))    # Gemini
raze = Raze(backend=make_backend("anthropic", model="claude-opus-5"))  # Claude
```

CLI (every command takes `--backend`):

```bash
raze decide finding.json --backend openai --model gpt-4o
raze plan   findings.json --backend gemini
raze swarm  findings.json --backend openai --base-url http://localhost:11434/v1 --model llama3.1
```

## Any other harness (the universal way)

Anything that can produce text from a (system, user) prompt is a backend. Write a
`complete_fn` and wrap it:

```python
from raze import Raze
from raze.backends import LLMBackend

def complete(system: str, user: str) -> str:
    return my_harness.run(system=system, user=user)   # Codex CLI, a gateway, a queue, TypeSafe System One, ...

raze = Raze(backend=LLMBackend(complete))
```

`LLMBackend` builds the System One prompt (schema-injected, evidence marked
untrusted), extracts the JSON judgment, and validates it — so any harness gets the
same typed, gated, calibrated decisions.

## Using Raze inside agent harnesses

Raze is a plain Python library + CLI, so it drops into any agent harness (Claude
Code, Codex CLI, Gemini CLI, custom loops) as a tool: call `raze decide/plan/swarm`
or import `RazeAgent`. Offensive execution stays human-gated regardless of harness.
