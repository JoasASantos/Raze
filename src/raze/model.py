"""The Raze model client and backend protocol.

Raze maps a JudgmentContext to a typed judgment. It is backend-agnostic: a real
deployment plugs in the TypeSafe System One SDK, a hosted Jev-family endpoint, or
a local model. The scaffold ships `EchoBackend`, a deterministic offline stub so
the harness runs and tests pass without network or credentials.
"""

from __future__ import annotations

from typing import Protocol, TypeVar

from raze.judgments import Judgment, JudgmentContext

J = TypeVar("J", bound=Judgment)


class Backend(Protocol):
    """A source of typed judgments."""

    def judge(self, schema: type[J], context: JudgmentContext) -> J:
        ...


class EchoBackend:
    """Deterministic offline backend.

    Produces schema-valid judgments with a fixed, low probability so nothing in
    the scaffold looks confident by accident. Real inference replaces this.
    """

    def __init__(self, default_probability: float = 0.5) -> None:
        self.default_probability = default_probability

    def judge(self, schema: type[J], context: JudgmentContext) -> J:
        defaults: dict = {
            "probability": self.default_probability,
            "rationale": f"EchoBackend stub for task: {context.task!r}",
        }
        # Fill required non-default fields with the schema's first enum/typed option.
        for name, field in schema.model_fields.items():
            if name in defaults or not field.is_required():
                continue
            defaults[name] = _placeholder(field.annotation)
        return schema(**defaults)


def _placeholder(annotation):
    import enum

    if isinstance(annotation, type) and issubclass(annotation, enum.Enum):
        return list(annotation)[0]  # conservative member (defined first by convention)
    if annotation in (bool,):
        return False
    if annotation in (int,):
        return 0
    if annotation in (float,):
        return 0.0
    if annotation in (str,):
        return ""
    return None


class Raze:
    """System One model: `state -> typed judgment + probability`.

    Raze does exactly one narrow thing per call. It does not plan, browse, or
    execute tools. The harness (OffSec One) composes many Raze calls and gates
    them with deterministic validators.
    """

    def __init__(self, backend: Backend | None = None) -> None:
        self.backend: Backend = backend or EchoBackend()

    def judge(self, schema: type[J], context: JudgmentContext) -> J:
        return self.backend.judge(schema, context)
