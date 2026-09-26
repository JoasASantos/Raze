"""Deterministic (no-LLM) judgment backend.

Derives a judgment from the analyzer signals + inferred vulnerability class +
CVSS-grounded severity — no model, no network, no fine-tune. This makes Raze
genuinely decision-capable standalone: an LLM backend becomes an optional upgrade
for the semantic verdict, not a requirement.

Heuristic (transparent, tunable):
- reachable  = any signal was produced (evidence exists).
- verdict    = `exploitable` when a high/critical CONFIRMING signal is present and
               reachable; `conditional` when there is any medium+ signal; else
               `not_exploitable` (hardening/weak signals alone do not confirm).
- severity   = max(strongest signal severity, class typical CVSS severity).
- probability= from the effective severity (calibrate with raze.calibrator).
"""

from __future__ import annotations

from raze.classify import infer_class
from raze.judgments import Judgment, JudgmentContext, NoveltyClass, Severity
from raze.topics import analyze

_ORD = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_PROB = {
    Severity.info: 0.3,
    Severity.low: 0.4,
    Severity.medium: 0.6,
    Severity.high: 0.8,
    Severity.critical: 0.9,
}

# Signals that, at high/critical severity, confirm a concrete exploitable path
# (as opposed to hardening/weak-only signals like missing-header or no-nx).
EXPLOIT_CONFIRMING = {
    "sql-error", "unescaped-reflection", "open-redirect", "cors-misconfig",
    "jwt-alg-none", "low-entropy-secret", "metadata-endpoint", "public-bucket",
    "risky-port", "kerberoastable", "asrep-roastable", "unconstrained-delegation",
    "wifi-encryption", "wps-enabled", "cleartext-traffic", "debuggable",
    "exported-component", "no-spf", "no-dmarc",
}


class HeuristicBackend:
    """A Raze backend that decides deterministically, without any model."""

    def judge(self, schema: type[Judgment], context: JudgmentContext) -> Judgment:
        signals = analyze(context.topic, context.state)
        vc = infer_class(context.topic, signals)

        reachable = bool(signals) or bool(context.evidence)
        confirming = any(
            s.severity in ("high", "critical") and s.name in EXPLOIT_CONFIRMING for s in signals
        )
        any_medium_plus = any(_ORD.get(s.severity, 0) >= 2 for s in signals)

        if confirming and reachable:
            verdict = "exploitable"
        elif any_medium_plus and reachable:
            verdict = "conditional"
        else:
            verdict = "not_exploitable"

        sev_values = [s.severity for s in signals]
        if vc is not None:
            sev_values.append(vc.typical_severity.value)
        eff = max(sev_values, key=lambda v: _ORD.get(v, 0)) if sev_values else "info"
        severity = Severity(eff)
        exploitable = verdict == "exploitable"

        fields = {
            "probability": _PROB[severity],
            "rationale": (
                f"heuristic: {len(signals)} signal(s), class={vc.id if vc else None}, "
                f"severity={severity.value}, reachable={reachable}"
            ),
            "verdict": verdict,
            "reachable": reachable,
            "novelty": NoveltyClass.novel.value,
            "severity": severity.value,
            "confidentiality": exploitable,
            "integrity": exploitable,
            "availability": False,
            "preconditions": [],
            "next_actions": [],
            # extra fields for other schemas (pydantic ignores unknown ones)
            "in_scope": True,
            "proceed": False,
            "requires_human": True,
            "score": _PROB[severity],
            "candidates": [],
        }
        return schema.model_validate(fields)
