"""Social-engineering analyzers (authorized assessments only).

Passive over collected email-authentication data — measures how spoofable a
domain is (phishing feasibility for a sanctioned assessment). Produces no
pretext content and sends nothing.

state: {"spf": bool, "dkim": bool, "dmarc": bool, "dmarc_policy": "none"|"quarantine"|"reject",
        "lookalike_registered": bool}
"""

from __future__ import annotations

from raze.topics.base import Signal


class EmailSpoofabilityAnalyzer:
    topic = "social"

    def analyze(self, state: dict) -> list[Signal]:
        out: list[Signal] = []
        if state.get("spf") is False:
            out.append(Signal("no-spf", "no SPF record — sender easily spoofed", severity="high"))
        if state.get("dkim") is False:
            out.append(Signal("no-dkim", "no DKIM — messages unsigned", severity="medium"))
        if state.get("dmarc") is False:
            out.append(
                Signal("no-dmarc", "no DMARC — no enforcement of SPF/DKIM", severity="high")
            )
        else:
            policy = str(state.get("dmarc_policy", "")).lower()
            if policy == "none":
                out.append(
                    Signal("dmarc-monitor-only", "DMARC p=none — monitor only, no blocking", severity="medium")
                )
        if state.get("lookalike_registered"):
            out.append(
                Signal("lookalike-domain", "a look-alike domain is registered", severity="medium")
            )
        return out
