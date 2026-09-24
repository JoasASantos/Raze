"""Triage a candidate finding end-to-end with the offline EchoBackend.

Run: python examples/triage_finding.py
"""

from __future__ import annotations

from offsec_one import Finding, OffSecOne, Scope
from raze import Raze


def main() -> None:
    scope = Scope(
        engagement_id="ENG-2026-001",
        authorization_ref="ROE-signed-2026-09-23",
        targets=["*.example.com"],
    )
    agent = OffSecOne(raze=Raze(), scope=scope)

    finding = Finding(
        target="app.example.com",
        topic="web",
        title="Reflected parameter in search endpoint",
        has_reproduction=False,  # no PoC yet -> validator will not queue an exploitable verdict
        state={
            "param_value": "<svg onload=1>",
            "response_body": "<html>results for <svg onload=1> ...</html>",
            "response_headers": {"Server": "nginx"},  # no CSP/HSTS/etc.
        },
    )

    a = agent.assess(finding)
    print(f"target        : {a.finding.target}")
    print("signals       :")
    for s in a.signals:
        print(f"  - {s}")
    print(f"exploitability: {a.exploitability.verdict.value} (p={a.exploitability.probability})")
    print(f"reachable     : {a.reachability.reachable}")
    print(f"novelty       : {a.novelty.novelty.value}")
    print(f"severity      : {a.impact.severity.value}")
    print(f"disposition   : {a.result.disposition}  reasons={a.result.reasons}")


if __name__ == "__main__":
    main()
