"""Active Directory analyzers — passive over collected directory data (BloodHound-style).

state: {"accounts": [ {"name": str, "spn": bool, "asrep": bool,
                       "unconstrained_delegation": bool, "admin": bool} ]}
"""

from __future__ import annotations

from offsec_one.topics.base import Signal


class KerberoastingAnalyzer:
    topic = "ad"

    def analyze(self, state: dict) -> list[Signal]:
        out: list[Signal] = []
        for acct in state.get("accounts", []) or []:
            name = acct.get("name", "?")
            admin = bool(acct.get("admin"))
            if acct.get("spn"):
                out.append(
                    Signal(
                        "kerberoastable",
                        f"{name} has an SPN — offline crackable TGS"
                        + (" (privileged!)" if admin else ""),
                        severity="high" if admin else "medium",
                    )
                )
            if acct.get("asrep"):
                out.append(
                    Signal(
                        "asrep-roastable",
                        f"{name} has DONT_REQ_PREAUTH — AS-REP roastable",
                        severity="high" if admin else "medium",
                    )
                )
        return out


class DelegationAnalyzer:
    topic = "ad"

    def analyze(self, state: dict) -> list[Signal]:
        out: list[Signal] = []
        for acct in state.get("accounts", []) or []:
            if acct.get("unconstrained_delegation"):
                out.append(
                    Signal(
                        "unconstrained-delegation",
                        f"{acct.get('name', '?')} allows unconstrained delegation — TGT capture",
                        severity="critical",
                    )
                )
        return out
