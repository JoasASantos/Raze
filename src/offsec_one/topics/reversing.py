"""Reverse-engineering analyzers — passive over collected static-analysis data.

state: {"imports": [str], "strings": [str]}
"""

from __future__ import annotations

import re

from offsec_one.topics.base import Signal

# Dangerous imported functions -> (severity, why)
DANGEROUS_IMPORTS = {
    "gets": ("critical", "gets() — unbounded read, classic overflow"),
    "strcpy": ("high", "strcpy() — no bounds check"),
    "strcat": ("high", "strcat() — no bounds check"),
    "sprintf": ("high", "sprintf() — format/overflow risk"),
    "system": ("high", "system() — command execution sink"),
    "exec": ("high", "exec*() — command execution sink"),
    "popen": ("high", "popen() — command execution sink"),
    "memcpy": ("medium", "memcpy() — check length provenance"),
    "scanf": ("medium", "scanf() — unbounded %s risk"),
}

_INTERESTING_STRING = re.compile(
    r"(password|passwd|secret|api[_-]?key|token|BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|https?://)",
    re.IGNORECASE,
)


class BinaryTriageAnalyzer:
    topic = "reversing"

    def analyze(self, state: dict) -> list[Signal]:
        out: list[Signal] = []
        for imp in state.get("imports", []) or []:
            key = str(imp).lower().lstrip("_")
            if key in DANGEROUS_IMPORTS:
                sev, why = DANGEROUS_IMPORTS[key]
                out.append(Signal("dangerous-import", why, severity=sev))
        for s in state.get("strings", []) or []:
            if _INTERESTING_STRING.search(str(s)):
                snippet = str(s)[:60]
                out.append(Signal("interesting-string", f"{snippet!r}", severity="low"))
        return out
