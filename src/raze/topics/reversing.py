"""Reverse-engineering analyzers — passive over collected static-analysis data.

state: {"imports": [str], "strings": [str]}
"""

from __future__ import annotations

import re

from raze.topics.base import Signal

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
        imports = [str(i).lower().lstrip("_") for i in state.get("imports", []) or []]
        strings = [str(s) for s in state.get("strings", []) or []]
        command_sinks = {"system", "exec", "popen"}

        for key in imports:
            if key in DANGEROUS_IMPORTS:
                sev, why = DANGEROUS_IMPORTS[key]
                out.append(Signal("dangerous-import", why, severity=sev))
        for s in strings:
            if "PRIVATE KEY" in s.upper():
                out.append(Signal("embedded-secret", "embedded private key in binary", "high"))
            elif _INTERESTING_STRING.search(s):
                out.append(Signal("interesting-string", f"{s[:60]!r}", severity="low"))

        # A command-exec sink plus a format/argument string is injection evidence.
        if any(k in command_sinks for k in imports) and any("%s" in s or "-c" in s for s in strings):
            out.append(
                Signal("command-injection-evidence",
                       "command-exec sink fed a tainted/format string", severity="high")
            )
        return out
