"""Wireless analyzers — passive over collected AP survey data.

state: {"encryption": "open"|"wep"|"wpa"|"wpa2"|"wpa3", "wps_enabled": bool,
        "cipher": "tkip"|"ccmp"|...}
"""

from __future__ import annotations

from offsec_one.topics.base import Signal

_ENC = {
    "open": ("critical", "open network — no encryption"),
    "wep": ("critical", "WEP is trivially broken"),
    "wpa": ("high", "WPA (TKIP) is deprecated and attackable"),
    "wpa2": ("info", "WPA2 — handshake capture + offline crack if weak PSK"),
    "wpa3": ("info", "WPA3 — SAE; check for downgrade/transition mode"),
}


class WifiSecurityAnalyzer:
    topic = "wireless"

    def analyze(self, state: dict) -> list[Signal]:
        out: list[Signal] = []
        enc = str(state.get("encryption", "")).lower()
        if enc in _ENC:
            sev, why = _ENC[enc]
            out.append(Signal("wifi-encryption", why, severity=sev))
        if str(state.get("cipher", "")).lower() == "tkip":
            out.append(Signal("weak-cipher", "TKIP cipher in use", severity="medium"))
        if state.get("wps_enabled"):
            out.append(
                Signal("wps-enabled", "WPS enabled — Pixie-Dust / PIN brute force", severity="high")
            )
        return out
