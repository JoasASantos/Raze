"""Mobile analyzers — passive over collected app manifest/config data.

state: {"cleartext_traffic": bool, "allow_backup": bool, "debuggable": bool,
        "exported_components": [ {"name": str, "permission": str|None} ]}
"""

from __future__ import annotations

from offsec_one.topics.base import Signal


class AndroidManifestAnalyzer:
    topic = "mobile"

    def analyze(self, state: dict) -> list[Signal]:
        out: list[Signal] = []
        if state.get("cleartext_traffic"):
            out.append(
                Signal("cleartext-traffic", "usesCleartextTraffic=true — MITM risk", severity="medium")
            )
        if state.get("allow_backup"):
            out.append(
                Signal("backup-allowed", "allowBackup=true — adb backup of app data", severity="low")
            )
        if state.get("debuggable"):
            out.append(
                Signal("debuggable", "android:debuggable=true in release", severity="high")
            )
        for comp in state.get("exported_components", []) or []:
            if not comp.get("permission"):
                out.append(
                    Signal(
                        "exported-component",
                        f"{comp.get('name', '?')} exported without permission — reachable by any app",
                        severity="medium",
                    )
                )
        return out
