"""Reconnaissance analyzers — passive classification of collected assets."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from offsec_one.topics.base import Signal

INTERESTING = {
    "admin": "high", "root": "high", "vpn": "high", "jenkins": "high", "git": "high",
    "dev": "medium", "staging": "medium", "test": "medium", "uat": "medium",
    "api": "medium", "internal": "high", "backup": "high", "db": "high", "sql": "high",
    "jira": "medium", "confluence": "medium", "grafana": "medium", "kibana": "medium",
}


def _host_of(state: dict) -> str | None:
    if state.get("host"):
        return str(state["host"]).strip().lower()
    url = state.get("url")
    if url:
        return (urlparse(url).hostname or "").lower() or None
    return None


class AssetAnalyzer:
    """Rank an asset's recon interest from its host/url.

    state: {"host": str} or {"url": str}
    """

    topic = "recon"

    def analyze(self, state: dict) -> list[Signal]:
        host = _host_of(state)
        if not host:
            return []
        out: list[Signal] = []
        try:
            ipaddress.ip_address(host)
            out.append(Signal("bare-ip", f"target is a bare IP {host}", severity="info"))
        except ValueError:
            labels = host.split(".")
            for label in labels:
                for kw, sev in INTERESTING.items():
                    if kw == label or label.startswith(kw + "-") or label.endswith("-" + kw):
                        out.append(
                            Signal("interesting-subdomain", f"{host} matches {kw!r}", severity=sev)
                        )
            if len(labels) >= 4:
                out.append(
                    Signal("deep-subdomain", f"{host} has {len(labels)} labels", severity="low")
                )
        return out
