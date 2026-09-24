"""Network analyzers — rank exposure from already-collected port data."""

from __future__ import annotations

from offsec_one.topics.base import Signal

# port -> (service, severity, why)
RISKY_PORTS = {
    21: ("ftp", "medium", "cleartext FTP"),
    23: ("telnet", "high", "cleartext Telnet"),
    445: ("smb", "high", "SMB exposed"),
    3389: ("rdp", "high", "RDP exposed"),
    3306: ("mysql", "high", "MySQL exposed"),
    5432: ("postgres", "high", "PostgreSQL exposed"),
    6379: ("redis", "critical", "Redis often unauthenticated"),
    9200: ("elasticsearch", "critical", "Elasticsearch often unauthenticated"),
    11211: ("memcached", "high", "memcached, amplification/exposure"),
    27017: ("mongodb", "critical", "MongoDB often unauthenticated"),
    2375: ("docker", "critical", "Docker API unauthenticated = RCE"),
    5900: ("vnc", "high", "VNC exposed"),
}


class PortExposureAnalyzer:
    """Flag risky open ports and rank pivot/exposure value.

    state: {"open_ports": [int, ...]}  (or list of {"port": int})
    """

    topic = "network"

    def analyze(self, state: dict) -> list[Signal]:
        ports = state.get("open_ports")
        if not ports:
            return []
        normalized: list[int] = []
        for p in ports:
            if isinstance(p, dict) and "port" in p:
                normalized.append(int(p["port"]))
            elif isinstance(p, (int, str)):
                try:
                    normalized.append(int(p))
                except ValueError:
                    continue
        out: list[Signal] = []
        for port in sorted(set(normalized)):
            if port in RISKY_PORTS:
                service, sev, why = RISKY_PORTS[port]
                out.append(Signal("risky-port", f"{port}/{service}: {why}", severity=sev))
        return out
