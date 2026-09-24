"""Cloud analyzers — bucket exposure and metadata-SSRF detection over collected data."""

from __future__ import annotations

from urllib.parse import urlparse

from raze.topics.base import Signal

# Cloud metadata endpoints reachable via SSRF.
METADATA_HOSTS = {
    "169.254.169.254": "AWS/GCP/Azure IMDS",
    "metadata.google.internal": "GCP metadata",
    "100.100.200.200": "Alibaba metadata",
}


class BucketExposureAnalyzer:
    """Flag a publicly exposed object-storage bucket.

    state: {"bucket_acl": {"public": bool, "grants": [str]}} or {"bucket_public": bool}
    """

    topic = "cloud"

    def analyze(self, state: dict) -> list[Signal]:
        acl = state.get("bucket_acl") or {}
        public = state.get("bucket_public")
        if public is None and isinstance(acl, dict):
            grants = [str(g).lower() for g in acl.get("grants", [])]
            public = bool(acl.get("public")) or any(
                "allusers" in g or "public" in g for g in grants
            )
        if public:
            return [Signal("public-bucket", "object storage readable by anyone", severity="high")]
        return []


class MetadataSSRFAnalyzer:
    """Flag a request/URL pointed at a cloud metadata endpoint (SSRF target).

    state: {"url": str}
    """

    topic = "cloud"

    def analyze(self, state: dict) -> list[Signal]:
        url = state.get("url")
        if not url:
            return []
        host = (urlparse(url).hostname or "").lower()
        if host in METADATA_HOSTS:
            return [
                Signal(
                    "metadata-endpoint",
                    f"URL targets {host} ({METADATA_HOSTS[host]}) — SSRF to credentials",
                    severity="critical",
                )
            ]
        return []
