"""HTTP header-fetch active tool.

Performs a single GET against an authorized target and returns its response
headers as analyzer-ready state (feeds web.SecurityHeaderAnalyzer, etc.). Only
http/https schemes are allowed.
"""

from __future__ import annotations

import urllib.request
from urllib.parse import urlparse

from raze.tools.base import ActiveTool


class HeaderFetchTool(ActiveTool):
    name = "http-header-fetch"

    def __init__(self, timeout: float = 10.0, user_agent: str = "raze/0.0") -> None:
        self.timeout = timeout
        self.user_agent = user_agent

    def _run(self, target: str, **kwargs) -> dict:
        url = target if "://" in target else f"https://{target}"
        scheme = urlparse(url).scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"HeaderFetchTool only allows http/https, got {scheme!r}")
        req = urllib.request.Request(
            url, method="GET", headers={"User-Agent": self.user_agent}
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            headers = {k: v for k, v in resp.headers.items()}
            status = getattr(resp, "status", None)
        return {"url": url, "status": status, "response_headers": headers}
