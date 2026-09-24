"""Topic analyzers registry.

Maps each offensive-security topic key to its deterministic analyzers. Topics with
no analyzer yet are listed in PROPOSED_TOPICS — declared, honestly not implemented.
"""

from __future__ import annotations

from raze.topics.ad import DelegationAnalyzer, KerberoastingAnalyzer
from raze.topics.base import Analyzer, Signal
from raze.topics.cloud import BucketExposureAnalyzer, MetadataSSRFAnalyzer
from raze.topics.crypto import SecretEntropyAnalyzer, WeakAlgorithmAnalyzer
from raze.topics.exploitdev import MitigationAnalyzer
from raze.topics.mobile import AndroidManifestAnalyzer
from raze.topics.network import PortExposureAnalyzer
from raze.topics.recon import AssetAnalyzer
from raze.topics.reversing import BinaryTriageAnalyzer
from raze.topics.social import EmailSpoofabilityAnalyzer
from raze.topics.taxonomy import ALL_TOPICS, Topic
from raze.topics.web import (
    ClickjackingAnalyzer,
    CookieSecurityAnalyzer,
    CorsMisconfigAnalyzer,
    OpenRedirectAnalyzer,
    ReflectionAnalyzer,
    SecurityHeaderAnalyzer,
    SQLiErrorAnalyzer,
)
from raze.topics.wireless import WifiSecurityAnalyzer

ANALYZERS: dict[str, list[Analyzer]] = {
    "web": [
        ReflectionAnalyzer(),
        SQLiErrorAnalyzer(),
        OpenRedirectAnalyzer(),
        CorsMisconfigAnalyzer(),
        ClickjackingAnalyzer(),
        CookieSecurityAnalyzer(),
        SecurityHeaderAnalyzer(),
    ],
    "recon": [AssetAnalyzer()],
    "network": [PortExposureAnalyzer()],
    "cloud": [BucketExposureAnalyzer(), MetadataSSRFAnalyzer()],
    "crypto": [WeakAlgorithmAnalyzer(), SecretEntropyAnalyzer()],
    "ad": [KerberoastingAnalyzer(), DelegationAnalyzer()],
    "mobile": [AndroidManifestAnalyzer()],
    "wireless": [WifiSecurityAnalyzer()],
    "exploitdev": [MitigationAnalyzer()],
    "reversing": [BinaryTriageAnalyzer()],
    "social": [EmailSpoofabilityAnalyzer()],
}

# Every taxonomy topic now has at least one analyzer.
PROPOSED_TOPICS: list[str] = []


def analyze(topic: str, state: dict) -> list[Signal]:
    """Run every analyzer registered for `topic` over `state` and collect signals."""
    signals: list[Signal] = []
    for analyzer in ANALYZERS.get(topic, []):
        signals.extend(analyzer.analyze(state))
    return signals


__all__ = [
    "ALL_TOPICS",
    "ANALYZERS",
    "PROPOSED_TOPICS",
    "Analyzer",
    "Signal",
    "Topic",
    "analyze",
]
