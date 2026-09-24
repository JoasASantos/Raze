"""Topic analyzers registry.

Maps each offensive-security topic key to its deterministic analyzers. Topics with
no analyzer yet are listed in PROPOSED_TOPICS — declared, honestly not implemented.
"""

from __future__ import annotations

from offsec_one.topics.base import Analyzer, Signal
from offsec_one.topics.cloud import BucketExposureAnalyzer, MetadataSSRFAnalyzer
from offsec_one.topics.crypto import SecretEntropyAnalyzer, WeakAlgorithmAnalyzer
from offsec_one.topics.network import PortExposureAnalyzer
from offsec_one.topics.recon import AssetAnalyzer
from offsec_one.topics.web import ReflectionAnalyzer, SecurityHeaderAnalyzer

ANALYZERS: dict[str, list[Analyzer]] = {
    "web": [ReflectionAnalyzer(), SecurityHeaderAnalyzer()],
    "recon": [AssetAnalyzer()],
    "network": [PortExposureAnalyzer()],
    "cloud": [BucketExposureAnalyzer(), MetadataSSRFAnalyzer()],
    "crypto": [WeakAlgorithmAnalyzer(), SecretEntropyAnalyzer()],
}

# Declared in the taxonomy, analyzers not yet implemented (see docs/TOPICS.md).
PROPOSED_TOPICS = ["ad", "mobile", "wireless", "exploitdev", "reversing", "social"]


def analyze(topic: str, state: dict) -> list[Signal]:
    """Run every analyzer registered for `topic` over `state` and collect signals."""
    signals: list[Signal] = []
    for analyzer in ANALYZERS.get(topic, []):
        signals.extend(analyzer.analyze(state))
    return signals


__all__ = ["ANALYZERS", "PROPOSED_TOPICS", "Signal", "Analyzer", "analyze"]
