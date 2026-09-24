"""Topic analyzers registry.

Maps each offensive-security topic key to its deterministic analyzers. Topics with
no analyzer yet are listed in PROPOSED_TOPICS — declared, honestly not implemented.
"""

from __future__ import annotations

from offsec_one.topics.ad import DelegationAnalyzer, KerberoastingAnalyzer
from offsec_one.topics.base import Analyzer, Signal
from offsec_one.topics.cloud import BucketExposureAnalyzer, MetadataSSRFAnalyzer
from offsec_one.topics.crypto import SecretEntropyAnalyzer, WeakAlgorithmAnalyzer
from offsec_one.topics.exploitdev import MitigationAnalyzer
from offsec_one.topics.mobile import AndroidManifestAnalyzer
from offsec_one.topics.network import PortExposureAnalyzer
from offsec_one.topics.recon import AssetAnalyzer
from offsec_one.topics.reversing import BinaryTriageAnalyzer
from offsec_one.topics.social import EmailSpoofabilityAnalyzer
from offsec_one.topics.web import ReflectionAnalyzer, SecurityHeaderAnalyzer
from offsec_one.topics.wireless import WifiSecurityAnalyzer

ANALYZERS: dict[str, list[Analyzer]] = {
    "web": [ReflectionAnalyzer(), SecurityHeaderAnalyzer()],
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


__all__ = ["ANALYZERS", "PROPOSED_TOPICS", "Signal", "Analyzer", "analyze"]
