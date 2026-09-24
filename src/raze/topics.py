"""Offensive-security topic taxonomy. See docs/TOPICS.md."""

from __future__ import annotations

from enum import Enum


class Topic(str, Enum):
    recon = "recon"
    web = "web"
    network = "network"
    ad = "ad"
    cloud = "cloud"
    mobile = "mobile"
    wireless = "wireless"
    exploitdev = "exploitdev"
    reversing = "reversing"
    social = "social"
    crypto = "crypto"


ALL_TOPICS = [t.value for t in Topic]
