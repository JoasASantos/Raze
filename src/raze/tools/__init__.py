"""Active tools — collectors that SEND traffic to a target.

Unlike analyzers (passive, interpret already-collected data), active tools reach
out to the target. Every active tool enforces the authorization boundary before
it sends anything: `run()` calls `scope.require(target)` first. Their output is a
state dict suitable for feeding topic analyzers.
"""

from raze.tools.base import ActiveTool
from raze.tools.http import HeaderFetchTool

__all__ = ["ActiveTool", "HeaderFetchTool"]
