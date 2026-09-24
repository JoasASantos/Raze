"""Authorization / scope boundary.

Hard boundary in code, not a model instruction. Any target not present in the
operator-supplied scope is rejected before Raze or any tool ever sees it.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field


class ScopeError(RuntimeError):
    """Raised when an action targets something outside the authorized scope."""


@dataclass
class Scope:
    """Operator-supplied authorization for an engagement."""

    engagement_id: str
    authorization_ref: str  # rules-of-engagement / signed-authorization identifier
    targets: list[str] = field(default_factory=list)  # host/domain globs, e.g. "*.example.com"

    def is_authorized(self, target: str) -> bool:
        return any(fnmatch.fnmatch(target, pattern) for pattern in self.targets)

    def require(self, target: str) -> None:
        if not self.authorization_ref:
            raise ScopeError("No authorization reference set; refusing to act.")
        if not self.is_authorized(target):
            raise ScopeError(
                f"Target {target!r} is outside authorized scope for "
                f"engagement {self.engagement_id!r}."
            )
