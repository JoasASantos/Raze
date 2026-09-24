"""Active-tool base class with a mandatory authorization gate."""

from __future__ import annotations

import abc

from raze.authz import Scope, ScopeError


class ActiveTool(abc.ABC):
    """A collector that sends traffic to a target.

    Subclasses implement `_run`. The public `run` enforces the scope first, so no
    active tool can ever touch an out-of-scope or unauthorized target.
    """

    name: str = "active-tool"

    def run(self, target: str, scope: Scope | None, **kwargs) -> dict:
        if scope is None:
            raise ScopeError(f"{self.name}: active tools require an explicit Scope.")
        scope.require(target)  # raises ScopeError if unauthorized / out of scope
        return self._run(target, **kwargs)

    @abc.abstractmethod
    def _run(self, target: str, **kwargs) -> dict:
        """Do the actual collection. Return a state dict for topic analyzers."""
        raise NotImplementedError
