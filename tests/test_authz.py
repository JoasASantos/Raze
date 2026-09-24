import pytest

from raze.authz import Scope, ScopeError


def test_in_scope_ok():
    s = Scope("ENG-1", "ROE-1", ["*.example.com"])
    s.require("app.example.com")  # no raise


def test_out_of_scope_rejected():
    s = Scope("ENG-1", "ROE-1", ["*.example.com"])
    with pytest.raises(ScopeError):
        s.require("victim.other.com")


def test_missing_authorization_rejected():
    s = Scope("ENG-1", "", ["*.example.com"])
    with pytest.raises(ScopeError):
        s.require("app.example.com")
