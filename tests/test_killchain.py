"""Decision-surface registry tests."""

from raze.judgments import GoNoGo, Judgment
from raze.killchain import (
    DECISION_REGISTRY,
    DecisionKind,
    Phase,
    human_gated_kinds,
    spec_for,
)


def test_every_kind_has_a_spec():
    assert set(DECISION_REGISTRY) == set(DecisionKind)


def test_specs_are_well_formed():
    for kind, spec in DECISION_REGISTRY.items():
        assert spec.kind == kind
        assert isinstance(spec.phase, Phase)
        assert issubclass(spec.schema, Judgment)
        assert spec.question


def test_offensive_actions_are_human_gated():
    gated = set(human_gated_kinds())
    assert {
        DecisionKind.technique_selection,
        DecisionKind.go_no_go,
        DecisionKind.next_pivot,
        DecisionKind.privesc_path,
    } <= gated
    # Read-only analysis is not gated.
    assert DecisionKind.exploitability not in gated
    assert DecisionKind.severity not in gated


def test_go_no_go_defaults_conservative():
    j = GoNoGo(probability=0.5)
    assert j.proceed is False
    assert j.requires_human is True


def test_spec_for_returns_schema():
    assert spec_for(DecisionKind.go_no_go).schema is GoNoGo
