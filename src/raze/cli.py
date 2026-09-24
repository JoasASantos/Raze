"""Raze CLI.

Commands:
  raze assess FINDING [--scope S] [--backend echo|anthropic] [--model M] [--json]
  raze topics
  raze --version

FINDING is a path to a JSON file, or '-' to read from stdin:
  {"target": "app.example.com", "topic": "web", "title": "...",
   "evidence": ["..."], "has_reproduction": false, "state": {...}}

Scope JSON:
  {"engagement_id": "ENG-1", "authorization_ref": "ROE-1", "targets": ["*.example.com"]}
"""

from __future__ import annotations

import argparse
import json
import sys

from raze import Raze, __version__
from raze.agent import Assessment, Finding, RazeAgent
from raze.authz import Scope, ScopeError
from raze.engagement import run_engagement
from raze.topics import ANALYZERS, PROPOSED_TOPICS

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_SCOPE = 2
EXIT_JUDGMENT = 3


def _load_json(path: str) -> dict:
    if path == "-":
        return json.load(sys.stdin)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _build_backend(name: str, model: str | None):
    if name == "echo":
        return None  # Raze() defaults to EchoBackend
    if name == "anthropic":
        from raze.backends import AnthropicBackend

        return AnthropicBackend(model=model) if model else AnthropicBackend()
    raise ValueError(f"Unknown backend {name!r}")


def _assessment_to_dict(a: Assessment) -> dict:
    return {
        "finding": {
            "target": a.finding.target,
            "topic": a.finding.topic,
            "title": a.finding.title,
            "has_reproduction": a.finding.has_reproduction,
        },
        "signals": [str(s) for s in a.signals],
        "exploitability": a.exploitability.model_dump(mode="json"),
        "impact": a.impact.model_dump(mode="json"),
        "reachability": a.reachability.model_dump(mode="json"),
        "novelty": a.novelty.model_dump(mode="json"),
        "disposition": a.result.disposition,
        "accepted": a.result.accepted,
        "reasons": a.result.reasons,
    }


def _print_human(a: Assessment) -> None:
    print(f"target        : {a.finding.target}  ({a.finding.topic})")
    print(f"title         : {a.finding.title}")
    if a.signals:
        print("signals       :")
        for s in a.signals:
            print(f"  - {s}")
    print(f"exploitability: {a.exploitability.verdict.value} (p={a.exploitability.probability})")
    print(f"reachable     : {a.reachability.reachable}")
    print(f"novelty       : {a.novelty.novelty.value}")
    print(f"severity      : {a.impact.severity.value}")
    print(f"disposition   : {a.result.disposition}  reasons={a.result.reasons}")


def _cmd_assess(args: argparse.Namespace) -> int:
    try:
        finding_data = _load_json(args.finding)
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: cannot read finding: {e}", file=sys.stderr)
        return EXIT_USAGE

    scope = None
    if args.scope:
        try:
            scope = Scope(**_load_json(args.scope))
        except (OSError, json.JSONDecodeError, TypeError) as e:
            print(f"error: cannot read scope: {e}", file=sys.stderr)
            return EXIT_USAGE

    try:
        finding = Finding(**finding_data)
    except TypeError as e:
        print(f"error: invalid finding fields: {e}", file=sys.stderr)
        return EXIT_USAGE

    try:
        backend = _build_backend(args.backend, args.model)
    except Exception as e:  # noqa: BLE001 - surface backend construction issues cleanly
        print(f"error: backend: {e}", file=sys.stderr)
        return EXIT_USAGE

    agent = RazeAgent(raze=Raze(backend=backend), scope=scope, run_analyzers=not args.no_analyzers)

    try:
        assessment = agent.assess(finding)
    except ScopeError as e:
        print(f"scope refused: {e}", file=sys.stderr)
        return EXIT_SCOPE
    except Exception as e:  # noqa: BLE001 - e.g. JudgmentParseError, backend errors
        print(f"assessment failed: {e}", file=sys.stderr)
        return EXIT_JUDGMENT

    if args.json:
        print(json.dumps(_assessment_to_dict(assessment), indent=2))
    else:
        _print_human(assessment)
    return EXIT_OK


def _cmd_decide(args: argparse.Namespace) -> int:
    try:
        finding_data = _load_json(args.finding)
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: cannot read finding: {e}", file=sys.stderr)
        return EXIT_USAGE

    scope = None
    if args.scope:
        try:
            scope = Scope(**_load_json(args.scope))
        except (OSError, json.JSONDecodeError, TypeError) as e:
            print(f"error: cannot read scope: {e}", file=sys.stderr)
            return EXIT_USAGE

    try:
        finding = Finding(**finding_data)
        backend = _build_backend(args.backend, args.model)
    except Exception as e:  # noqa: BLE001 - surface finding/backend errors cleanly
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE

    agent = RazeAgent(raze=Raze(backend=backend), scope=scope, run_analyzers=not args.no_analyzers)
    try:
        decision = agent.decide(finding)
    except ScopeError as e:
        print(f"scope refused: {e}", file=sys.stderr)
        return EXIT_SCOPE
    except Exception as e:  # noqa: BLE001
        print(f"decision failed: {e}", file=sys.stderr)
        return EXIT_JUDGMENT

    if args.json:
        print(json.dumps(decision.to_dict(), indent=2))
    else:
        print(f"[{decision.action.upper()}] {decision.finding_title}  "
              f"priority={decision.priority:.1f} confidence={decision.confidence}")
        print(f"  {decision.rationale}")
        if decision.latency_ms is not None:
            print(f"  latency={decision.latency_ms:.1f}ms (single combined call)")
    return EXIT_OK


def _cmd_plan(args: argparse.Namespace) -> int:
    """Campaign-level: decide a whole set of findings and rank a global plan."""
    try:
        raw = _load_json(args.findings)
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: cannot read findings: {e}", file=sys.stderr)
        return EXIT_USAGE
    if not isinstance(raw, list):
        print("error: findings file must be a JSON array", file=sys.stderr)
        return EXIT_USAGE

    scope = None
    if args.scope:
        try:
            scope = Scope(**_load_json(args.scope))
        except (OSError, json.JSONDecodeError, TypeError) as e:
            print(f"error: cannot read scope: {e}", file=sys.stderr)
            return EXIT_USAGE

    try:
        # Accept either bare finding objects or dataset rows ({"finding": {...}}).
        findings = [Finding(**(entry.get("finding", entry))) for entry in raw]
        backend = _build_backend(args.backend, args.model)
    except Exception as e:  # noqa: BLE001
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE

    agent = RazeAgent(raze=Raze(backend=backend), scope=scope, run_analyzers=not args.no_analyzers)
    try:
        report = run_engagement(findings, agent)
    except ScopeError as e:
        print(f"scope refused: {e}", file=sys.stderr)
        return EXIT_SCOPE
    except Exception as e:  # noqa: BLE001
        print(f"planning failed: {e}", file=sys.stderr)
        return EXIT_JUDGMENT

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return EXIT_OK

    print(f"engagement: {report.n_findings} findings in {report.total_ms:.1f}ms "
          f"({report.throughput:.0f}/s)  actions={report.action_counts}")
    if report.chains:
        print("attack chains:")
        for c in report.chains:
            print(f"  * [{c.kind}] {c.label} (prio {c.chain_priority:.0f}): {' -> '.join(c.steps)}")
    print(f"top {min(args.top, len(report.decisions))} by priority:")
    for d in report.top(args.top):
        print(f"  [{d.action:11s}] p={d.priority:5.1f}  {d.finding_title}")
    return EXIT_OK


def _cmd_topics(_args: argparse.Namespace) -> int:
    print("Implemented topics:")
    for topic, analyzers in ANALYZERS.items():
        names = ", ".join(type(a).__name__ for a in analyzers)
        print(f"  {topic:10s} {names}")
    if PROPOSED_TOPICS:
        print("\nProposed topics (declared, not implemented):")
        print("  " + ", ".join(PROPOSED_TOPICS))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="raze",
        description="Offensive-security agent built on Raze (System One model, Jev family).",
    )
    parser.add_argument("--version", action="version", version=f"Raze {__version__}")
    sub = parser.add_subparsers(dest="command")

    a = sub.add_parser("assess", help="Assess a finding (JSON file or '-' for stdin).")
    a.add_argument("finding", help="Path to finding JSON, or '-' for stdin.")
    a.add_argument("--scope", help="Path to scope JSON (enforces authorization boundary).")
    a.add_argument("--backend", choices=["echo", "anthropic"], default="echo")
    a.add_argument("--model", help="Model id for the anthropic backend (default claude-opus-5).")
    a.add_argument("--no-analyzers", action="store_true", help="Skip deterministic analyzers.")
    a.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable text.")
    a.set_defaults(func=_cmd_assess)

    d = sub.add_parser("decide", help="Fast chained decision (one combined model call).")
    d.add_argument("finding", help="Path to finding JSON, or '-' for stdin.")
    d.add_argument("--scope", help="Path to scope JSON (enforces authorization boundary).")
    d.add_argument("--backend", choices=["echo", "anthropic"], default="echo")
    d.add_argument("--model", help="Model id for the anthropic backend (default claude-opus-5).")
    d.add_argument("--no-analyzers", action="store_true", help="Skip deterministic analyzers.")
    d.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable text.")
    d.set_defaults(func=_cmd_decide)

    p = sub.add_parser("plan", help="Decide a whole engagement (JSON array) and rank a plan.")
    p.add_argument("findings", help="Path to a JSON array of findings (or dataset rows), '-' stdin.")
    p.add_argument("--scope", help="Path to scope JSON (enforces authorization boundary).")
    p.add_argument("--backend", choices=["echo", "anthropic"], default="echo")
    p.add_argument("--model", help="Model id for the anthropic backend (default claude-opus-5).")
    p.add_argument("--no-analyzers", action="store_true", help="Skip deterministic analyzers.")
    p.add_argument("--top", type=int, default=10, help="How many ranked decisions to print.")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable text.")
    p.set_defaults(func=_cmd_plan)

    t = sub.add_parser("topics", help="List implemented and proposed topics.")
    t.set_defaults(func=_cmd_topics)

    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_USAGE
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
