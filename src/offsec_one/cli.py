"""OffSec One CLI.

Commands:
  offsec-one assess FINDING [--scope S] [--backend echo|anthropic] [--model M] [--json]
  offsec-one topics
  offsec-one --version

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

from offsec_one.agent import Assessment, Finding, OffSecOne
from offsec_one.authz import Scope, ScopeError
from offsec_one.topics import ANALYZERS, PROPOSED_TOPICS
from raze import Raze, __version__

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

    agent = OffSecOne(raze=Raze(backend=backend), scope=scope, run_analyzers=not args.no_analyzers)

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
        prog="offsec-one",
        description="Offensive-security agent built on Raze (System One model, Jev family).",
    )
    parser.add_argument("--version", action="version", version=f"OffSec One (raze {__version__})")
    sub = parser.add_subparsers(dest="command")

    a = sub.add_parser("assess", help="Assess a finding (JSON file or '-' for stdin).")
    a.add_argument("finding", help="Path to finding JSON, or '-' for stdin.")
    a.add_argument("--scope", help="Path to scope JSON (enforces authorization boundary).")
    a.add_argument("--backend", choices=["echo", "anthropic"], default="echo")
    a.add_argument("--model", help="Model id for the anthropic backend (default claude-opus-5).")
    a.add_argument("--no-analyzers", action="store_true", help="Skip deterministic analyzers.")
    a.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable text.")
    a.set_defaults(func=_cmd_assess)

    t = sub.add_parser("topics", help="List implemented and proposed topics.")
    t.set_defaults(func=_cmd_topics)

    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_USAGE
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
