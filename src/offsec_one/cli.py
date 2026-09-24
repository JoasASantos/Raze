"""Minimal CLI entrypoint for OffSec One."""

from __future__ import annotations

import argparse

from raze import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="offsec-one",
        description="Offensive-security agent built on Raze (System One model, Jev family).",
    )
    parser.add_argument("--version", action="version", version=f"OffSec One (raze {__version__})")
    parser.parse_args(argv)
    print("OffSec One scaffold. See examples/triage_finding.py and docs/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
