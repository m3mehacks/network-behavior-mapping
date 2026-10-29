#!/usr/bin/env python3
"""Command line entry point for the network behaviour mapping pipeline."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from nbm.util import load_cases, log, setup_logging  # noqa: E402


def cmd_fetch(cases) -> None:
    from nbm.fetch import fetch_all

    fetch_all(cases)


def cmd_analyze(cases) -> None:
    from nbm.analyze import analyze_all

    analyze_all(cases)


def cmd_report(cases) -> None:
    from nbm.report import report_all

    report_all(cases)


def cmd_rules(cases) -> None:
    from nbm.rules import rules_all

    rules_all(cases)


COMMANDS = {
    "fetch": cmd_fetch,
    "analyze": cmd_analyze,
    "report": cmd_report,
    "rules": cmd_rules,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cli.py", description="Map malware network behaviour from packet captures."
    )
    parser.add_argument(
        "command",
        choices=[*COMMANDS, "all"],
        help="pipeline stage to run; 'all' runs fetch, analyze, report and rules in order",
    )
    parser.add_argument(
        "--case",
        action="append",
        dest="cases",
        metavar="ID",
        help="limit to one case id (repeatable); defaults to every case in config/cases.yaml",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    args = parser.parse_args(argv)

    setup_logging(args.verbose)
    cases = load_cases(args.cases)
    if not cases:
        log.error("no cases selected")
        return 1

    stages = list(COMMANDS) if args.command == "all" else [args.command]
    for stage in stages:
        log.info("=== %s ===", stage)
        COMMANDS[stage](cases)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
