from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .lockfiles import detect_lockfiles
from .severity import SEVERITY_CHOICES, Severity

OUTPUT_CHOICES: tuple[str, ...] = ("text", "json", "sarif")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dep-vuln-checker",
        description="Check project dependency manifests for known vulnerabilities.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="Check a project path for known vulnerabilities.")
    check.add_argument("path", help="Path to a project directory.")
    check.add_argument("--output", choices=OUTPUT_CHOICES, default="text")
    check.add_argument(
        "--min-severity",
        choices=SEVERITY_CHOICES,
        default="low",
        help="Minimum severity that causes a non-zero exit (default: low).",
    )
    return parser


def _emit(findings: list[dict], output: str) -> str:
    if output == "json":
        return json.dumps({"findings": findings}, indent=2)
    if output == "sarif":
        return json.dumps(
            {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": "dep-vuln-checker"}}, "results": findings}],
            },
            indent=2,
        )
    if not findings:
        return "No vulnerabilities found."
    return "\n".join(f"- {f}" for f in findings)


def run_check(path: Path, output: str, min_severity: Severity) -> int:
    if not path.is_dir():
        print(f"error: {path} is not a directory", file=sys.stderr)
        return 2

    lockfiles = detect_lockfiles(path)
    if not lockfiles:
        print(f"No recognized lockfile under {path}; nothing to check.")
        return 0

    findings: list[dict] = []
    print(_emit(findings, output))

    above_threshold = [f for f in findings if Severity.parse(f["severity"]) >= min_severity]
    return 1 if above_threshold else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "check":
        return run_check(Path(args.path), args.output, Severity.parse(args.min_severity))
    return 2


if __name__ == "__main__":
    sys.exit(main())
