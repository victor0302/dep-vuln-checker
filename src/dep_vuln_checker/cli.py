from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .lockfiles import detect_lockfiles
from .output import Finding, render_json, render_sarif, render_text
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
    check.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in text output.",
    )
    return parser


def _emit(findings: list[Finding], output: str, *, color: bool) -> str:
    if output == "json":
        return render_json(findings)
    if output == "sarif":
        return render_sarif(findings)
    return render_text(findings, color=color)


def run_check(
    path: Path,
    output: str,
    min_severity: Severity,
    *,
    color: bool = True,
) -> int:
    if not path.is_dir():
        print(f"error: {path} is not a directory", file=sys.stderr)
        return 2

    lockfiles = detect_lockfiles(path)
    if not lockfiles:
        print(f"No recognized lockfile under {path}; nothing to check.")
        return 0

    findings: list[Finding] = []
    print(_emit(findings, output, color=color))

    above_threshold = [f for f in findings if _severity_of(f) >= min_severity]
    return 1 if above_threshold else 0


def _severity_of(finding: Finding) -> Severity:
    try:
        return Severity.parse(finding.severity)
    except KeyError:
        return Severity.NONE


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "check":
        return run_check(
            Path(args.path),
            args.output,
            Severity.parse(args.min_severity),
            color=not args.no_color,
        )
    return 2


if __name__ == "__main__":
    sys.exit(main())
