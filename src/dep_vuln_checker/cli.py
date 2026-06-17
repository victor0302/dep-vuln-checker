import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dep-vuln-checker",
        description="Check project dependency manifests for known vulnerabilities.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Path to a project directory.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    print(f"dep-vuln-checker: scaffolding only; nothing to scan yet at {args.path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
