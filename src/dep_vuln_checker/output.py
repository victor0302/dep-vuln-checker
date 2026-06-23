from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "unknown")

ANSI_BY_SEVERITY: dict[str, str] = {
    "critical": "\x1b[1;31m",  # bold red
    "high": "\x1b[31m",         # red
    "medium": "\x1b[33m",       # yellow
    "low": "\x1b[36m",          # cyan
    "unknown": "\x1b[2m",       # dim
}
ANSI_RESET = "\x1b[0m"


@dataclass(frozen=True)
class Finding:
    id: str
    package: str
    ecosystem: str
    version: str | None
    severity: str
    summary: str
    references: tuple[str, ...]


def _severity_rank(s: str) -> int:
    try:
        return SEVERITY_ORDER.index(s)
    except ValueError:
        return len(SEVERITY_ORDER)


def _to_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "package": f.package,
        "ecosystem": f.ecosystem,
        "version": f.version,
        "severity": f.severity,
        "summary": f.summary,
        "references": list(f.references),
    }


def render_text(findings: Iterable[Finding], *, color: bool = True) -> str:
    fs = list(findings)
    if not fs:
        return "No vulnerabilities found."

    grouped: dict[tuple[str, str, str | None], list[Finding]] = defaultdict(list)
    for f in fs:
        grouped[(f.ecosystem, f.package, f.version)].append(f)

    lines: list[str] = []
    for (ecosystem, package, version), bucket in sorted(grouped.items()):
        header = f"{ecosystem}/{package}" + (f"@{version}" if version else "")
        lines.append(header)
        bucket.sort(key=lambda f: (_severity_rank(f.severity), f.id))
        for f in bucket:
            sev = f.severity.upper().ljust(8)
            if color:
                sev = f"{ANSI_BY_SEVERITY.get(f.severity, '')}{sev}{ANSI_RESET}"
            lines.append(f"  {sev} {f.id}  {f.summary}")
        lines.append("")
    return "\n".join(lines).rstrip("\n")


def render_json(findings: Iterable[Finding]) -> str:
    fs = sorted(list(findings), key=lambda f: (f.ecosystem, f.package, f.id))
    return json.dumps({"findings": [_to_dict(f) for f in fs]}, indent=2)


def render_sarif(findings: Iterable[Finding]) -> str:
    fs = list(findings)
    rules_by_id: dict[str, dict] = {}
    results: list[dict] = []
    for f in fs:
        rules_by_id[f.id] = {
            "id": f.id,
            "shortDescription": {"text": f.summary or f.id},
            "helpUri": f.references[0] if f.references else None,
        }
        results.append({
            "ruleId": f.id,
            "level": _sarif_level(f.severity),
            "message": {
                "text": f"{f.ecosystem}/{f.package}"
                        + (f"@{f.version}" if f.version else "")
                        + (f": {f.summary}" if f.summary else "")
            },
        })
    rules = [
        {k: v for k, v in rule.items() if v is not None}
        for rule in rules_by_id.values()
    ]
    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "dep-vuln-checker",
                            "informationUri": "https://github.com/victor0302/dep-vuln-checker",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        },
        indent=2,
    )


def _sarif_level(severity: str) -> str:
    if severity in ("critical", "high"):
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
