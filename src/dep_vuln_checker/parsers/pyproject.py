from __future__ import annotations

import re
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from . import Dep

_SPEC_RE = re.compile(
    r"""
    ^\s*
    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)
    (?:\s*\[[^\]]*\])?
    (?:\s*(?:==|~=|>=|<=|>|<|!=)\s*(?P<version>[^\s;#,]+))?
    """,
    re.VERBOSE,
)


def _parse_requirement(spec: str) -> Dep | None:
    match = _SPEC_RE.match(spec.split(";", 1)[0])
    if not match:
        return None
    return match.group("name"), match.group("version")


def parse(path: Path) -> list[Dep]:
    data = tomllib.loads(path.read_text())
    project = data.get("project", {})
    raw_specs: list[str] = list(project.get("dependencies", []))
    for group in project.get("optional-dependencies", {}).values():
        raw_specs.extend(group)

    deps: list[Dep] = []
    for spec in raw_specs:
        parsed = _parse_requirement(spec)
        if parsed:
            deps.append(parsed)
    return deps
