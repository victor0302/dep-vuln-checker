from __future__ import annotations

import re
import sys
from pathlib import Path

from . import Dep

_SPEC_RE = re.compile(
    r"""
    ^\s*
    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)
    (?:\s*\[[^\]]*\])?
    (?:\s*(?:==|~=|>=|<=|>|<|!=)\s*(?P<version>[^\s;#]+))?
    """,
    re.VERBOSE,
)

_URL_MARKERS = ("git+", "hg+", "svn+", "bzr+", "http://", "https://", "file://")


def parse(path: Path, _seen: set[Path] | None = None) -> list[Dep]:
    seen = _seen if _seen is not None else set()
    resolved = path.resolve()
    if resolved in seen:
        return []
    seen.add(resolved)

    deps: list[Dep] = []
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue

        if line.startswith(("-r", "--requirement")):
            ref = line.split(None, 1)[1].strip() if " " in line else ""
            if ref:
                included = (path.parent / ref).resolve()
                if included.exists():
                    deps.extend(parse(included, seen))
            continue

        if line.startswith("-e") or any(m in line for m in _URL_MARKERS):
            print(f"warning: skipping unsupported install line: {line}", file=sys.stderr)
            continue

        if line.startswith("-"):
            continue

        match = _SPEC_RE.match(line)
        if match:
            deps.append((match.group("name"), match.group("version")))
    return deps
