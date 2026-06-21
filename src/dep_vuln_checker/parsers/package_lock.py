from __future__ import annotations

import json
from pathlib import Path

from . import Dep


def parse(path: Path) -> list[Dep]:
    data = json.loads(path.read_text())
    version = data.get("lockfileVersion")
    if version not in (2, 3):
        raise ValueError(f"unsupported lockfileVersion {version!r}; expected 2 or 3")

    deps: list[Dep] = []
    seen: set[tuple[str, str]] = set()
    for pkg_path, info in (data.get("packages") or {}).items():
        if not pkg_path:
            continue
        name = info.get("name") or _name_from_path(pkg_path)
        version_str = info.get("version")
        if not name or not version_str:
            continue
        key = (name, version_str)
        if key in seen:
            continue
        seen.add(key)
        deps.append((name, version_str))
    return deps


def _name_from_path(pkg_path: str) -> str | None:
    parts = pkg_path.split("node_modules/")
    if len(parts) < 2:
        return None
    return parts[-1]
