from __future__ import annotations

from pathlib import Path

KNOWN_LOCKFILES: tuple[str, ...] = (
    "requirements.txt",
    "pyproject.toml",
    "package-lock.json",
)


def detect_lockfiles(root: Path) -> list[Path]:
    return sorted(p for name in KNOWN_LOCKFILES for p in root.rglob(name))
