from __future__ import annotations

from enum import IntEnum


class Severity(IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        return cls[value.upper()]


SEVERITY_CHOICES: tuple[str, ...] = tuple(s.name.lower() for s in Severity)
