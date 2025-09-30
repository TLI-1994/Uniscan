"""Severity normalization helpers."""
from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def normalize(cls, value: str | None) -> "Severity":
        if not value:
            return cls.LOW
        key = value.strip().upper()
        try:
            return _LEGACY_MAP[key]
        except KeyError:
            return cls.LOW


_LEGACY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def normalize_severity(value: str | None) -> Severity:
    """Normalize a severity string to one of the canonical levels."""
    return Severity.normalize(value)
