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


_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
)

ORDERED_SEVERITIES = tuple(level.value for level in _ORDER)

_ORDER_INDEX = {level: index for index, level in enumerate(_ORDER)}


def severity_sort_key(value: str | Severity) -> int:
    """Return the ordering index for a severity value."""
    if isinstance(value, Severity):
        return _ORDER_INDEX.get(value, len(_ORDER))
    try:
        level = Severity(value.lower())
    except ValueError:
        return len(_ORDER)
    return _ORDER_INDEX.get(level, len(_ORDER))
