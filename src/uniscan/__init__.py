"""Compatibility shim for the deprecated `uniscan` package."""
from __future__ import annotations

import warnings

from usentinel import *  # noqa: F401,F403

warnings.warn(
    "The `uniscan` package has been renamed to `usentinel`. Please update your "
    "dependencies to use `usentinel` directly.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [name for name in globals() if not name.startswith("_")]
