"""Uniscan package exports."""

from importlib import metadata

try:  # pragma: no cover - metadata lookup depends on installation context
    __version__ = metadata.version("uniscan")
except metadata.PackageNotFoundError:  # pragma: no cover - source tree fallback
    __version__ = "0.0.dev0"

from .main import main

__all__ = ["main", "__version__"]
