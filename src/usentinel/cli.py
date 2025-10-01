"""Command-line interface parsing utilities for Usentinel."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from . import __version__


DEFAULT_FORMAT = "html"
VALID_FORMATS = {"html", "raw", "json"}


@dataclass(frozen=True)
class CliOptions:
    """Normalized CLI options returned by :func:`parse_args`."""

    target: Path
    format: str = DEFAULT_FORMAT
    output: Path | None = None
    ruleset: tuple[Path, ...] = ()
    include_binaries: bool = True
    skip_binaries: bool = False
    semgrep: str = "auto"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="usentinel",
        description="Audit Unity projects for suspicious code and native binaries.",
    )

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    parser.add_argument(
        "target",
        type=Path,
        help="Path to the Unity project to scan",
    )

    parser.add_argument(
        "--format",
        choices=sorted(VALID_FORMATS),
        default=DEFAULT_FORMAT,
        help="Output format (html or raw)",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write formatted output (used for html format)",
    )

    parser.add_argument(
        "--ruleset",
        action="append",
        type=Path,
        default=None,
        help="Additional rule YAML files to load",
    )

    binary_group = parser.add_mutually_exclusive_group()
    binary_group.add_argument(
        "--include-binaries",
        dest="include_binaries",
        action="store_true",
        help="Force scanning for native binaries (default is enabled)",
    )
    binary_group.add_argument(
        "--skip-binaries",
        dest="skip_binaries",
        action="store_true",
        help="Skip native binary detection",
    )
    parser.set_defaults(include_binaries=None, skip_binaries=False)

    parser.add_argument(
        "--engine",
        choices=["auto", "semgrep", "heuristic"],
        default="auto",
        help="Select analysis engine (default: auto)",
    )

    return parser


def parse_args(argv: Sequence[str]) -> CliOptions:
    parser = build_parser()
    namespace = parser.parse_args(list(argv))

    include_binaries_flag = namespace.include_binaries
    include_binaries = True if include_binaries_flag is None else bool(include_binaries_flag)
    skip_binaries = namespace.skip_binaries
    if skip_binaries:
        include_binaries = False

    ruleset_paths: Iterable[Path]
    if namespace.ruleset is None:
        ruleset_paths = ()
    else:
        ruleset_paths = tuple(namespace.ruleset)

    options = CliOptions(
        target=namespace.target,
        format=_normalize_format(namespace.format),
        output=namespace.output,
        ruleset=tuple(ruleset_paths),
        include_binaries=include_binaries,
        skip_binaries=skip_binaries,
        semgrep=namespace.engine,
    )

    return options


def _normalize_format(value: str) -> str:
    if value == "json":
        return "raw"
    return value
