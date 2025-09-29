"""Command-line interface parsing utilities for Uniscan."""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from . import __version__


DEFAULT_FORMAT = "text"
DEFAULT_VERBOSITY = "normal"
VALID_FORMATS = {"text", "json"}
VALID_VERBOSITY = {"quiet", "normal", "debug"}


@dataclass(frozen=True)
class CliOptions:
    """Normalized CLI options returned by :func:`parse_args`."""

    target: Path
    format: str = DEFAULT_FORMAT
    ruleset: tuple[Path, ...] = ()
    no_colors: bool = False
    include_binaries: bool = True
    skip_binaries: bool = False
    verbosity: str = DEFAULT_VERBOSITY
    semgrep: str = "auto"
    progress: bool = True
    pretty: bool = False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="uniscan",
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
        help="Output format (text or json)",
    )

    parser.add_argument(
        "--ruleset",
        action="append",
        type=Path,
        default=None,
        help="Additional rule YAML files to load",
    )

    parser.add_argument(
        "--no-colors",
        action="store_true",
        help="Disable ANSI colors in text output",
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
        "--verbosity",
        choices=sorted(VALID_VERBOSITY),
        default=DEFAULT_VERBOSITY,
        help="Adjust log verbosity",
    )

    parser.add_argument(
        "--engine",
        choices=["auto", "semgrep", "heuristic"],
        default="auto",
        help="Select analysis engine (default: auto)",
    )

    parser.add_argument(
        "--pretty",
        dest="pretty",
        action="store_true",
        help="Group findings by file and rule for easier reading",
    )
    parser.add_argument(
        "--no-pretty",
        dest="pretty",
        action="store_false",
        help="Disable grouped output (default)",
    )
    parser.set_defaults(pretty=False)

    parser.add_argument(
        "--progress",
        dest="progress",
        action="store_true",
        help="Show a live progress indicator during scanning",
    )
    parser.add_argument(
        "--no-progress",
        dest="progress",
        action="store_false",
        help="Disable the progress indicator",
    )
    parser.set_defaults(progress=True)

    parser.add_argument(
        "--quiet",
        action="store_const",
        const="quiet",
        dest="verbosity",
        help="Alias for --verbosity quiet",
    )
    parser.add_argument(
        "--debug",
        action="store_const",
        const="debug",
        dest="verbosity",
        help="Alias for --verbosity debug",
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
        format=namespace.format,
        ruleset=tuple(ruleset_paths),
        no_colors=namespace.no_colors,
        include_binaries=include_binaries,
        skip_binaries=skip_binaries,
        verbosity=namespace.verbosity,
        semgrep=namespace.engine,
        progress=namespace.progress,
        pretty=namespace.pretty,
    )

    return options
