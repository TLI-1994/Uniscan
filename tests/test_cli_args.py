import argparse
from pathlib import Path

import pytest

from uniscan.cli import CliOptions, build_parser, parse_args


def test_parser_defines_expected_arguments():
    parser = build_parser()
    options = {action.dest for action in parser._actions}

    for expected in {
        "target",
        "format",
        "ruleset",
        "no_colors",
        "include_binaries",
        "skip_binaries",
        "verbosity",
        "engine",
        "progress",
    }:
        assert expected in options


def test_parse_args_requires_target():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_mutually_exclusive_binary_flags():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["/tmp", "--include-binaries", "--skip-binaries"])


def test_parse_args_returns_cli_options():
    args = parse_args(["/tmp/project", "--format", "json", "--no-colors"])

    assert isinstance(args, CliOptions)
    assert args.target == Path("/tmp/project")
    assert args.format == "json"
    assert args.no_colors is True
    assert args.include_binaries is True
    assert args.skip_binaries is False
    assert args.verbosity == "normal"
    assert args.semgrep == "auto"
    assert args.progress is True
    assert args.pretty is False


def test_parser_rejects_invalid_format():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["/tmp", "--format", "xml"])


@pytest.mark.parametrize("flag", ["--quiet", "--debug"])
def test_shorthand_verbosity_flags(flag):
    args = parse_args(["/tmp", flag])
    expected = "quiet" if flag == "--quiet" else "debug"
    assert args.verbosity == expected


def test_engine_flag_can_select_semgrep():
    args = parse_args(["/tmp", "--engine", "semgrep"])
    assert args.semgrep == "semgrep"


def test_progress_flag_enables_progress():
    args = parse_args(["/tmp", "--progress"])
    assert args.progress is True


def test_skip_binaries_flag_disables_inclusion():
    args = parse_args(["/tmp", "--skip-binaries"])
    assert args.include_binaries is False
    assert args.skip_binaries is True


def test_pretty_flag_enables_grouped_output():
    args = parse_args(["/tmp", "--pretty"])
    assert args.pretty is True
