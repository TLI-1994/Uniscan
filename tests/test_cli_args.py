import argparse
from pathlib import Path

import pytest

from usentinel.cli import CliOptions, build_parser, parse_args


def test_parser_defines_expected_arguments():
    parser = build_parser()
    options = {action.dest for action in parser._actions}

    for expected in {
        "target",
        "format",
        "ruleset",
        "output",
        "include_binaries",
        "skip_binaries",
        "engine",
        "version",
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
    args = parse_args(["/tmp/project", "--format", "raw"])

    assert isinstance(args, CliOptions)
    assert args.target == Path("/tmp/project")
    assert args.format == "raw"
    assert args.output is None
    assert args.include_binaries is True
    assert args.skip_binaries is False
    assert args.semgrep == "auto"


def test_parser_rejects_invalid_format():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["/tmp", "--format", "xml"])


def test_parse_args_accepts_output_path():
    args = parse_args(["/tmp", "--format", "html", "--output", "report.html"])

    assert args.format == "html"
    assert args.output == Path("report.html")


def test_parse_args_normalizes_json_alias():
    args = parse_args(["/tmp", "--format", "json"])

    assert args.format == "raw"


def test_version_flag_prints_version(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--version"])

    captured = capsys.readouterr()
    assert "usentinel" in captured.out
def test_engine_flag_can_select_semgrep():
    args = parse_args(["/tmp", "--engine", "semgrep"])
    assert args.semgrep == "semgrep"


def test_skip_binaries_flag_disables_inclusion():
    args = parse_args(["/tmp", "--skip-binaries"])
    assert args.include_binaries is False
    assert args.skip_binaries is True
