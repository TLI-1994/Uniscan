import sys
from pathlib import Path

import pytest

from uniscan.cli import CliOptions
from uniscan.main import run_scan
from uniscan.rules import load_ruleset
from uniscan.scanner import ScanReport


@pytest.mark.parametrize(
    "flag, expected",
    [
        ("heuristic", "heuristic"),
        ("semgrep", "heuristic"),  # falls back because Semgrep disabled in tests
        ("auto", "heuristic"),
    ],
)
def test_run_scan_respects_engine_flag(unity_project, monkeypatch, flag, expected):
    project = unity_project("clean_project")

    # Build options mimicking CLI parsing
    options = CliOptions(
        target=project,
        format="json",
        ruleset=(),
        no_colors=True,
        include_binaries=False,
        skip_binaries=True,
        verbosity="normal",
        semgrep=flag,
        progress=True,
    )

    monkeypatch.setenv("UNISCAN_DISABLE_SEMGREP", "1")
    report = run_scan(options)
    assert isinstance(report, ScanReport)
    assert report.engine["name"] == expected
