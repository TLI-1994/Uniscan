import sys
from pathlib import Path

import pytest

from usentinel.cli import CliOptions
from usentinel.main import run_scan
from usentinel.rules import load_ruleset
from usentinel.scanner import ScanReport


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
        format="raw",
        ruleset=(),
        include_binaries=False,
        skip_binaries=True,
        semgrep=flag,
    )

    monkeypatch.setenv("USENTINEL_DISABLE_SEMGREP", "1")
    report = run_scan(options)
    assert isinstance(report, ScanReport)
    assert report.engine["name"] == expected
