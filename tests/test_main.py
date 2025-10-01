from __future__ import annotations

import io
from datetime import datetime
from pathlib import Path

import pytest

from usentinel.main import _generate_report_filename, _slugify


def test_slugify_basic():
    assert _slugify("My Project") == "my-project"


def test_slugify_fallback_when_empty():
    assert _slugify("   ") == "project"
    assert _slugify("@@@") == "project"


class DummyReport:
    def __init__(self, name: str, findings_count: int = 0) -> None:
        self.target = Path(f"/fake/{name}")
        self.findings = [object()] * findings_count
        self.summary = {"findings": {"total": findings_count}}


def test_generate_report_filename_includes_project_timestamp_and_hash(monkeypatch):
    report = DummyReport("My Project", findings_count=2)
    when = datetime(2024, 5, 18, 17, 24, 55)

    filename = _generate_report_filename(report, when)

    assert filename.startswith("usentinel-report-my-project-20240518-172455-")
    assert filename.endswith(".html")
    digest_part = filename.split("-")[-1].split(".")[0]
    assert len(digest_part) == 8


def test_progress_printer_disables_when_not_tty(monkeypatch):
    output_buffer = io.StringIO()

    class FakeStdout:
        def __init__(self) -> None:
            self.buffer = output_buffer

        def write(self, text: str) -> int:
            self.buffer.write(text)
            return len(text)

        def flush(self) -> None:
            pass

        def isatty(self) -> bool:
            return False

    fake_stdout = FakeStdout()
    monkeypatch.setattr("sys.stdout", fake_stdout)

    from usentinel.scanner import _ProgressPrinter

    progress = _ProgressPrinter(total=10)
    progress.start()
    progress.increment()
    progress.finish()

    assert output_buffer.getvalue() == ""
