"""Core scanning engine for Usentinel."""
from __future__ import annotations

import os
import re
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence

from .binaries import BinaryClassifier, BinaryFinding
from .rules import Rule, Ruleset
from .semgrep_runner import SemgrepMatch, SemgrepRunner, SemgrepUnavailable
from .severity import Severity, normalize_severity


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    path: Path
    line: int | None = None
    snippet: str | None = None


@dataclass(frozen=True)
class ScanReport:
    target: Path
    findings: list[Finding]
    binaries: list[BinaryFinding]
    summary: dict
    engine: dict[str, object]


@dataclass(frozen=True)
class ScannerConfig:
    include_binaries: bool = True
    skip_binaries: bool = False
    allowed_dirs: tuple[str, ...] = ("Assets", "Packages", "ProjectSettings")
    use_semgrep: bool | None = None  # None = auto detect
    max_workers: int | None = None

    def binaries_enabled(self) -> bool:
        if self.skip_binaries:
            return False
        return self.include_binaries


class Scanner:
    """Walk Unity projects and evaluate rules and binary heuristics."""

    def __init__(
        self,
        *,
        ruleset: Ruleset,
        semgrep_sources: Sequence[Path] | None,
        binary_classifier: BinaryClassifier,
        config: ScannerConfig | None = None,
    ) -> None:
        self.ruleset = ruleset
        self._semgrep_sources = tuple(Path(p) for p in semgrep_sources or ())
        self.binary_classifier = binary_classifier
        self.config = config or ScannerConfig()
        cpu_workers = os.cpu_count() or 1
        self._max_workers = max(1, min(32, self.config.max_workers or cpu_workers))
        self._matchers = _build_matchers(ruleset)
        self._rule_index = {rule.id: rule for rule in ruleset.rules}
        self._semgrep_runner = self._maybe_init_semgrep_runner()

    def scan(self, target: Path) -> ScanReport:
        project_root = Path(target).resolve()
        if not project_root.exists():
            raise FileNotFoundError(f"Target {project_root} not found")
        if not project_root.is_dir():
            raise NotADirectoryError(f"Target {project_root} is not a directory")

        csharp_files: list[Path] = []
        other_files: list[Path] = []
        for file_path in self._iter_candidate_files(project_root):
            if file_path.suffix.lower() == ".cs":
                csharp_files.append(file_path)
            else:
                other_files.append(file_path)

        findings: list[Finding] = []
        binaries: list[BinaryFinding] = []

        total_progress = len(csharp_files)
        if self.config.binaries_enabled():
            total_progress += len(other_files)
        progress = _ProgressPrinter(total_progress)

        semgrep_phase = self._semgrep_runner is not None and csharp_files
        if semgrep_phase:
            progress.start_semgrep_timer()
        else:
            progress.start()

        semgrep_used = False
        semgrep_error: str | None = None
        if semgrep_phase:
            try:
                progress.start_spinner("Running Semgrep")
                relative_targets = _relativize_paths(project_root, csharp_files)
                matches = self._semgrep_runner.run(project_root, relative_targets)
                progress.stop_spinner()
                findings.extend(self._convert_semgrep_matches(project_root, matches))
                semgrep_used = True
                progress.increment(len(csharp_files))
            except SemgrepUnavailable as exc:
                progress.stop_spinner()
                semgrep_error = str(exc) or "semgrep unavailable"
                if self.config.use_semgrep:
                    progress.finish()
                    raise

        if not semgrep_used:
            for path in csharp_files:
                file_findings = self._scan_csharp(path)
                findings.extend(file_findings)
                progress.increment()

        if self.config.binaries_enabled():
            for file_path in other_files:
                binary = self.binary_classifier.classify(file_path)
                if binary:
                    binaries.append(binary)
                progress.increment()

        summary = _summarize(findings, binaries)
        engine_info: dict[str, object] = {"name": "semgrep" if semgrep_used else "heuristic"}
        if semgrep_used and self._semgrep_runner and self._semgrep_runner.version:
            engine_info["version"] = self._semgrep_runner.version
        if not semgrep_used and semgrep_error:
            engine_info["fallback_reason"] = semgrep_error

        progress.finish()

        return ScanReport(
            target=project_root,
            findings=findings,
            binaries=binaries,
            summary=summary,
            engine=engine_info,
        )

    def _iter_candidate_files(self, root: Path) -> Iterator[Path]:
        allow = {name.lower() for name in self.config.allowed_dirs}
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            relative = path.relative_to(root)
            try:
                top_level = relative.parts[0].lower()
            except IndexError:
                top_level = ""
            if allow and top_level not in allow:
                continue
            yield path

    def _scan_csharp(self, path: Path) -> list[Finding]:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        findings: list[Finding] = []
        lines = source.splitlines()

        for matcher in self._matchers:
            for line_no, snippet in matcher.find_matches(lines):
                findings.append(
                    Finding(
                        rule_id=_format_rule_id(matcher.rule),
                        severity=matcher.rule.severity,
                        message=matcher.rule.message,
                        path=path,
                        line=line_no,
                        snippet=snippet,
                    )
                )

        return findings

    def _convert_semgrep_matches(self, project_root: Path, matches: Sequence[SemgrepMatch]) -> list[Finding]:
        findings: list[Finding] = []
        for match in matches:
            rule = self._resolve_rule(match.rule_id)
            message = rule.message if rule else (match.message or match.rule_id)
            if rule:
                severity = rule.severity
            else:
                severity = normalize_severity(match.severity).value
            path = match.path
            if not path.is_absolute():
                path = (project_root / path).resolve()
            findings.append(
                Finding(
                    rule_id=_format_rule_id(rule) if rule else _normalize_semgrep_id(match.rule_id),
                    severity=severity,
                    message=message,
                    path=path,
                    line=match.line,
                    snippet=match.snippet.strip() if match.snippet else None,
                )
            )
        return findings

    def _resolve_rule(self, check_id: str) -> Rule | None:
        rule = self._rule_index.get(check_id)
        if rule:
            return rule
        normalized = _normalize_semgrep_id(check_id)
        if "." in normalized:
            _, suffix = normalized.split(".", 1)
            rule = self._rule_index.get(suffix)
            if rule:
                return rule
        return _lookup_rule_by_suffix(self.ruleset.rules, check_id)

    def _maybe_init_semgrep_runner(self) -> SemgrepRunner | None:
        if self.config.use_semgrep is False:
            return None
        if os.environ.get("USENTINEL_DISABLE_SEMGREP") or os.environ.get("UNISCAN_DISABLE_SEMGREP"):
            return None
        if not self._semgrep_sources:
            return None
        return SemgrepRunner.maybe_create(self._semgrep_sources, jobs=self._max_workers)


class _RuleMatcher:
    def __init__(self, rule: Rule, patterns: Sequence[_PatternChecker]) -> None:
        self.rule = rule
        self.patterns = list(patterns)

    def find_matches(self, lines: Sequence[str]) -> list[tuple[int, str]]:
        matches: list[tuple[int, str]] = []
        for idx, line in enumerate(lines, start=1):
            for pattern in self.patterns:
                if pattern.matches(line):
                    matches.append((idx, line.strip()))
                    break
        return matches


class _PatternChecker:
    def matches(self, line: str) -> bool:  # pragma: no cover - interface marker
        raise NotImplementedError


class _SubstringChecker(_PatternChecker):
    def __init__(self, needle: str) -> None:
        self.needle = needle

    def matches(self, line: str) -> bool:
        return self.needle in line


class _RegexChecker(_PatternChecker):
    def __init__(self, pattern: str) -> None:
        self.pattern = re.compile(pattern)

    def matches(self, line: str) -> bool:
        return bool(self.pattern.search(line))


class _MultiSubstringChecker(_PatternChecker):
    def __init__(self, needles: Sequence[str]) -> None:
        self.needles = [needle for needle in needles if needle]

    def matches(self, line: str) -> bool:
        return all(needle in line for needle in self.needles)


def _build_matchers(ruleset: Ruleset) -> list[_RuleMatcher]:
    matchers: list[_RuleMatcher] = []
    for rule in ruleset.for_language("csharp"):
        patterns: list[_PatternChecker] = []
        raw = rule.raw
        pattern_value = raw.get("pattern")
        if isinstance(pattern_value, str):
            patterns.extend(_build_substring_checkers(pattern_value))

        pattern_regex = raw.get("pattern-regex")
        if isinstance(pattern_regex, str):
            patterns.append(_RegexChecker(pattern_regex))

        pattern_either = raw.get("pattern-either")
        if isinstance(pattern_either, Iterable):
            for entry in pattern_either:
                if not isinstance(entry, dict):
                    continue
                if "pattern" in entry and isinstance(entry["pattern"], str):
                    patterns.extend(_build_substring_checkers(entry["pattern"]))
                if "pattern-regex" in entry and isinstance(entry["pattern-regex"], str):
                    patterns.append(_RegexChecker(entry["pattern-regex"]))

        if patterns:
            matchers.append(_RuleMatcher(rule, patterns))

    return matchers


def _build_substring_checkers(pattern: str) -> list[_PatternChecker]:
    normalized = pattern.replace("...", "").strip()
    if not normalized:
        return []

    call_form = normalized.split("(", 1)[0].strip()

    if "Convert.FromBase64String" in normalized:
        needles: list[str] = []
        if call_form:
            parts = call_form.split(".")
            if len(parts) >= 2:
                needles.append(".".join(parts[-2:]))
            else:
                needles.append(call_form)
        needles.append("Convert.FromBase64String")
        return [_MultiSubstringChecker(needles)]

    checkers: list[_PatternChecker] = []
    checkers.append(_SubstringChecker(normalized))

    if call_form and call_form != normalized:
        checkers.append(_SubstringChecker(call_form))

    parts = call_form.split(".") if call_form else normalized.split(".")
    if parts and len(parts) >= 2:
        last_two = ".".join(parts[-2:])
        if last_two not in {normalized, call_form}:
            checkers.append(_SubstringChecker(last_two))

    return checkers


def _summarize(findings: Sequence[Finding], binaries: Sequence[BinaryFinding]) -> dict:
    severity_counts: dict[str, int] = {
        "total": len(findings),
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 0,
        Severity.MEDIUM.value: 0,
        Severity.LOW.value: 0,
    }
    for finding in findings:
        severity = finding.severity.lower()
        severity_counts.setdefault(severity, 0)
        severity_counts[severity] += 1

    return {
        "findings": severity_counts,
        "binaries": len(binaries),
    }


def _relativize_paths(project_root: Path, files: Sequence[Path]) -> list[Path]:
    relative: list[Path] = []
    for path in files:
        try:
            relative.append(path.relative_to(project_root))
        except ValueError:
            relative.append(path)
    return relative


class _ProgressPrinter:
    _SPINNER = "|/-\\"

    def __init__(self, total: int) -> None:
        tty = sys.stdout.isatty()
        self.enabled = total > 0 and tty
        self.total = max(total, 1)
        self.current = 0
        self._last = ""
        self._spinning = False
        self._spin_index = 0
        self._spin_label = ""
        self._spinner_thread: threading.Thread | None = None
        self._show_semgrep_time = False
        self._start_time: float | None = None

    def start(self) -> None:
        if not self.enabled:
            return
        self._write(self._progress_line())

    def start_semgrep_timer(self) -> None:
        if not self.enabled:
            return
        self._show_semgrep_time = True
        self._start_time = time.time()
        self._write(self._semgrep_line())

    def start_spinner(self, label: str) -> None:
        if not self.enabled:
            return
        if self._spinning:
            return
        self._spinning = True
        self._spin_index = 0
        self._spin_label = label
        self._write(self._spinner_line())
        self._spinner_thread = threading.Thread(target=self._spin_loop, daemon=True)
        self._spinner_thread.start()

    def stop_spinner(self) -> None:
        if not self.enabled or not self._spinning:
            return
        self._spinning = False
        if self._spinner_thread:
            self._spinner_thread.join(timeout=0.2)
            self._spinner_thread = None
        if self._show_semgrep_time:
            self._show_semgrep_time = False
            self._start_time = None
        self._write(self._progress_line())

    def increment(self, step: int = 1) -> None:
        if not self.enabled:
            return
        if self._spinning:
            return
        if step <= 0:
            return
        self.current = min(self.total, self.current + step)
        self._write(self._progress_line())

    def finish(self) -> None:
        if not self.enabled:
            return
        if self._spinning:
            self.stop_spinner()
        self._show_semgrep_time = False
        self._start_time = None
        sys.stderr.write("\n")
        sys.stderr.flush()

    def _progress_line(self) -> str:
        percent = int(self.current / self.total * 100)
        return f"Scanning... {self.current}/{self.total} ({percent:3d}%)"

    def _spinner_line(self) -> str:
        if self._show_semgrep_time and self._start_time:
            elapsed = time.time() - self._start_time
            return f"{self._SPINNER[self._spin_index]} {self._spin_label} ({elapsed:.1f}s)"
        return f"{self._SPINNER[self._spin_index]} {self._spin_label}"

    def _spin_loop(self) -> None:
        while self._spinning:
            time.sleep(0.1)
            self._spin_index = (self._spin_index + 1) % len(self._SPINNER)
            self._write(self._spinner_line())

    def _write(self, text: str) -> None:
        if not self.enabled:
            return
        if self._show_semgrep_time and not self._spinning and self._start_time:
            text = self._semgrep_line()
        padding = max(len(self._last) - len(text), 0)
        sys.stderr.write("\r" + text + " " * padding)
        sys.stderr.flush()
        self._last = text

    def _semgrep_line(self) -> str:
        if not self._start_time:
            return "Running Semgrep"
        elapsed = time.time() - self._start_time
        return f"Running Semgrep ({elapsed:.1f}s)"


def _normalize_semgrep_id(check_id: str) -> str:
    for marker in (".core.", ".private."):
        if marker in check_id:
            suffix = check_id.split(marker, 1)[1]
            return marker.strip(".") + "." + suffix
    return check_id.split(".")[-1]


def _lookup_rule_by_suffix(rules: Sequence[Rule], check_id: str) -> Rule | None:
    for rule in rules:
        if check_id.endswith(rule.id):
            return rule
    return None


def _format_rule_id(rule: Rule | None) -> str:
    if rule is None:
        return "unknown"
    prefix = rule.tag
    if prefix == "external":
        return rule.id
    return f"{prefix}.{rule.id}"


def _resolve_rule(self, check_id: str) -> Rule | None:
    rule = self._rule_index.get(check_id)
    if rule:
        return rule
    normalized = _normalize_semgrep_id(check_id)
    if "." in normalized:
        _, suffix = normalized.split(".", 1)
        rule = self._rule_index.get(suffix)
        if rule:
            return rule
    return _lookup_rule_by_suffix(self.ruleset.rules, check_id)
