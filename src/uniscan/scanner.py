"""Core scanning engine for Uniscan."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, List, Sequence

from .binaries import BinaryClassifier, BinaryFinding
from .rules import Rule, Ruleset


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


@dataclass(frozen=True)
class ScannerConfig:
    include_binaries: bool = True
    skip_binaries: bool = False
    allowed_dirs: tuple[str, ...] = ("Assets", "Packages", "ProjectSettings")

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
        binary_classifier: BinaryClassifier,
        config: ScannerConfig | None = None,
    ) -> None:
        self.ruleset = ruleset
        self.binary_classifier = binary_classifier
        self.config = config or ScannerConfig()
        self._matchers = _build_matchers(ruleset)

    def scan(self, target: Path) -> ScanReport:
        project_root = Path(target).resolve()
        if not project_root.exists():
            raise FileNotFoundError(f"Target {project_root} not found")
        if not project_root.is_dir():
            raise NotADirectoryError(f"Target {project_root} is not a directory")

        findings: list[Finding] = []
        binaries: list[BinaryFinding] = []

        for file_path in self._iter_candidate_files(project_root):
            if file_path.suffix.lower() == ".cs":
                findings.extend(self._scan_csharp(file_path))
            elif self.config.binaries_enabled():
                binary = self.binary_classifier.classify(file_path)
                if binary:
                    binaries.append(binary)

        summary = _summarize(findings, binaries)
        return ScanReport(target=project_root, findings=findings, binaries=binaries, summary=summary)

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
            match_line = matcher.find_match(lines)
            if match_line is None:
                continue
            line_no, snippet = match_line
            findings.append(
                Finding(
                    rule_id=matcher.rule.id,
                    severity=matcher.rule.severity.lower(),
                    message=matcher.rule.message,
                    path=path,
                    line=line_no,
                    snippet=snippet,
                )
            )

        return findings


class _RuleMatcher:
    def __init__(self, rule: Rule, patterns: Sequence[_PatternChecker]) -> None:
        self.rule = rule
        self.patterns = list(patterns)

    def find_match(self, lines: Sequence[str]) -> tuple[int, str] | None:
        for idx, line in enumerate(lines, start=1):
            for pattern in self.patterns:
                if pattern.matches(line):
                    return idx, line.strip()
        return None


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
        "info": 0,
        "warning": 0,
        "error": 0,
        "critical": 0,
    }
    for finding in findings:
        severity = finding.severity.lower()
        severity_counts.setdefault(severity, 0)
        severity_counts[severity] += 1

    return {
        "findings": severity_counts,
        "binaries": len(binaries),
    }
