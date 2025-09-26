"""Core scanning engine for Uniscan."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, List, Sequence

from .binaries import BinaryClassifier, BinaryFinding
from .rules import Rule, Ruleset
from .semgrep_runner import SemgrepMatch, SemgrepRunner, SemgrepUnavailable


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

        semgrep_used = False
        semgrep_error: str | None = None
        if self._semgrep_runner and csharp_files:
            try:
                relative_targets = _relativize_paths(project_root, csharp_files)
                matches = self._semgrep_runner.run(project_root, relative_targets)
                findings.extend(self._convert_semgrep_matches(project_root, matches))
                semgrep_used = True
            except SemgrepUnavailable as exc:
                semgrep_error = str(exc) or "semgrep unavailable"
                if self.config.use_semgrep:
                    raise

        if not semgrep_used:
            findings.extend(self._heuristic_scan(csharp_files))

        if self.config.binaries_enabled():
            for file_path in other_files:
                binary = self.binary_classifier.classify(file_path)
                if binary:
                    binaries.append(binary)

        summary = _summarize(findings, binaries)
        engine_info: dict[str, object] = {"name": "semgrep" if semgrep_used else "heuristic"}
        if not semgrep_used and semgrep_error:
            engine_info["fallback_reason"] = semgrep_error

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

    def _heuristic_scan(self, files: Sequence[Path]) -> list[Finding]:
        findings: list[Finding] = []
        for path in files:
            findings.extend(self._scan_csharp(path))
        return findings

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
                    rule_id=_format_rule_id(matcher.rule),
                    severity=matcher.rule.severity.lower(),
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
            severity = (rule.severity if rule else (match.severity or "WARNING")).lower()
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
        if os.environ.get("UNISCAN_DISABLE_SEMGREP"):
            return None
        return SemgrepRunner.maybe_create(self.ruleset.sources)


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


def _relativize_paths(project_root: Path, files: Sequence[Path]) -> list[Path]:
    relative: list[Path] = []
    for path in files:
        try:
            relative.append(path.relative_to(project_root))
        except ValueError:
            relative.append(path)
    return relative


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
