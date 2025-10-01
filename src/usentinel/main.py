from __future__ import annotations

import json
import sys
import re
from datetime import datetime
import hashlib
from pathlib import Path
from collections import defaultdict
from typing import Any, Sequence

from importlib import resources as importlib_resources
from jinja2 import Environment, select_autoescape

from .binaries import BinaryClassifier
from .cli import CliOptions, parse_args
from .rules import RuleLoadError, load_ruleset, load_semgrep_sources
from .scanner import Finding, ScanReport, Scanner, ScannerConfig
from .severity import ORDERED_SEVERITIES, severity_sort_key

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_FS_ERROR = 3
EXIT_RULE_ERROR = 4
EXIT_FAILURE = 1

_RESET = "\x1b[0m"
_COLORS = {
    "low": "\x1b[34m",      # blue
    "medium": "\x1b[33m",   # yellow
    "high": "\x1b[31m",     # red
    "critical": "\x1b[35m",  # magenta
}

def _load_html_template() -> str:
    template_resource = importlib_resources.files("usentinel.templates") / "report.html"
    return template_resource.read_text(encoding="utf-8")

_HTML_ENV = Environment(autoescape=select_autoescape(["html", "xml"]))
_HTML_TEMPLATE_OBJ = _HTML_ENV.from_string(_load_html_template())


def _generate_report_filename(report: ScanReport, when: datetime) -> str:
    project_name = _slugify(report.target.name or "project")
    timestamp = when.strftime("%Y%m%d-%H%M%S")
    digest_source = f"{report.target}|{len(report.findings)}|{report.summary.get('findings', {}).get('total', len(report.findings))}|{when.timestamp()}"
    digest = hashlib.sha256(digest_source.encode("utf-8")).hexdigest()[:8]
    return f"usentinel-report-{project_name}-{timestamp}-{digest}.html"


def _slugify(value: str) -> str:
    normalized = value.strip().lower()
    normalized = re.sub(r"[^a-z0-9]+", "-", normalized)
    normalized = normalized.strip("-")
    return normalized or "project"

def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    try:
        options = parse_args(argv)
    except SystemExit as exc:
        # argparse already emitted a message; propagate its exit code
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE

    try:
        report = run_scan(options)
    except FileNotFoundError as exc:
        _print_error(str(exc))
        return EXIT_FS_ERROR
    except NotADirectoryError as exc:
        _print_error(str(exc))
        return EXIT_FS_ERROR
    except RuleLoadError as exc:
        _print_error(str(exc))
        return EXIT_RULE_ERROR
    except Exception as exc:  # pragma: no cover - defensive final guard
        _print_error(f"Unexpected error: {exc}")
        return EXIT_FAILURE

    if options.format == "json":
        print(_report_to_json(report, options))
    elif options.format == "html":
        output_path = _write_html_report(report, options)
        print(f"HTML report written to {output_path}")
    else:
        print(_report_to_text(report, options))

    return EXIT_OK


def run_scan(options: CliOptions) -> ScanReport:
    extra_rule_files = options.ruleset if options.ruleset else None
    ruleset = load_ruleset(include_private=True, extra_rule_files=extra_rule_files)
    semgrep_sources = load_semgrep_sources(include_private=True, extra_rule_files=extra_rule_files)

    classifier = BinaryClassifier()
    should_include_binaries = options.include_binaries or not options.skip_binaries
    config = ScannerConfig(
        include_binaries=should_include_binaries,
        skip_binaries=options.skip_binaries,
        use_semgrep=_map_engine_choice(options.semgrep),
        show_progress=options.progress,
    )

    scanner = Scanner(
        ruleset=ruleset,
        semgrep_sources=semgrep_sources,
        binary_classifier=classifier,
        config=config,
    )
    return scanner.scan(options.target)


def _map_engine_choice(choice: str) -> bool | None:
    if choice == "semgrep":
        return True
    if choice == "heuristic":
        return False
    return None


def _report_to_json(report: ScanReport, options: CliOptions) -> str:
    payload: dict[str, Any] = {
        "target": str(report.target),
        "summary": report.summary,
        "engine": report.engine,
        "findings": [
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "message": finding.message,
                "path": str(finding.path),
                "line": finding.line,
                "snippet": finding.snippet,
            }
            for finding in report.findings
        ],
        "binaries": [
            {
                "path": str(binary.path),
                "kind": binary.kind,
                "size": binary.size,
                "magic": binary.magic,
            }
            for binary in report.binaries
        ],
    }
    return json.dumps(payload, indent=2 if options.verbosity == "debug" else None)


def _report_to_text(report: ScanReport, options: CliOptions) -> str:
    lines = [f"Scan target: {report.target}"]
    engine_name = str(report.engine.get("name", "unknown"))
    fallback = report.engine.get("fallback_reason")
    if fallback:
        fallback_str = str(fallback)
        lines.append(f"Analysis engine: {engine_name} (fallback: {fallback_str})")
    else:
        lines.append(f"Analysis engine: {engine_name}")

    counts = report.summary.get("findings", {})
    lines.append(
        "Findings: total={total} critical={critical} high={high} medium={medium} low={low}".format(
            total=counts.get("total", 0),
            critical=counts.get("critical", 0),
            high=counts.get("high", 0),
            medium=counts.get("medium", 0),
            low=counts.get("low", 0),
        )
    )
    if report.summary.get("binaries"):
        lines.append(f"Native binaries detected: {report.summary['binaries']}")

    lines.extend(_format_findings_text(report.findings, options))

    return "\n".join(lines)


def _format_findings_text(findings: Sequence[Finding], options: CliOptions) -> list[str]:
    if options.verbosity == "quiet":
        return []

    if options.pretty:
        return _format_grouped_findings(findings, options)

    sorted_findings = sorted(
        findings,
        key=lambda f: (
            severity_sort_key(f.severity),
            f.rule_id,
            str(f.path),
            f.line or 0,
        ),
    )

    colorize = not options.no_colors
    lines: list[str] = []
    for finding in sorted_findings:
        rule_display, severity_text = _decorate_rule_and_severity(
            finding.rule_id, finding.severity, colorize
        )
        location = f"{finding.path}:{finding.line}" if finding.line else str(finding.path)
        snippet = _format_snippet(finding.snippet, options)

        lines.append(f"[{rule_display}] {severity_text} - {finding.message} ({location}){snippet}")

    return lines


def _severity_color(severity: str) -> str | None:
    return _COLORS.get(severity.lower())


def _decorate_rule_and_severity(rule_id: str, severity: str, colorize: bool) -> tuple[str, str]:
    severity_text = severity.upper()
    if not colorize:
        return rule_id, severity_text

    color = _severity_color(severity)
    if not color:
        return rule_id, severity_text

    return f"{color}{rule_id}{_RESET}", f"{color}{severity_text}{_RESET}"


def _format_snippet(snippet: str | None, options: CliOptions) -> str:
    if options.verbosity != "debug" or not snippet:
        return ""
    return f" \u2014 {snippet}"


def _format_grouped_findings(findings: Sequence[Finding], options: CliOptions) -> list[str]:
    colorize = not options.no_colors
    debug = options.verbosity == "debug"

    by_file: dict[str, dict[str, list[Finding]]] = defaultdict(lambda: defaultdict(list))
    for finding in findings:
        by_file[str(finding.path)][finding.rule_id].append(finding)

    file_severity_rank: dict[str, int] = {}
    for file_path, rule_map in by_file.items():
        best = min(
            severity_sort_key(finding.severity)
            for group in rule_map.values()
            for finding in group
        )
        file_severity_rank[file_path] = best

    ordered_files = sorted(
        by_file.keys(), key=lambda path: (file_severity_rank[path], path)
    )

    lines: list[str] = []
    for file_index, file_path in enumerate(ordered_files):
        if file_index > 0:
            lines.append("")
        lines.append(file_path)

        rule_map = by_file[file_path]
        severity_counts: dict[str, int] = {}
        for group in rule_map.values():
            for finding in group:
                severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        summary_parts = [
            f"{level}:{severity_counts[level]}"
            for level in ORDERED_SEVERITIES
            if severity_counts.get(level)
        ]
        if summary_parts:
            lines.append("  Severity summary: " + ", ".join(summary_parts))

        for rule_id in sorted(
            rule_map.keys(),
            key=lambda rid: (
                severity_sort_key(rule_map[rid][0].severity),
                rid,
            ),
        ):
            group = rule_map[rule_id]
            exemplar = group[0]
            rule_display, severity_text = _decorate_rule_and_severity(rule_id, exemplar.severity, colorize)
            message = exemplar.message

            line_numbers = sorted({f.line for f in group if f.line is not None})
            if line_numbers:
                displayed = ", ".join(str(num) for num in line_numbers[:10])
                if len(line_numbers) > 10:
                    displayed += ", …"
                line_info = f"lines {displayed}"
            else:
                line_info = "lines n/a"
            if len(group) > len(line_numbers):
                line_info += f" ({len(group)} matches)"

            snippet_text = ""
            if debug:
                snippets = [f.snippet for f in group if f.snippet]
                if snippets:
                    snippet_text = f" \u2014 {snippets[0]}"
                    if len(snippets) > 1:
                        snippet_text += f" (+{len(snippets) - 1} more)"

            lines.append(f"  [{rule_display}] {severity_text} - {message} ({line_info}){snippet_text}")

    return lines


def _print_error(message: str) -> None:
    print(message, file=sys.stderr)


def _write_html_report(report: ScanReport, options: CliOptions) -> Path:
    html = _report_to_html(report)
    output_path = _resolve_output_path(report, options)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path


def _report_to_html(report: ScanReport) -> str:
    summary = report.summary.get("findings", {})
    severities = []
    for level in ORDERED_SEVERITIES:
        count = summary.get(level, 0)
        severities.append(
            {
                "label": level.capitalize(),
                "css_class": f"severity-{level}",
                "count": count,
                "has_findings": count > 0,
            }
        )

    findings = []
    for finding in sorted(
        report.findings,
        key=lambda f: (
            severity_sort_key(f.severity),
            str(f.path),
            f.line or 0,
            f.rule_id,
        ),
    ):
        link = _file_uri(finding.path, finding.line)
        line_display = f" (line {finding.line})" if finding.line else ""
        findings.append(
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity.upper(),
                "css_class": finding.severity.lower(),
                "message": finding.message,
                "path_display": f"{finding.path}{line_display}",
                "link": link,
                "snippet": finding.snippet,
            }
        )

    binaries = [
        {
            "path": str(binary.path),
            "kind": binary.kind,
            "size": binary.size,
            "magic": binary.magic,
        }
        for binary in report.binaries
    ]

    context = {
        "target": str(report.target),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "engine": {
            "name": report.engine.get("name", "unknown"),
            "fallback_reason": report.engine.get("fallback_reason"),
        },
        "findings_total": summary.get("total", len(report.findings)),
        "severities": severities,
        "binaries_total": report.summary.get("binaries", len(report.binaries)),
        "findings": findings,
        "binaries": binaries,
    }

    return _HTML_TEMPLATE_OBJ.render(context)


def _file_uri(path: Path, line: int | None) -> str | None:
    try:
        uri = path.resolve().as_uri()
    except (OSError, ValueError):
        return None
    if line:
        uri = f"{uri}#L{line}"
    return uri


def _resolve_output_path(report: ScanReport, options: CliOptions) -> Path:
    timestamp = datetime.now()

    if options.output is None:
        filename = _generate_report_filename(report, timestamp)
        candidate = Path.cwd() / filename
        return _unique_path(candidate)

    base = options.output
    if not base.is_absolute():
        base = Path.cwd() / base

    base = base.expanduser().resolve()

    if base.exists() and base.is_dir():
        filename = _generate_report_filename(report, timestamp)
        candidate = base / filename
        return _unique_path(candidate)

    if base.suffix == "":
        base = base.with_suffix(".html")

    return _unique_path(base)


def _unique_path(path: Path) -> Path:
    candidate = path
    counter = 1
    suffix = candidate.suffix or ".html"
    stem = candidate.stem if candidate.suffix else candidate.name
    parent = candidate.parent

    while candidate.exists():
        candidate = parent / f"{stem}-{counter}{suffix}"
        counter += 1

    return candidate


if __name__ == "__main__":
    sys.exit(main())
