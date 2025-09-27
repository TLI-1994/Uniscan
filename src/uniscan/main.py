from __future__ import annotations

import json
import sys
from pathlib import Path
from collections import defaultdict
from typing import Any, Sequence

from .binaries import BinaryClassifier
from .cli import CliOptions, parse_args
from .rules import RuleLoadError, load_ruleset, load_semgrep_sources
from .scanner import Finding, ScanReport, Scanner, ScannerConfig

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_FS_ERROR = 3
EXIT_RULE_ERROR = 4
EXIT_FAILURE = 1

_RESET = "\x1b[0m"
_COLORS = {
    "info": "\x1b[34m",  # blue
    "warning": "\x1b[33m",  # yellow
    "error": "\x1b[31m",  # red
    "critical": "\x1b[35m",  # magenta
}


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
        "Findings: total={total} info={info} warning={warning} error={error}".format(
            total=counts.get("total", 0),
            info=counts.get("info", 0),
            warning=counts.get("warning", 0),
            error=counts.get("error", 0),
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

    colorize = not options.no_colors
    lines: list[str] = []
    for finding in findings:
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

    lines: list[str] = []
    for file_index, file_path in enumerate(sorted(by_file.keys())):
        if file_index > 0:
            lines.append("")
        lines.append(file_path)

        rule_map = by_file[file_path]
        for rule_id in sorted(rule_map.keys()):
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


if __name__ == "__main__":
    sys.exit(main())
