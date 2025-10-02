from __future__ import annotations

import json
import sys
import re
import textwrap
from datetime import datetime
import hashlib
from pathlib import Path
from typing import Any

from importlib import resources as importlib_resources
from markupsafe import Markup
from jinja2 import Environment, select_autoescape

from . import __version__
from .binaries import BinaryClassifier
from .cli import CliOptions, parse_args
from .rules import RuleLoadError, load_ruleset, load_semgrep_sources
from .scanner import ScanReport, Scanner, ScannerConfig
from .severity import ORDERED_SEVERITIES, severity_sort_key
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_by_name
from pygments.util import ClassNotFound

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_FS_ERROR = 3
EXIT_RULE_ERROR = 4
EXIT_FAILURE = 1

def _load_html_template() -> str:
    template_resource = importlib_resources.files("usentinel.templates") / "report.html"
    return template_resource.read_text(encoding="utf-8")

_HTML_ENV = Environment(autoescape=select_autoescape(["html", "xml"]))
_HTML_TEMPLATE_OBJ = _HTML_ENV.from_string(_load_html_template())


_LEXER_NAME = "csharp"
_HTML_FORMATTER = HtmlFormatter(nowrap=True, noclasses=True)


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

    if options.format == "raw":
        print(_report_to_json(report, options))
    else:
        output_path = _write_html_report(report, options)
        print(f"HTML report written to {output_path}")

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
    return json.dumps(payload, indent=2)




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
        snippet_rendered = _format_snippet(finding.snippet) if finding.snippet else None
        findings.append(
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity.upper(),
                "css_class": finding.severity.lower(),
                "message": finding.message,
                "path_display": f"{finding.path}{line_display}",
                "link": link,
                "snippet_html": snippet_rendered,
                "snippet_text": finding.snippet,
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
        "usentinel_version": __version__,
        "engine": {
            "name": report.engine.get("name", "unknown"),
            "fallback_reason": report.engine.get("fallback_reason"),
            "version": report.engine.get("version"),
        },
        "findings_total": summary.get("total", len(report.findings)),
        "severities": severities,
        "binaries_total": report.summary.get("binaries", len(report.binaries)),
        "findings": findings,
        "binaries": binaries,
    }

    return _HTML_TEMPLATE_OBJ.render(context)


def _format_snippet(snippet: str) -> Markup | None:
    snippet_text = textwrap.dedent(snippet or "").strip("\n")
    if not snippet_text:
        return None

    try:
        lexer = get_lexer_by_name(_LEXER_NAME)
    except ClassNotFound:  # pragma: no cover - pygments missing language
        from pygments.lexers.special import TextLexer

        lexer = TextLexer()

    highlighted = highlight(snippet_text, lexer, _HTML_FORMATTER)
    return Markup(highlighted.strip())


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
