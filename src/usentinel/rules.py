"""Rule loading and representation utilities for Usentinel."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Iterable, Iterator, List, Sequence, Tuple

import yaml

from .severity import normalize_severity


class RuleLoadError(RuntimeError):
    """Raised when a rule file cannot be parsed or is invalid."""


@dataclass(frozen=True)
class Rule:
    id: str
    message: str
    languages: tuple[str, ...]
    severity: str
    raw: dict
    source: Path
    tag: str


@dataclass(frozen=True)
class Ruleset:
    rules: tuple[Rule, ...]
    sources: tuple[Path, ...]

    def for_language(self, language: str) -> list[Rule]:
        language_lower = language.lower()
        return [rule for rule in self.rules if language_lower in (lang.lower() for lang in rule.languages)]


def load_ruleset(
    *,
    include_private: bool = True,
    extra_rule_files: Sequence[Path] | None = None,
) -> Ruleset:
    """Load rules from bundled YAML files and optional user-provided files."""

    sources: List[Path] = []

    with _rules_root() as rules_root:
        core_dir = rules_root / "core" / "heuristic"
        if not core_dir.exists():
            core_dir = rules_root / "core"
        sources.extend(sorted(core_dir.glob("*.yaml")))

        if include_private:
            private_dir = rules_root / "private" / "heuristic"
            if private_dir.exists():
                sources.extend(sorted(private_dir.glob("*.yaml")))
            else:
                legacy_private = rules_root / "private"
                if legacy_private.exists():
                    sources.extend(sorted(legacy_private.glob("*.yaml")))

    if extra_rule_files:
        sources.extend(Path(path) for path in extra_rule_files)

    rules: list[Rule] = []
    for path in sources:
        if not path.exists():
            raise RuleLoadError(f"Rule file not found: {path}")
        text = path.read_text()
        data = _load_rule_document(text, source=path)

        file_rules = _parse_rule_document(data, source=path)
        rules.extend(file_rules)

    unique_sources: list[Path] = []
    seen_sources = set()
    for path in sources:
        resolved = path.resolve()
        if resolved in seen_sources:
            continue
        seen_sources.add(resolved)
        unique_sources.append(resolved)

    return Ruleset(tuple(rules), tuple(unique_sources))


def load_semgrep_sources(
    *,
    include_private: bool = True,
    extra_rule_files: Sequence[Path] | None = None,
) -> Tuple[Path, ...]:
    sources: List[Path] = []

    with _rules_root() as rules_root:
        semgrep_core = rules_root / "core" / "semgrep"
        if not semgrep_core.exists():
            semgrep_core = rules_root / "semgrep" / "core"
        if semgrep_core.exists():
            sources.extend(sorted(semgrep_core.glob("*.yaml")))

        if include_private:
            private_dir = rules_root / "private" / "semgrep"
            if not private_dir.exists():
                private_dir = rules_root / "semgrep" / "private"
            if private_dir.exists():
                sources.extend(sorted(private_dir.glob("*.yaml")))

    if extra_rule_files:
        sources.extend(Path(path) for path in extra_rule_files)

    unique: list[Path] = []
    seen = set()
    for path in sources:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(resolved)

    return tuple(unique)


def _parse_rule_document(document: object, *, source: Path) -> list[Rule]:
    if not isinstance(document, dict):
        raise RuleLoadError(f"Rule file {source} must contain a mapping at top level")

    rule_entries = document.get("rules")
    if not isinstance(rule_entries, Iterable) or isinstance(rule_entries, (str, bytes)):
        raise RuleLoadError(f"Rule file {source} must define a 'rules' list")

    parsed: list[Rule] = []
    for entry in rule_entries:
        if not isinstance(entry, dict):
            raise RuleLoadError(f"Rule entry in {source} must be a mapping")

        try:
            rule_id = str(entry["id"])
            message = str(entry["message"])
        except KeyError as exc:
            raise RuleLoadError(f"Rule in {source} missing required field {exc}") from exc

        languages_raw = entry.get("languages")
        if not isinstance(languages_raw, Iterable) or isinstance(languages_raw, (str, bytes)):
            raise RuleLoadError(f"Rule {rule_id} in {source} must define a list of languages")
        languages = tuple(str(lang) for lang in languages_raw)

        severity = normalize_severity(entry.get("severity")).value

        parsed.append(
            Rule(
                id=rule_id,
                message=message,
                languages=languages,
                severity=severity,
                raw=entry,
                source=source,
                tag=_infer_tag(source),
            )
        )

    return parsed


def _load_rule_document(text: str, *, source: Path) -> object:
    try:
        return yaml.safe_load(text)
    except Exception as exc:  # pragma: no cover - yaml parsing details not important
        raise RuleLoadError(f"Failed to load rule file {source}: {exc}") from exc


def _infer_tag(source: Path) -> str:
    parts = source.parts
    if "core" in parts:
        return "core"
    if "private" in parts:
        return "private"
    return "external"


@contextmanager
def _rules_root() -> Iterator[Path]:
    module_root = Path(__file__).resolve().parent
    repo_rules = module_root.parent.parent / "rules"
    if repo_rules.exists():
        yield repo_rules
        return

    try:
        rules_traversable = resources.files("usentinel_rules")
    except ModuleNotFoundError as exc:  # pragma: no cover - packaging error
        raise RuleLoadError("Bundled rules are unavailable") from exc

    with resources.as_file(rules_traversable) as bundle_root:
        yield bundle_root
