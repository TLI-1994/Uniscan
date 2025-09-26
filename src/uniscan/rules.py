"""Rule loading and representation utilities for Uniscan."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence

try:  # pragma: no cover - optional dependency
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    yaml = None


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

    module_root = Path(__file__).resolve().parent
    rules_root = module_root.parent.parent / "rules"
    sources: List[Path] = []

    core_dir = rules_root / "core"
    sources.extend(sorted(core_dir.glob("*.yaml")))

    if include_private:
        private_dir = rules_root / "private"
        sources.extend(sorted(private_dir.glob("*.yaml")))

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

        severity = str(entry.get("severity", "INFO")).upper()

        parsed.append(
            Rule(
                id=rule_id,
                message=message,
                languages=languages,
                severity=severity,
                raw=entry,
                source=source,
            )
        )

    return parsed


def _load_rule_document(text: str, *, source: Path) -> object:
    if yaml is not None:
        try:
            return yaml.safe_load(text)
        except Exception as exc:  # pragma: no cover - yaml parsing details not important
            raise RuleLoadError(f"Failed to load rule file {source}: {exc}") from exc
    return _fallback_parse_yaml(text, source=source)


def _fallback_parse_yaml(text: str, *, source: Path) -> object:
    rules: list[dict] = []
    current: dict | None = None
    active_list_key: str | None = None
    list_indent: int | None = None
    saw_rules_key = False

    for raw_line in text.splitlines():
        stripped_leading = raw_line.lstrip()
        if not stripped_leading or stripped_leading.startswith("#"):
            continue

        indent = len(raw_line) - len(stripped_leading)
        line = stripped_leading

        if active_list_key is not None and list_indent is not None and indent < list_indent:
            active_list_key = None
            list_indent = None

        if line.startswith("rules:"):
            saw_rules_key = True
            continue

        if line.startswith("- id:"):
            if current:
                rules.append(current)
            current = {
                "id": _parse_scalar(line[len("- id:"):].strip())
            }
            active_list_key = None
            list_indent = None
            continue

        if current is None:
            # Skip preamble until first rule entry
            continue

        if active_list_key and line.startswith("- "):
            content = line[2:].strip()
            if not content:
                continue
            if ":" not in content:
                raise RuleLoadError(f"Invalid list entry in {source}: {content}")
            key, value = content.split(":", 1)
            entry = {key.strip(): _parse_scalar(value.strip())}
            current[active_list_key].append(entry)
            continue

        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()

        if not value:
            if key == "rules":
                # top-level declaration handled implicitly
                continue
            if key == "pattern-either":
                current[key] = []
                active_list_key = key
                list_indent = indent + 2
            else:
                current[key] = {}
            continue

        current[key] = _parse_scalar(value)
        active_list_key = None
        list_indent = None

    if current:
        rules.append(current)

    if not saw_rules_key:
        raise RuleLoadError(f"Rule file {source} missing top-level 'rules' key")

    return {"rules": rules}


def _parse_scalar(token: str):
    token = token.strip()
    if token.startswith("[") and token.endswith("]"):
        inner = token[1:-1].strip()
        if not inner:
            return []
        parts = [part.strip() for part in inner.split(",")]
        return [_strip_quotes(part) for part in parts]
    return _strip_quotes(token)


def _strip_quotes(value: str) -> str:
    if (value.startswith("'") and value.endswith("'")) or (
        value.startswith('"') and value.endswith('"')
    ):
        return value[1:-1]
    return value
