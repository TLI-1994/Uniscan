#!/usr/bin/env python3
"""Generate the Semgrep rule for Unity autorun editor hooks."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

import yaml


class LiteralStr(str):
    """String subclass that forces literal block style in YAML."""


def _literal_str_representer(dumper: yaml.Dumper, data: LiteralStr):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.add_representer(LiteralStr, _literal_str_representer)
yaml.SafeDumper.add_representer(LiteralStr, _literal_str_representer)
yaml.Dumper.add_representer(LiteralStr, _literal_str_representer)

DATA_PATH = Path(__file__).resolve().parent / "data" / "autorun_editor_hooks.yaml"
OUTPUT_PATH = Path(__file__).resolve().parents[2] / "rules/core/semgrep/unity.autorun.editor-hooks.yaml"


def _load_spec() -> dict[str, Any]:
    with DATA_PATH.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle)
    if not isinstance(payload, dict):  # pragma: no cover - defensive
        raise RuntimeError("Autorun editor hook spec must be a mapping")
    return payload


def _iter_class_patterns(spec: dict[str, Any]) -> Iterable[LiteralStr]:
    class_attrs = spec.get("class_attributes", [])
    class_decls = spec.get("class_declarations", [])
    for attribute in class_attrs:
        for declaration in class_decls:
            yield LiteralStr(f"[{attribute}]\n{declaration}")


def _iter_method_patterns(spec: dict[str, Any]) -> Iterable[LiteralStr]:
    signature_sets = spec.get("signature_sets", {})
    method_groups = spec.get("method_groups", [])
    for group in method_groups:
        attributes = group.get("attributes", [])
        signature_key = group.get("signature_set")
        if signature_key is None:
            raise RuntimeError("method group missing signature_set")
        signatures = signature_sets.get(signature_key)
        if signatures is None:
            raise RuntimeError(f"unknown signature set: {signature_key}")
        allow_args = bool(group.get("allow_args"))
        for attribute in attributes:
            for signature in signatures:
                yield LiteralStr(f"[{attribute}]\n{signature}")
                if allow_args:
                    yield LiteralStr(f"[{attribute}(...)]\n{signature}")


def _build_patterns(spec: dict[str, Any]) -> list[dict[str, LiteralStr]]:
    patterns = []
    for block in _iter_class_patterns(spec):
        patterns.append({"pattern": block})
    for block in _iter_method_patterns(spec):
        patterns.append({"pattern": block})
    return patterns


def generate() -> dict[str, Any]:
    spec = _load_spec()
    patterns = _build_patterns(spec)
    rule = {
        "id": "unity.autorun.editor-hooks",
        "message": "Editor/run hooks that auto-execute code",
        "languages": ["csharp"],
        "severity": "WARNING",
        "pattern-either": patterns,
    }
    return {"rules": [rule]}


def write(output: Path = OUTPUT_PATH) -> None:
    data = generate()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, sort_keys=False)


def main() -> None:
    write()


if __name__ == "__main__":  # pragma: no cover - CLI entry
    main()
