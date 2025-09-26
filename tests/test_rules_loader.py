from pathlib import Path

import pytest

from uniscan.rules import Ruleset, RuleLoadError, load_ruleset


def test_load_ruleset_includes_core_rules():
    ruleset = load_ruleset(include_private=False)

    assert isinstance(ruleset, Ruleset)
    rule_ids = {rule.id for rule in ruleset.rules}
    assert "unity.proc.exec.process-start" in rule_ids
    assert "unity.reflection.assembly-load" not in rule_ids


def test_load_ruleset_can_merge_private_rules(tmp_path):
    ruleset = load_ruleset(include_private=True)
    rule_ids = {rule.id for rule in ruleset.rules}

    assert "unity.reflection.assembly-load" in rule_ids

    # Custom ruleset augmentation
    extra_rule = tmp_path / "custom_rules.yaml"
    extra_rule.write_text(
        """
        rules:
          - id: sample.rule
            message: Sample rule for testing
            languages: [csharp]
            severity: WARNING
            pattern: ForbiddenThing(...)
        """.strip()
    )

    augmented = load_ruleset(include_private=False, extra_rule_files=[extra_rule])
    augmented_ids = {rule.id for rule in augmented.rules}

    assert "sample.rule" in augmented_ids


def test_invalid_rule_file_raises(tmp_path):
    bad_rule = tmp_path / "bad.yaml"
    bad_rule.write_text("not-a-valid: [structure]")

    with pytest.raises(RuleLoadError):
        load_ruleset(include_private=False, extra_rule_files=[bad_rule])


def test_ruleset_filters_by_language():
    ruleset = load_ruleset(include_private=True)
    csharp_rules = ruleset.for_language("csharp")

    assert all("csharp" in rule.languages for rule in csharp_rules)
    assert len(csharp_rules) == len(ruleset.rules)

    nonexistent = ruleset.for_language("python")
    assert nonexistent == []
