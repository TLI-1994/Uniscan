from pathlib import Path
import sys

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.semgrep import generate_autorun_editor_hooks as generator  # noqa: E402


def test_autorun_generator_matches_expected(tmp_path, monkeypatch):
    fixtures_root = Path('tests/fixtures/semgrep_generator')
    spec_src = fixtures_root / 'spec.yaml'
    expected_yaml = (fixtures_root / 'expected.yaml').read_text(encoding='utf-8')

    spec_dest = tmp_path / 'spec.yaml'
    spec_dest.write_text(spec_src.read_text(encoding='utf-8'), encoding='utf-8')

    output_path = tmp_path / 'unity.autorun.editor-hooks.yaml'

    monkeypatch.setattr(generator, 'DATA_PATH', spec_dest)
    monkeypatch.setattr(generator, 'OUTPUT_PATH', output_path)

    generator.write(output_path)

    actual_yaml = output_path.read_text(encoding='utf-8')
    assert actual_yaml.strip() == expected_yaml.strip()

    actual = yaml.safe_load(actual_yaml)
    expected = yaml.safe_load(expected_yaml)
    assert actual == expected
