import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return ROOT / "tests" / "fixtures"


@pytest.fixture()
def unity_project(fixtures_dir):
    def _resolve(name: str) -> Path:
        path = fixtures_dir / name
        if not path.exists():
            raise FileNotFoundError(f"Fixture project '{name}' not found at {path}")
        return path

    return _resolve
