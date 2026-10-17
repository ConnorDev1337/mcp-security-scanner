from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from hypothesis import HealthCheck, settings

FIXTURES = Path(__file__).parent / "fixtures"

# Property-based tests: "ci" (the default) is small and deterministic so every run checks
# the same examples quickly; "fuzz" explores many more random examples. Select a profile
# with HYPOTHESIS_PROFILE=fuzz or pytest --hypothesis-profile=fuzz.
settings.register_profile(
    "ci",
    max_examples=40,
    deadline=None,
    derandomize=True,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
settings.register_profile(
    "fuzz",
    max_examples=2000,
    deadline=None,
    print_blob=True,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))


@pytest.fixture(autouse=True)
def _isolate_pins(tmp_path, monkeypatch):
    """Keep tests away from the developer's real pin file and disable colored output."""
    monkeypatch.setenv("MCP_SCANNER_PINS", str(tmp_path / "default-pins.json"))
    monkeypatch.setenv("NO_COLOR", "1")


@pytest.fixture
def write_json(tmp_path):
    def _write(relative: str, data, *, raw: str | None = None) -> Path:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(raw if raw is not None else json.dumps(data, indent=2), encoding="utf-8")
        return path

    return _write


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES
