from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _isolate_pins(tmp_path, monkeypatch):
    """Never let a test read or write the developer's real pin file."""
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
