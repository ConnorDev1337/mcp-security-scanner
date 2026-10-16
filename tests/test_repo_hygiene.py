"""The scanner's own sources must not contain the characters it flags.

Test inputs use ``\\uXXXX`` escapes instead of literal invisible characters so
reviewers (and GitHub's bidi warnings) can see exactly what is being tested.
"""

from pathlib import Path

import pytest

from mcp_scanner.textutil import is_hidden_char

ROOT = Path(__file__).resolve().parent.parent
FILES = [
    *sorted(
        p
        for folder in ("src", "tests", "examples", ".github")
        for p in (ROOT / folder).rglob("*")
        if p.suffix in {".py", ".json", ".yml", ".yaml", ".toml", ".md"} and p.is_file()
    ),
    ROOT / "README.md",
    ROOT / "pyproject.toml",
]


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_no_hidden_characters(path):
    text = path.read_text(encoding="utf-8")
    hidden = [
        (number, f"U+{ord(ch):04X}")
        for number, line in enumerate(text.splitlines(), 1)
        for ch in line
        if is_hidden_char(ch)
    ]
    assert hidden == []
