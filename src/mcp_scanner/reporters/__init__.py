"""Output formats: console table, JSON and SARIF 2.1.0."""

from __future__ import annotations

import os
from pathlib import Path


def display_path(path: str | None, root: Path | None = None) -> str:
    """Return ``path`` relative to ``root`` (default: cwd) with POSIX separators.

    Paths outside ``root`` are returned unchanged and a missing path as ``-``.
    """
    if not path:
        return "-"
    root = root or Path.cwd()
    try:
        return Path(os.path.abspath(path)).relative_to(os.path.abspath(root)).as_posix()
    except ValueError:
        return str(path)
