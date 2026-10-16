"""Position-aware JSON/JSONC parser.

Unlike :mod:`json`, it records where each value starts (keyed by JSON Pointer)
so findings can point at exact lines. It accepts JSONC as used by VS Code and
Zed (comments, trailing commas) and records duplicate keys, which ``json.loads``
silently collapses: a reviewer may read the first definition of a server while
the client runs the last one.
"""

from __future__ import annotations

import bisect
import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Location, join_pointer

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 256

_STRING = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"', re.DOTALL)
_NUMBER = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")
_DECODER = json.JSONDecoder(strict=False)


class JSONLocError(ValueError):
    """Syntax error with a 1-based ``line`` and ``column``."""

    def __init__(self, message: str, line: int, column: int) -> None:
        super().__init__(f"{message} (line {line}, column {column})")
        self.line = line
        self.column = column


def _line_starts(text: str) -> list[int]:
    return [0] + [m.end() for m in re.finditer("\n", text)]


def _position(starts: list[int], offset: int) -> tuple[int, int]:
    index = bisect.bisect_right(starts, offset) - 1
    return index + 1, offset - starts[index] + 1


class _Parser:
    def __init__(self, text: str, allow_comments: bool) -> None:
        self.text = text
        self.n = len(text)
        self.pos = 0
        self.allow_comments = allow_comments
        self.offsets: dict[str, int] = {}
        self.duplicates: list[str] = []

    def error(self, message: str, pos: int | None = None) -> JSONLocError:
        line, column = _position(_line_starts(self.text), self.pos if pos is None else pos)
        return JSONLocError(message, line, column)

    def peek(self) -> str:
        return self.text[self.pos] if self.pos < self.n else ""

    def skip(self) -> None:
        text, n = self.text, self.n
        while self.pos < n:
            c = text[self.pos]
            if c in " \t\r\n":
                self.pos += 1
            elif self.allow_comments and c == "/" and self.pos + 1 < n:
                nxt = text[self.pos + 1]
                if nxt == "/":
                    end = text.find("\n", self.pos)
                    self.pos = n if end == -1 else end + 1
                elif nxt == "*":
                    end = text.find("*/", self.pos + 2)
                    if end == -1:
                        raise self.error("unterminated comment")
                    self.pos = end + 2
                else:
                    break
            else:
                break

    def value(self, pointer: str, depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise self.error("nesting too deep")
        self.skip()
        if self.pos >= self.n:
            raise self.error("unexpected end of input")
        # Object members are already located at their key; keep that position.
        self.offsets.setdefault(pointer, self.pos)
        c = self.text[self.pos]
        if c == "{":
            return self.object(pointer, depth)
        if c == "[":
            return self.array(pointer, depth)
        if c == '"':
            return self.string()
        match = _NUMBER.match(self.text, self.pos)
        if match:
            self.pos = match.end()
            return json.loads(match.group())
        for literal, result in (("true", True), ("false", False), ("null", None)):
            if self.text.startswith(literal, self.pos):
                self.pos += len(literal)
                return result
        raise self.error(f"unexpected character {c!r}")

    def string(self) -> str:
        match = _STRING.match(self.text, self.pos)
        if not match:
            raise self.error("unterminated string")
        self.pos = match.end()
        try:
            return _DECODER.decode(match.group())
        except json.JSONDecodeError as exc:
            raise self.error(f"invalid string: {exc.msg}", match.start() + exc.pos) from None

    def object(self, pointer: str, depth: int) -> dict[str, Any]:
        self.pos += 1
        result: dict[str, Any] = {}
        self.skip()
        if self.peek() == "}":
            self.pos += 1
            return result
        while True:
            self.skip()
            if self.peek() != '"':
                raise self.error("expected string key")
            key_pos = self.pos
            key = self.string()
            child = join_pointer(pointer, key)
            if key in result:
                self.duplicates.append(child)
                # The last definition wins: drop offsets recorded for the earlier value.
                prefix = child + "/"
                for stale in [p for p in self.offsets if p.startswith(prefix)]:
                    del self.offsets[stale]
            self.offsets[child] = key_pos
            self.skip()
            if self.peek() != ":":
                raise self.error("expected ':'")
            self.pos += 1
            result[key] = self.value(child, depth + 1)
            self.skip()
            c = self.peek()
            if c == ",":
                self.pos += 1
                self.skip()
                if self.allow_comments and self.peek() == "}":  # JSONC trailing comma.
                    self.pos += 1
                    return result
                continue
            if c == "}":
                self.pos += 1
                return result
            raise self.error("expected ',' or '}'")

    def array(self, pointer: str, depth: int) -> list[Any]:
        self.pos += 1
        result: list[Any] = []
        self.skip()
        if self.peek() == "]":
            self.pos += 1
            return result
        while True:
            result.append(self.value(join_pointer(pointer, len(result)), depth + 1))
            self.skip()
            c = self.peek()
            if c == ",":
                self.pos += 1
                self.skip()
                if self.allow_comments and self.peek() == "]":  # JSONC trailing comma.
                    self.pos += 1
                    return result
                continue
            if c == "]":
                self.pos += 1
                return result
            raise self.error("expected ',' or ']'")


def parse(text: str, *, allow_comments: bool = True) -> tuple[Any, dict[str, int], list[str]]:
    """Parse JSON or JSONC text.

    Return ``(value, offsets, duplicates)``: ``offsets`` maps JSON Pointers to
    source offsets and ``duplicates`` lists the pointers of repeated keys. Raise
    :class:`JSONLocError` on invalid input.
    """
    parser = _Parser(text, allow_comments)
    value = parser.value("", 0)
    parser.skip()
    if parser.pos != parser.n:
        raise parser.error("unexpected trailing data")
    return value, parser.offsets, parser.duplicates


@dataclass
class SourceDocument:
    """A parsed file plus everything needed to map JSON Pointers to lines."""

    path: str
    text: str
    data: Any
    offsets: dict[str, int] = field(default_factory=dict)
    duplicates: list[str] = field(default_factory=list)
    _starts: list[int] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self._starts = _line_starts(self.text)

    def position(self, offset: int) -> tuple[int, int]:
        return _position(self._starts, offset)

    def locate(self, pointer: str, hint: str | None = None) -> Location:
        """Return the location of ``pointer``, or of its closest recorded ancestor.

        Documents without offsets (TOML) fall back to the first occurrence of ``hint``.
        """
        current = pointer
        while current in self.offsets or current:
            if current in self.offsets:
                line, column = self.position(self.offsets[current])
                return Location(self.path, line, column, pointer)
            current = current.rsplit("/", 1)[0]
        if hint:
            index = self.text.find(hint)
            if index >= 0:
                line, column = self.position(index)
                return Location(self.path, line, column, pointer)
        return Location(self.path, None, None, pointer)


def from_text(path: str, text: str, *, toml: bool = False) -> SourceDocument:
    """Parse ``text`` as JSONC, or as TOML if ``toml`` is true; a leading BOM is ignored."""
    if text.startswith("\ufeff"):
        text = text[1:]
    if toml:
        return SourceDocument(path, text, tomllib.loads(text))
    data, offsets, duplicates = parse(text)
    return SourceDocument(path, text, data, offsets, duplicates)


def load_document(path: str | Path) -> SourceDocument:
    """Read and parse a JSON or JSONC file, or TOML if the suffix is ``.toml``.

    Raise ``OSError``, ``UnicodeDecodeError``, ``ValueError`` (file too large, or
    :class:`JSONLocError`) or ``tomllib.TOMLDecodeError`` on failure.
    """
    file_path = Path(path)
    size = file_path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"file is too large ({size} bytes, limit {MAX_FILE_BYTES})")
    text = file_path.read_bytes().decode("utf-8")
    return from_text(str(file_path), text, toml=file_path.suffix.lower() == ".toml")
