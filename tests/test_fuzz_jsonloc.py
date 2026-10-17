"""Property-based tests of the position-aware JSON/JSONC parser.

Valid documents are generated as Python values and serialized with random
whitespace, comments, trailing commas and repeated keys, while the serializer
records where each JSON Pointer starts; the parser must return the same value,
the same offsets and the repeated keys. Arbitrary and mutated text must only
ever raise :class:`JSONLocError`.
"""

import json
import time

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from mcp_scanner.jsonloc import (
    MAX_DEPTH,
    JSONLocError,
    SourceDocument,
    from_text,
    load_document,
    parse,
)
from mcp_scanner.models import join_pointer

KEYS = st.text(max_size=8) | st.sampled_from(["a", "a/b", "~", "~1", "", "mcpServers"])
SCALARS = (
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text()
)
VALUES = st.recursive(
    SCALARS,
    lambda children: st.lists(children, max_size=4) | st.dictionaries(KEYS, children, max_size=4),
    max_leaves=25,
)

STRICT_GAPS = st.sampled_from(["", " ", "\n", "\t", "\r\n", "  \n  "])
JSONC_GAPS = STRICT_GAPS | st.sampled_from(
    ["// note\n", "/* c */", "/**/", "/* a\n b */ ", "//\n"]
)


class _Writer:
    """Serialize a value with drawn layout choices, recording offsets and repeated keys."""

    def __init__(self, draw, jsonc: bool) -> None:
        self.draw = draw
        self.jsonc = jsonc
        self.parts: list[str] = []
        self.size = 0
        self.offsets: dict[str, int] = {}
        self.duplicates: list[str] = []

    def emit(self, text: str) -> None:
        self.parts.append(text)
        self.size += len(text)

    def gap(self) -> None:
        self.emit(self.draw(JSONC_GAPS if self.jsonc else STRICT_GAPS))

    def scalar(self, value) -> str:
        if isinstance(value, str):
            return json.dumps(value, ensure_ascii=self.draw(st.booleans()))
        return json.dumps(value)

    def value(self, value, pointer: str, record: bool = True) -> None:
        if record:
            self.offsets.setdefault(pointer, self.size)
        if isinstance(value, dict):
            self.container("{", "}", list(value.items()), pointer, record)
        elif isinstance(value, list):
            self.container("[", "]", list(enumerate(value)), pointer, record)
        else:
            self.emit(self.scalar(value))

    def container(self, open_: str, close: str, items, pointer: str, record: bool) -> None:
        self.emit(open_)
        members = []
        for key, item in items:
            if isinstance(key, str) and self.draw(st.integers(0, 4)) == 0:
                # An earlier definition of the same key, overridden by the real one.
                members.append((key, self.draw(SCALARS | st.lists(SCALARS, max_size=2)), True))
            members.append((key, item, False))
        for index, (key, item, decoy) in enumerate(members):
            self.gap()
            child = join_pointer(pointer, key)
            keep = record and not decoy
            if isinstance(key, str):
                if keep:
                    self.offsets[child] = self.size
                if not decoy and any(k == key and d for k, _, d in members[:index]):
                    self.duplicates.append(child)
                self.emit(json.dumps(key))
                self.gap()
                self.emit(":")
                self.gap()
            self.value(item, child, keep)
            self.gap()
            if index + 1 < len(members) or (self.jsonc and self.draw(st.booleans())):
                self.emit(",")
                self.gap()
        if not members:
            self.gap()
        self.emit(close)


@st.composite
def documents(draw, jsonc: bool):
    value = draw(VALUES)
    writer = _Writer(draw, jsonc)
    writer.gap()
    writer.value(value, "")
    writer.gap()
    return value, "".join(writer.parts), writer.offsets, writer.duplicates


@given(documents(jsonc=False))
def test_strict_json_matches_json_loads_and_offsets(doc):
    value, text, offsets, duplicates = doc
    parsed, found, repeated = parse(text, allow_comments=False)
    assert parsed == value == json.loads(text)
    assert found == offsets
    assert sorted(repeated) == sorted(duplicates)


@given(documents(jsonc=True))
def test_jsonc_layout_does_not_change_value_or_offsets(doc):
    value, text, offsets, duplicates = doc
    parsed, found, repeated = parse(text)
    assert parsed == value
    assert found == offsets
    assert sorted(repeated) == sorted(duplicates)


@given(documents(jsonc=True))
def test_locations_point_at_the_recorded_token(doc):
    _, text, offsets, _ = doc
    source = from_text("doc.json", text)
    for pointer, offset in offsets.items():
        location = source.locate(pointer)
        line_start = text.rfind("\n", 0, offset) + 1
        assert location.line == text.count("\n", 0, offset) + 1
        assert location.column == offset - line_start + 1
        assert location.pointer == pointer
        # Members are located at their key, other values at their first character.
        assert text[offset] in '{["-0123456789tfn'


def _check_error(text: str) -> None:
    try:
        parse(text)
        parse(text, allow_comments=False)
    except JSONLocError as exc:
        assert 1 <= exc.line <= text.count("\n") + 1
        assert exc.column >= 1


@given(st.text())
def test_arbitrary_text_raises_only_jsonloc_error(text):
    _check_error(text)


@given(st.text(alphabet=st.sampled_from('{}[]:,"\\/*\n -0123456789.eE+truefalsn٣')))
def test_json_alphabet_soup_raises_only_jsonloc_error(text):
    _check_error(text)


@given(documents(jsonc=True), st.data())
def test_mutated_documents_raise_only_jsonloc_error(doc, data):
    text = doc[1]
    for _ in range(data.draw(st.integers(1, 3))):
        index = data.draw(st.integers(0, len(text)))
        cut = data.draw(st.integers(0, 3))
        insert = data.draw(st.text(alphabet='{}[]:,"\\/*\n 0-e', max_size=2))
        text = text[:index] + insert + text[index + cut :]
    _check_error(text)


@given(st.text())
def test_strict_mode_agrees_with_json_loads(text):
    # NaN and Infinity are a json extension; raw control characters in strings are
    # accepted on purpose (strict=False).
    assume(not any(word in text for word in ("NaN", "Infinity")))
    try:
        expected = json.loads(text)
    except ValueError:
        expected = JSONLocError
    try:
        parsed = parse(text, allow_comments=False)[0]
    except JSONLocError:
        parsed = JSONLocError
    if expected is not JSONLocError:
        assert parsed == expected


@given(st.binary())
def test_arbitrary_bytes_in_files_fail_cleanly(tmp_path_factory, data):
    path = tmp_path_factory.mktemp("bytes") / "config.json"
    path.write_bytes(data)
    try:
        doc = load_document(path)
    except (UnicodeDecodeError, ValueError):
        return
    assert isinstance(doc, SourceDocument)


@pytest.mark.parametrize("open_", ["[", '{"a":'])
def test_nesting_limit_is_a_syntax_error(open_):
    close = "]" if open_ == "[" else "}"
    deep = open_ * MAX_DEPTH + "0" + close * MAX_DEPTH
    parse(deep)  # The innermost value sits exactly at the limit.
    with pytest.raises(JSONLocError, match="nesting too deep"):
        parse(open_ + deep + close)
    with pytest.raises(JSONLocError, match="nesting too deep"):
        parse(open_ * 100_000)


# --------------------------------------------------------------------------- regressions


def test_non_ascii_digits_are_not_numbers():
    # Found by fuzzing: \d matched U+0663 (ARABIC-INDIC DIGIT THREE), and the number
    # was then handed to json.loads, which raised a plain JSONDecodeError.
    with pytest.raises(JSONLocError, match="trailing data"):
        parse("1" + chr(0x663))


def test_integer_beyond_digit_limit_is_a_syntax_error():
    # Found by review: int() refuses more than 4300 digits with a bare ValueError.
    with pytest.raises(JSONLocError, match="number too long") as info:
        parse('{"a": ' + "1" * 5000 + "}")
    assert (info.value.line, info.value.column) == (1, 7)


def test_repeated_keys_cost_linear_time():
    # Found by review: each repeated key scanned every recorded offset (quadratic).
    count = 30_000
    body = ",".join(f'"k{i}": 0' for i in range(count))
    body += "," + ",".join('"a": [1, {"b": 2}]' for _ in range(count))
    start = time.perf_counter()
    value, offsets, duplicates = parse("{" + body + "}")
    assert time.perf_counter() - start < 3
    assert value["a"] == [1, {"b": 2}] and len(duplicates) == count - 1
    last = offsets["/a"]
    assert offsets["/a/1/b"] > last and len(offsets) == count + 5


def test_repeated_key_keeps_only_the_last_offsets():
    text = '{"a": {"x": 1, "y": [2]}, "a": {"x": 3}}'
    _, offsets, duplicates = parse(text)
    assert duplicates == ["/a"]
    assert offsets == {"": 0, "/a": text.rindex('"a"'), "/a/x": text.rindex('"x"')}


@pytest.mark.parametrize(
    "text",
    [
        "x = " + "[" * 5000 + "]" * 5000,  # Found by review: RecursionError in tomllib.
        "x = " + "[" * (MAX_DEPTH + 5) + "]" * (MAX_DEPTH + 5),
    ],
    ids=["recursion-error", "beyond-limit"],
)
def test_deep_toml_is_a_value_error(text):
    with pytest.raises(ValueError, match="nested too deeply"):
        from_text("config.toml", text, toml=True)


def test_toml_dates_become_iso_strings():
    # TOML dates reached json.dumps (pin hashes, dumps), which cannot serialize them.
    doc = from_text(
        "c.toml", "a = 1979-05-27T07:32:00Z\nb = 07:32:00\nc = 1979-05-27\n", toml=True
    )
    assert doc.data == {"a": "1979-05-27T07:32:00+00:00", "b": "07:32:00", "c": "1979-05-27"}
