import pytest

from mcp_scanner.jsonloc import JSONLocError, from_text, parse

TEXT = """{
  // comment
  "mcpServers": {
    "a": {"command": "npx", "args": ["-y", "pkg"]},
    /* block
       comment */
    "b": {
      "url": "https://example.com/mcp",
    },
  },
}
"""


def test_parses_jsonc_with_positions():
    doc = from_text("cfg.json", TEXT)
    assert doc.data["mcpServers"]["a"]["args"] == ["-y", "pkg"]
    assert doc.locate("/mcpServers/a").line == 4
    assert doc.locate("/mcpServers/b/url").line == 8
    assert doc.locate("/mcpServers/a/args/1").line == 4
    # Unknown pointers fall back to the closest existing ancestor.
    assert doc.locate("/mcpServers/b/headers/x").line == 7


def test_matches_stdlib_on_plain_json():
    import json

    text = '{"x": [1, 2.5, -3e2, true, false, null, "\\u00e9\\n"], "y": {}}'
    value, _, _ = parse(text)
    assert value == json.loads(text)


def test_records_duplicate_keys_and_points_at_last_definition():
    text = '{\n "mcpServers": {\n  "s": {"command": "safe"},\n  "s": {"command": "evil"}\n }\n}'
    doc = from_text("dup.json", text)
    assert doc.data["mcpServers"]["s"]["command"] == "evil"
    assert doc.duplicates == ["/mcpServers/s"]
    assert doc.locate("/mcpServers/s").line == 4
    assert doc.locate("/mcpServers/s/command").line == 4


def test_pointer_escaping():
    doc = from_text("p.json", '{"a/b": {"c~d": 1}}')
    assert doc.locate("/a~1b/c~0d").column == 10


@pytest.mark.parametrize(
    "text",
    ['{"a": }', '{"a": 1', '{"a" 1}', '["unterminated]', "{} extra", '{"a": tru}', "/* x"],
)
def test_reports_errors_with_position(text):
    with pytest.raises(JSONLocError) as info:
        parse(text)
    assert info.value.line >= 1


def test_strips_bom():
    doc = from_text("bom.json", '\ufeff{"a": 1}')
    assert doc.data == {"a": 1}


def test_toml_document_uses_hint_for_location():
    doc = from_text("config.toml", '[mcp_servers.github]\ncommand = "npx"\n', toml=True)
    assert doc.data["mcp_servers"]["github"]["command"] == "npx"
    assert doc.locate("/mcp_servers/github", hint="github").line == 1
