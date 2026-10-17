"""Property-based tests of the configuration and manifest loaders, end to end.

Every supported client layout (JSON, JSONC and Codex TOML) is generated with
random and ill-typed values; malformed files are produced by mutation and from
raw bytes. Loading must never raise, and the documents that load must go
through the whole scan (rules, pinning, every report format, the dump) without
crashing.
"""

import json
import tempfile
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from fuzzing import UNICODE_TEXT, scaled
from mcp_scanner.loader import load_config
from mcp_scanner.manifest import dump_inventories, load_manifest
from mcp_scanner.reporters import json_report, sarif, table
from mcp_scanner.scanner import ScanOptions, run_scan

NAMES = UNICODE_TEXT.filter(bool) | st.sampled_from(["github", "fs", "a/b", "~0", "x" * 300])
SCALARS = (
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | UNICODE_TEXT
)
JUNK = st.recursive(
    SCALARS,
    lambda children: st.lists(children, max_size=3) | st.dictionaries(NAMES, children, max_size=3),
    max_leaves=8,
)
WORDS = st.sampled_from(
    ["npx", "uvx", "docker", "sh", "-c", "--token", "run", "${HOME}", "${input:key}", "@x/y"]
)
STRINGS = WORDS | UNICODE_TEXT
URLS = st.sampled_from(
    ["https://example.com/mcp", "http://10.0.0.5/sse", "https://u:p4ss@h/x?token=abc12345"]
) | UNICODE_TEXT.map(lambda text: "https://example.com/" + text)

ENTRY = st.fixed_dictionaries(
    {},
    optional={
        "command": STRINGS | st.lists(STRINGS, max_size=3) | JUNK,
        "args": st.lists(STRINGS, max_size=5) | JUNK,
        "env": st.dictionaries(NAMES, STRINGS, max_size=3) | JUNK,
        "url": URLS | JUNK,
        "serverUrl": URLS,
        "httpUrl": URLS,
        "type": st.sampled_from(["stdio", "http", "sse", "streamable-http", "remote"]) | JUNK,
        "transport": STRINGS,
        "headers": st.dictionaries(NAMES, STRINGS, max_size=3) | JUNK,
        "http_headers": st.dictionaries(NAMES, STRINGS, max_size=2),
        "cwd": STRINGS | JUNK,
        "disabled": st.booleans(),
    },
)
SERVERS = st.dictionaries(NAMES, ENTRY | JUNK, max_size=4)

# (file name inside the client directory, top-level layout)
LAYOUTS = [
    ("claude_desktop_config.json", lambda servers: {"mcpServers": servers}),
    (".mcp.json", lambda servers: {"mcpServers": servers}),
    (".claude.json", lambda servers: {"projects": {"/work/app": {"mcpServers": servers}}}),
    (".cursor/mcp.json", lambda servers: {"mcpServers": servers}),
    (".vscode/mcp.json", lambda servers: {"servers": servers, "inputs": []}),
    ("Code/User/settings.json", lambda servers: {"mcp": {"servers": servers}}),
    ("zed/settings.json", lambda servers: {"context_servers": servers}),
    ("cline_mcp_settings.json", lambda servers: {"mcpServers": servers}),
    (".gemini/settings.json", lambda servers: {"mcpServers": servers}),
]


def _toml_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(v) for v in value if v is not None) + "]"
    if isinstance(value, dict):
        items = (f"{json.dumps(k)} = {_toml_value(v)}" for k, v in value.items() if v is not None)
        return "{" + ", ".join(items) + "}"
    return '""'  # TOML has no null.


def _codex(servers: dict, date: bool) -> str:
    lines = ['model = "o3"']
    for name, entry in servers.items():
        lines.append(f"[mcp_servers.{json.dumps(name)}]")
        if isinstance(entry, dict):
            lines.extend(f"{json.dumps(k)} = {_toml_value(v)}" for k, v in entry.items())
        if date:
            lines.append("approved = 1979-05-27T07:32:00Z")
    return "\n".join(lines) + "\n"


def _scan(path: Path, folder: Path, *, manifests=()) -> None:
    """Scan ``path`` with pinning, render every format and dump the inventories."""
    options = ScanOptions(
        configs=[str(path)] if path else [],
        tool_manifests=list(manifests),
        pins=folder / "pins.json",
    )
    for _ in range(2):  # The second run compares with the pins written by the first.
        report = run_scan(options)
        for render in (table.render, json_report.render, sarif.render):
            render(report, root=folder)
        dump = folder / "dump.json"
        dump_inventories(report.inventories, dump)
        reloaded, notices = load_manifest(str(dump))
        assert [inv.server for inv in reloaded] == [inv.server for inv in report.inventories]
        assert not [n for n in notices if n.level == "error"]


@scaled(0.5)
@given(st.sampled_from(LAYOUTS), SERVERS, st.booleans(), st.booleans())
def test_every_json_layout_loads_and_scans(layout, servers, ascii_only, jsonc):
    name, wrap = layout
    text = json.dumps(wrap(servers), indent=2, ensure_ascii=ascii_only)
    if jsonc:
        text = "// generated\n" + text.replace("\n", " /* c */\n", 1)
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        path = folder / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", errors="surrogatepass")
        result = load_config(path)
        assert len(result.documents) <= 1
        if result.documents:
            _scan(path, folder)


@scaled(0.5)
@given(SERVERS, st.booleans())
def test_codex_toml_loads_and_scans(servers, date):
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        path = folder / ".codex" / "config.toml"
        path.parent.mkdir()
        path.write_text(_codex(servers, date), encoding="utf-8", errors="surrogatepass")
        result = load_config(path)
        assert all(n.level != "error" or "cannot parse" in n.message for n in result.notices)
        if result.documents:
            _scan(path, folder)


@given(st.sampled_from([name for name, _ in LAYOUTS] + [".codex/config.toml"]), st.binary())
def test_arbitrary_bytes_yield_a_clean_notice(name, data):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        result = load_config(path)
        assert result.documents or any(n.level == "error" for n in result.notices)


@given(st.sampled_from(LAYOUTS), SERVERS, st.data())
def test_mutated_configs_yield_a_clean_notice(layout, servers, data):
    name, wrap = layout
    text = json.dumps(wrap(servers))
    for _ in range(data.draw(st.integers(1, 4))):
        index = data.draw(st.integers(0, len(text)))
        text = text[:index] + data.draw(st.text(max_size=3)) + text[index + 1 :]
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", errors="surrogatepass")
        load_config(path)


TOOLS = st.lists(
    st.fixed_dictionaries(
        {"name": NAMES},
        optional={
            "description": STRINGS,
            "title": STRINGS | JUNK,
            "inputSchema": st.fixed_dictionaries(
                {"type": st.just("object")},
                optional={"properties": st.dictionaries(NAMES, JUNK, max_size=3)},
            )
            | JUNK,
            "annotations": JUNK,
        },
    )
    | JUNK,
    max_size=3,
)
INVENTORY = st.fixed_dictionaries(
    {"tools": TOOLS | JUNK},
    optional={
        "instructions": STRINGS | JUNK,
        "serverInfo": JUNK,
        "prompts": st.lists(
            st.fixed_dictionaries({"name": NAMES}, optional={"description": STRINGS}) | JUNK,
            max_size=2,
        )
        | JUNK,
        "resources": st.lists(
            st.fixed_dictionaries({"uri": URLS | STRINGS}, optional={"name": STRINGS}) | JUNK,
            max_size=2,
        )
        | JUNK,
        "resourceTemplates": st.lists(
            st.fixed_dictionaries({"uriTemplate": STRINGS}) | JUNK, max_size=2
        ),
    },
)
MANIFESTS = (
    st.dictionaries(NAMES, INVENTORY | TOOLS | JUNK, max_size=3).map(lambda s: {"servers": s})
    | INVENTORY
    | INVENTORY.map(lambda inv: {"jsonrpc": "2.0", "id": 1, "result": inv})
    | TOOLS
    | JUNK
)


@scaled(0.5)
@given(MANIFESTS, st.booleans())
def test_manifests_load_and_scan(manifest, ascii_only):
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        path = folder / "tools.json"
        text = json.dumps(manifest, ensure_ascii=ascii_only)
        path.write_text(text, encoding="utf-8", errors="surrogatepass")
        inventories, _ = load_manifest(str(path))
        if inventories:
            _scan(None, folder, manifests=[str(path)])


# --------------------------------------------------------------------------- regressions


def test_lone_surrogates_survive_the_whole_scan(tmp_path):
    # Found by fuzzing: a JSON escape such as "\ud800" in a server or tool name made
    # Finding.fingerprint, the pin digests and every file writer raise
    # UnicodeEncodeError, so a hostile server could abort the scan.
    surrogate = chr(0xD800)
    config = tmp_path / "claude_desktop_config.json"
    config.write_text(
        json.dumps({"mcpServers": {surrogate: {"command": "npx", "args": ["x" + surrogate]}}}),
        encoding="utf-8",
    )
    tools = tmp_path / "tools.json"
    tool = {"name": "t" + surrogate, "description": "Reads " + surrogate}
    tools.write_text(json.dumps({"servers": {surrogate: {"tools": [tool]}}}), encoding="utf-8")
    options = ScanOptions(
        configs=[str(config)], tool_manifests=[str(tools)], pins=tmp_path / "pins.json"
    )
    report = run_scan(options)
    assert report.findings and not report.notices
    assert "\\ud800" in (tmp_path / "pins.json").read_text(encoding="utf-8")
    dump_inventories(report.inventories, tmp_path / "dump.json")
    (inventory,), _ = load_manifest(str(tmp_path / "dump.json"))
    assert inventory.server == surrogate and inventory.tools[0].raw == tool
    again = run_scan(options)  # The pins written above read back unchanged.
    assert not [f for f in again.findings if f.rule.id.startswith("MCPS4")]
