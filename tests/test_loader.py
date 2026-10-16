from pathlib import Path

import pytest

from mcp_scanner.loader import (
    UnresolvedVariable,
    candidate_paths,
    discover,
    expand_vars,
    guess_client,
    load_config,
    load_configs,
)


def test_claude_desktop_config(write_json):
    path = write_json(
        "claude_desktop_config.json",
        {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    "env": {"DEBUG": 1},
                }
            }
        },
    )
    result = load_config(path)
    assert not [n for n in result.notices if n.level == "error"]
    (server,) = result.servers
    assert server.client == "claude-desktop"
    assert server.transport == "stdio"
    assert server.command == "npx"
    assert server.args[-1] == "/tmp"
    assert server.env == {"DEBUG": "1"}
    assert server.locate("args", 2).line is not None


def test_vscode_mcp_json_with_comments(write_json):
    raw = """{
  // VS Code workspace MCP config
  "inputs": [{"type": "promptString", "id": "token", "password": true}],
  "servers": {
    "github": {"type": "http", "url": "https://api.githubcopilot.com/mcp/",
               "headers": {"Authorization": "Bearer ${input:token}"}},
    "local": {"type": "stdio", "command": "uvx", "args": ["mcp-server-git"]},
  }
}"""
    path = write_json(".vscode/mcp.json", None, raw=raw)
    result = load_config(path)
    names = {s.name: s for s in result.servers}
    assert set(names) == {"github", "local"}
    assert names["github"].client == "vscode"
    assert names["github"].transport == "http"
    assert names["github"].headers["Authorization"].startswith("Bearer ${input:")
    assert names["local"].locate().line == 7


def test_vscode_settings_nested_mcp(write_json):
    path = write_json(
        "Code/User/settings.json",
        {"editor.fontSize": 12, "mcp": {"servers": {"x": {"command": "node", "args": ["s.js"]}}}},
    )
    result = load_config(path)
    assert [s.name for s in result.servers] == ["x"]
    assert result.servers[0].client == "vscode"


def test_claude_code_user_and_project_scopes(write_json):
    path = write_json(
        ".claude.json",
        {
            "mcpServers": {"global": {"type": "stdio", "command": "npx", "args": ["a"]}},
            "projects": {
                "/home/u/repo": {"mcpServers": {"proj": {"type": "sse", "url": "http://x/sse"}}}
            },
        },
    )
    result = load_config(path)
    by_name = {s.name: s for s in result.servers}
    assert by_name["global"].scope is None
    assert by_name["proj"].scope == "/home/u/repo"
    assert by_name["proj"].transport == "sse"
    assert by_name["proj"].pointer == "/projects/~1home~1u~1repo/mcpServers/proj"


def test_zed_legacy_command_object(write_json):
    path = write_json(
        "zed/settings.json",
        {
            "context_servers": {
                "z": {"command": {"path": "/usr/bin/node", "args": ["srv.js"], "env": {"A": "b"}}}
            }
        },
    )
    (server,) = load_config(path).servers
    assert server.client == "zed"
    assert server.command == "/usr/bin/node"
    assert server.args == ["srv.js"]
    assert server.env == {"A": "b"}


def test_codex_toml(write_json):
    path = write_json(
        ".codex/config.toml",
        None,
        raw='model = "o3"\n\n[mcp_servers.docs]\ncommand = "uvx"\nargs = ["docs-mcp"]\n'
        '[mcp_servers.docs.env]\nTOKEN = "abc"\n',
    )
    (server,) = load_config(path).servers
    assert server.client == "codex"
    assert server.env == {"TOKEN": "abc"}
    assert server.locate("env", "TOKEN").line == 3


def test_windsurf_server_url_and_gemini_http_url(write_json):
    ws = write_json("mcp_config.json", {"mcpServers": {"r": {"serverUrl": "https://h/mcp"}}})
    gm = write_json(".gemini/settings.json", {"mcpServers": {"g": {"httpUrl": "https://h/mcp"}}})
    result = load_configs([ws, gm])
    assert [(s.client, s.transport, s.url) for s in result.servers] == [
        ("windsurf", "http", "https://h/mcp"),
        ("gemini-cli", "http", "https://h/mcp"),
    ]


def test_errors_are_notices_not_exceptions(write_json, tmp_path):
    bad = write_json("bad.json", None, raw='{"mcpServers": {')
    result = load_configs([bad, tmp_path / "missing.json", bad])
    assert [n.level for n in result.notices] == ["error", "error"]
    assert result.servers == []


def test_non_object_entries_and_empty_documents(write_json):
    path = write_json("x.json", {"mcpServers": {"bad": "npx foo"}})
    result = load_config(path)
    assert result.servers == []
    assert "not an object" in result.notices[0].message
    empty = load_config(write_json("y.json", {"unrelated": True}))
    assert "no MCP server definitions" in empty.notices[0].message


@pytest.mark.parametrize(
    ("relative", "data", "expected"),
    [
        ("a/.cursor/mcp.json", {"mcpServers": {}}, "cursor"),
        ("cline_mcp_settings.json", {"mcpServers": {}}, "cline"),
        ("whatever.json", {"mcpServers": {}}, "generic"),
        ("whatever.json", {"servers": {}}, "vscode"),
        (".aws/amazonq/mcp.json", {"mcpServers": {}}, "amazon-q"),
    ],
)
def test_guess_client(relative, data, expected):
    assert guess_client(Path(relative), data) == expected


def test_discovery_finds_existing_files(tmp_path):
    home, cwd = tmp_path / "home", tmp_path / "repo"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_text("{}")
    cwd.mkdir()
    (cwd / ".mcp.json").write_text("{}")
    found = discover(home=home, cwd=cwd, environ={}, system="Linux")
    assert [(c, p.name) for c, p in found] == [
        ("claude-code", ".mcp.json"),
        ("cursor", "mcp.json"),
    ]


@pytest.mark.parametrize("system", ["Windows", "Darwin", "Linux"])
def test_candidate_paths_cover_main_clients(tmp_path, system):
    clients = {c for c, _ in candidate_paths(tmp_path, tmp_path, {}, system)}
    assert {"claude-desktop", "claude-code", "cursor", "vscode", "windsurf", "zed"} <= clients


def test_expand_vars():
    env = {"HOME": "/h", "TOKEN": "t"}
    assert expand_vars("${HOME}/x", env) == "/h/x"
    assert expand_vars("Bearer ${env:TOKEN}", env) == "Bearer t"
    assert expand_vars("${MISSING:-fallback}", env) == "fallback"
    with pytest.raises(UnresolvedVariable):
        expand_vars("${MISSING}", env)
    with pytest.raises(UnresolvedVariable):
        expand_vars("${input:token}", env)
