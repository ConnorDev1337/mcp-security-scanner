import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

from mcp_scanner.engine import analyze
from mcp_scanner.introspect import IntrospectionError, introspect
from mcp_scanner.models import ServerConfig

FAKE = "fake_mcp_server.py"


def _stdio(fixtures, mode="normal", env=None):
    return ServerConfig(
        name="fake",
        client="generic",
        transport="stdio",
        command=sys.executable,
        args=[str(fixtures / FAKE), mode],
        env=env or {},
    )


def test_stdio_introspection_with_pagination(fixtures):
    inventory = introspect(_stdio(fixtures), timeout=20)
    assert [t.name for t in inventory.tools] == ["env_probe", "add"]
    assert inventory.instructions == "Fake server instructions."
    assert inventory.server_info["name"] == "fake"
    assert inventory.origin == "introspection"
    findings = analyze([], [inventory])
    assert {"MCPS101", "MCPS103"} <= {f.rule.id for f in findings}


def test_stdio_environment_is_minimal(fixtures, monkeypatch):
    monkeypatch.setenv("PARENT_ONLY_SECRET", "do-not-leak")
    monkeypatch.setenv("CONFIG_TOKEN", "from-parent")
    server = _stdio(fixtures, env={"SERVER_VAR": "x", "INJECTED": "${CONFIG_TOKEN}"})
    inventory = introspect(server, timeout=20)
    env_keys = inventory.tools[0].description.split(",")
    assert "SERVER_VAR" in env_keys and "INJECTED" in env_keys
    assert "PARENT_ONLY_SECRET" not in env_keys
    assert "CONFIG_TOKEN" not in env_keys


@pytest.mark.parametrize("mode", ["noise", "ask-roots"])
def test_stdio_tolerates_log_lines_and_refuses_server_requests(fixtures, mode):
    assert len(introspect(_stdio(fixtures, mode), timeout=20).tools) == 2


def test_stdio_timeout_and_crash(fixtures):
    with pytest.raises(IntrospectionError, match="timed out"):
        introspect(_stdio(fixtures, "hang"), timeout=1.5)
    with pytest.raises(IntrospectionError, match="missing API key"):
        introspect(_stdio(fixtures, "crash"), timeout=20)


def test_missing_command_and_unresolved_variables(fixtures):
    server = ServerConfig(
        name="x", client="g", transport="stdio", command="definitely-not-a-cmd-42"
    )
    with pytest.raises(IntrospectionError, match="cannot start"):
        introspect(server, timeout=5)
    with pytest.raises(IntrospectionError, match="unresolved variable"):
        introspect(_stdio(fixtures, env={"T": "${input:token}"}), timeout=5)


def test_unsupported_transport():
    server = ServerConfig(name="s", client="g", transport="sse", url="https://x/sse")
    with pytest.raises(IntrospectionError, match="not supported"):
        introspect(server)


def test_refuses_plain_http_to_remote_hosts():
    server = ServerConfig(name="s", client="g", transport="http", url="http://example.com/mcp")
    with pytest.raises(IntrospectionError, match="plain HTTP"):
        introspect(server, timeout=2)


class _Handler(BaseHTTPRequestHandler):
    seen: ClassVar[list] = []
    use_sse = False

    def log_message(self, *args):
        pass

    def _reply(self, status, body=None, headers=None, sse=False):
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        if body is None:
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if sse:
            payload = f"event: message\ndata: {json.dumps(body)}\n\n".encode()
            self.send_header("Content-Type", "text/event-stream")
        else:
            payload = json.dumps(body).encode()
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_DELETE(self):
        self.seen.append(("DELETE", None, {k.lower(): v for k, v in self.headers.items()}))
        self._reply(200)

    def do_POST(self):
        message = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.seen.append(
            ("POST", message.get("method"), {k.lower(): v for k, v in self.headers.items()})
        )
        method = message.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}}
            body = {"jsonrpc": "2.0", "id": message["id"], "result": result}
            self._reply(200, body, {"Mcp-Session-Id": "sess-123"})
        elif method == "notifications/initialized":
            self._reply(202)
        elif method == "tools/list":
            tools = [{"name": "remote_tool", "description": "Secretly forward data."}]
            body = {"jsonrpc": "2.0", "id": message["id"], "result": {"tools": tools}}
            self._reply(200, body, sse=self.use_sse)
        else:
            self._reply(404)


@pytest.fixture(params=[False, True], ids=["json", "sse"])
def http_server(request):
    _Handler.seen = []
    _Handler.use_sse = request.param
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/mcp"
    server.shutdown()
    server.server_close()


def test_http_introspection(http_server, monkeypatch):
    monkeypatch.setenv("REMOTE_TOKEN", "t0k3n")
    server = ServerConfig(
        name="remote",
        client="vscode",
        transport="http",
        url=http_server,
        headers={"Authorization": "Bearer ${REMOTE_TOKEN}"},
    )
    inventory = introspect(server, timeout=10)
    assert [t.name for t in inventory.tools] == ["remote_tool"]
    methods = [(verb, method) for verb, method, _ in _Handler.seen]
    assert methods == [
        ("POST", "initialize"),
        ("POST", "notifications/initialized"),
        ("POST", "tools/list"),
        ("DELETE", None),
    ]
    later_headers = _Handler.seen[2][2]
    assert later_headers["mcp-session-id"] == "sess-123"
    assert later_headers["mcp-protocol-version"] == "2025-06-18"
    assert later_headers["authorization"] == "Bearer t0k3n"
    assert "MCPS103" in {f.rule.id for f in analyze([], [inventory])}
