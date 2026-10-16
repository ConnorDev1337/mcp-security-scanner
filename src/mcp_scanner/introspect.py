"""Opt-in live enumeration of tools, prompts and resources over stdio or Streamable HTTP.

WARNING: introspecting a stdio server EXECUTES its configured command with the
caller's privileges. Only introspect servers you would run anyway, ideally in a
container or VM, and prefer offline manifests (``--tools``).

Only listing methods are called: ``tools/list``, plus ``prompts/list``,
``resources/list`` and ``resources/templates/list`` when the server advertises
the matching capability. ``prompts/get`` and ``resources/read`` are never
called, so no prompt messages or resource contents are fetched.

Hardening:

* stdio servers inherit only a minimal environment (PATH, HOME, temp dirs, ...)
  plus the variables from their own configuration;
* requests from the server (sampling, roots, elicitation) are refused;
* HTTP redirects are not followed, and plain ``http://`` is refused for
  non-loopback hosts because configured headers often carry credentials;
* each session has a single deadline, and the server process tree is killed if
  it does not exit on its own.
"""

from __future__ import annotations

import collections
import json
import os
import queue
import shutil
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlsplit

from . import TOOL_NAME, __version__
from .loader import UnresolvedVariable, expand_vars
from .models import (
    Location,
    Notice,
    PromptDefinition,
    ResourceDefinition,
    ServerConfig,
    ServerInventory,
    ToolDefinition,
)
from .rules.config import is_loopback
from .textutil import sanitize

PROTOCOL_VERSION = "2025-06-18"
MAX_PAGES = 100  # Upper bound on pages per list method and server.
METHOD_NOT_FOUND = -32601  # JSON-RPC error code.
# Optional listings: (inventory attribute, capability, method, result key, required item key).
FEATURES = (
    ("prompts", "prompts", "prompts/list", "prompts", "name"),
    ("resources", "resources", "resources/list", "resources", "uri"),
    (
        "resource_templates",
        "resources",
        "resources/templates/list",
        "resourceTemplates",
        "uriTemplate",
    ),
)
MAX_BODY = 32 * 1024 * 1024  # Maximum bytes read from a JSON (non-SSE) HTTP response.
# Inherited variables needed to start a process; everything else must come from
# the server's own configuration.
SAFE_ENV_KEYS = frozenset(
    {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "SYSTEMDRIVE",
        "TEMP",
        "TMP",
        "TMPDIR",
        "HOME",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "USER",
        "USERNAME",
        "LOGNAME",
        "SHELL",
        "XDG_RUNTIME_DIR",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
    }
)


class IntrospectionError(Exception):
    """Live introspection of a server failed.

    ``code`` is the JSON-RPC error code when the server answered with an error.
    """

    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


def _rpc_error(method: str, error: Any) -> IntrospectionError:
    code = error.get("code") if isinstance(error, dict) else None
    return IntrospectionError(
        f"{method} failed: {sanitize(json.dumps(error), 300)}",
        code if isinstance(code, int) else None,
    )


def _initialize_params() -> dict[str, Any]:
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": TOOL_NAME, "version": __version__},
    }


def _expand(value: str, environ: Mapping[str, str]) -> str:
    try:
        return expand_vars(value, environ)
    except UnresolvedVariable as exc:
        raise IntrospectionError(
            f"unresolved variable {exc.args[0]!r} (needs environment or interactive input)"
        ) from None


def build_env(server: ServerConfig, environ: Mapping[str, str]) -> dict[str, str]:
    """Return the stdio server environment: safe inherited variables plus its own.

    Raise :class:`IntrospectionError` if a configured value cannot be expanded.
    """
    env = {k: v for k, v in environ.items() if k.upper() in SAFE_ENV_KEYS}
    for key, value in server.env.items():
        env[key] = _expand(value, environ)
    return env


Request = Callable[[str, dict[str, Any]], dict[str, Any]]


def _list_all(request: Request, method: str, key: str, required: str) -> list[dict[str, Any]]:
    """Fetch every page of a paginated list ``method``; keep items with a string ``required``."""
    items: list[dict[str, Any]] = []
    cursor = None
    for _ in range(MAX_PAGES):
        result = request(method, {"cursor": cursor} if cursor else {})
        page = result.get(key, [])
        if isinstance(page, list):
            items.extend(
                i for i in page if isinstance(i, dict) and isinstance(i.get(required), str)
            )
        cursor = result.get("nextCursor")
        if not cursor or not isinstance(cursor, str):
            break
    return items


def _collect(request: Request, init: dict[str, Any]) -> list[dict[str, Any]]:
    """Fetch every ``tools/list`` page, unless the server does not advertise tools."""
    capabilities = init.get("capabilities")
    if isinstance(capabilities, dict) and "tools" not in capabilities:
        return []
    return _list_all(request, "tools/list", "tools", "name")


def _collect_features(
    request: Request, init: dict[str, Any]
) -> tuple[dict[str, list[dict[str, Any]] | None], list[str]]:
    """List the prompts, resources and resource templates that the server advertises.

    Return the items per inventory attribute and a list of warnings. A missing
    capability means the server declares none (``[]``). A failed listing leaves
    that kind uncollected (``None``) with a warning instead of failing the whole
    introspection, so the tools already fetched are still analyzed.
    """
    capabilities = init.get("capabilities")
    collected: dict[str, list[dict[str, Any]] | None] = {}
    warnings: list[str] = []
    for attr, capability, method, key, required in FEATURES:
        if not isinstance(capabilities, dict):
            collected[attr] = None  # Nothing advertised at all: unknown, not "none".
        elif capability not in capabilities:
            collected[attr] = []
        else:
            try:
                collected[attr] = _list_all(request, method, key, required)
            except IntrospectionError as exc:
                if exc.code == METHOD_NOT_FOUND:
                    # Common for resources/templates/list; clients cannot list them either.
                    collected[attr] = []
                else:
                    collected[attr] = None
                    warnings.append(f"{exc} ({attr.replace('_', ' ')} not analyzed)")
    return collected, warnings


def _enumerate(
    request: Request, init: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]] | None], list[str]]:
    """Run every listing method within the session's single deadline."""
    tools = _collect(request, init)
    features, warnings = _collect_features(request, init)
    return tools, features, warnings


def _resources(
    items: list[dict[str, Any]] | None, location: Location, *, template: bool
) -> list[ResourceDefinition] | None:
    if items is None:
        return None
    return [
        ResourceDefinition(
            i["name"] if isinstance(i.get("name"), str) else "",
            i,
            fallback=location,
            template=template,
        )
        for i in items
    ]


def _inventory(
    server: ServerConfig,
    init: dict[str, Any],
    listing: tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]] | None], list[str]],
) -> ServerInventory:
    tools, features, warnings = listing
    location = server.locate()
    instructions = init.get("instructions")
    info = init.get("serverInfo")
    prompts = features.get("prompts")
    return ServerInventory(
        server=server.name,
        tools=[ToolDefinition(t["name"], t, fallback=location) for t in tools],
        instructions=instructions if isinstance(instructions, str) else None,
        server_info=info if isinstance(info, dict) else {},
        origin="introspection",
        fallback=location,
        prompts=None
        if prompts is None
        else [PromptDefinition(p["name"], p, fallback=location) for p in prompts],
        resources=_resources(features.get("resources"), location, template=False),
        resource_templates=_resources(features.get("resource_templates"), location, template=True),
        notices=[Notice("warning", f"{server.name}: {w}", location.path) for w in warnings],
    )


# --------------------------------------------------------------------------- stdio


class _StdioSession:
    """Newline-delimited JSON-RPC session over a child process's stdin and stdout."""

    def __init__(self, proc: subprocess.Popen[bytes], deadline: float) -> None:
        self.proc = proc
        self.deadline = deadline
        self.lines: queue.Queue[bytes | None] = queue.Queue()
        self.stderr: collections.deque[str] = collections.deque(maxlen=20)
        self.next_id = 0
        threading.Thread(target=self._pump_stdout, daemon=True).start()
        threading.Thread(target=self._pump_stderr, daemon=True).start()

    def _pump_stdout(self) -> None:
        for line in self.proc.stdout or ():
            self.lines.put(line)
        self.lines.put(None)

    def _pump_stderr(self) -> None:
        for line in self.proc.stderr or ():
            self.stderr.append(line.decode("utf-8", "replace").rstrip())

    def _tail(self) -> str:
        tail = " / ".join(list(self.stderr)[-3:])
        return f" (stderr: {sanitize(tail, 300)})" if tail else ""

    def send(self, message: dict[str, Any]) -> None:
        if self.proc.stdin is None:
            raise IntrospectionError("server input is not available")
        try:
            self.proc.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
            self.proc.stdin.flush()
        except OSError as exc:
            raise IntrospectionError(f"server closed its input: {exc}{self._tail()}") from None

    def notify(self, method: str) -> None:
        self.send({"jsonrpc": "2.0", "method": method})

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.next_id += 1
        request_id = self.next_id
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        while True:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise IntrospectionError(f"timed out waiting for {method}{self._tail()}")
            try:
                line = self.lines.get(timeout=remaining)
            except queue.Empty:
                raise IntrospectionError(f"timed out waiting for {method}{self._tail()}") from None
            if line is None:
                raise IntrospectionError(f"server exited before answering {method}{self._tail()}")
            try:
                message = json.loads(line)
            except ValueError:
                continue  # Non-JSON log output on stdout.
            if not isinstance(message, dict):
                continue
            if "method" in message and "id" in message:  # Server-initiated request.
                self._refuse(message)
                continue
            if message.get("id") != request_id:
                continue
            if "error" in message:
                raise _rpc_error(method, message["error"])
            result = message.get("result")
            if not isinstance(result, dict):
                raise IntrospectionError(f"{method} returned an invalid result")
            return result

    def _refuse(self, message: dict[str, Any]) -> None:
        """Answer pings and refuse every other server-initiated request."""
        if message.get("method") == "ping":
            self.send({"jsonrpc": "2.0", "id": message["id"], "result": {}})
        else:
            error = {"code": -32601, "message": "Method not supported by scanner"}
            self.send({"jsonrpc": "2.0", "id": message["id"], "error": error})

    def close(self) -> None:
        """Close stdin, then kill the process tree if the server does not exit."""
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            pass
        if os.name == "nt":
            subprocess.run(  # noqa: S603 - fixed argv, kills the process tree we started
                ["taskkill", "/F", "/T", "/PID", str(self.proc.pid)],  # noqa: S607
                capture_output=True,
                check=False,
            )
        else:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                self.proc.kill()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def _introspect_stdio(
    server: ServerConfig, timeout: float, environ: Mapping[str, str]
) -> ServerInventory:
    if not server.command:
        raise IntrospectionError("no command configured")
    env = build_env(server, environ)
    command = _expand(server.command, environ)
    args = [_expand(a, environ) for a in server.args]
    # Resolve against the server's PATH; on Windows this also finds .cmd/.bat shims.
    executable = shutil.which(command, path=env.get("PATH")) or command
    cwd = _expand(server.cwd, environ) if server.cwd else None
    # A separate process group/session lets close() kill the whole process tree.
    kwargs: dict[str, Any] = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    else:
        kwargs["start_new_session"] = True
    try:
        proc = subprocess.Popen(  # noqa: S603 - executing the server is the point of --introspect
            [executable, *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=cwd,
            **kwargs,
        )
    except OSError as exc:
        raise IntrospectionError(f"cannot start {command!r}: {exc}") from None
    session = _StdioSession(proc, time.monotonic() + timeout)
    try:
        init = session.request("initialize", _initialize_params())
        session.notify("notifications/initialized")
        listing = _enumerate(session.request, init)
    finally:
        session.close()
    return _inventory(server, init, listing)


# --------------------------------------------------------------------------- Streamable HTTP


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so configured credentials are never sent to another URL."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # urllib then raises HTTPError for the 3xx response.


class _HttpSession:
    """Streamable HTTP session: JSON-RPC over POST, answered with JSON or SSE."""

    def __init__(self, url: str, headers: dict[str, str], deadline: float) -> None:
        self.url = url
        self.headers = headers
        self.deadline = deadline
        self.opener = urllib.request.build_opener(_NoRedirect)
        self.session_id: str | None = None
        self.protocol: str | None = None
        self.next_id = 0

    def _remaining(self, what: str) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise IntrospectionError(f"timed out waiting for {what}")
        return remaining

    def _open(self, method: str, payload: dict[str, Any] | None, what: str) -> Any:
        headers = {"Accept": "application/json, text/event-stream", **self.headers}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.protocol:
            headers["MCP-Protocol-Version"] = self.protocol
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(  # noqa: S310 - scheme checked by _introspect_http
            self.url,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            response = self.opener.open(request, timeout=self._remaining(what))
        except urllib.error.HTTPError as exc:
            raise IntrospectionError(f"{what}: HTTP {exc.code} {exc.reason}") from None
        except (urllib.error.URLError, OSError) as exc:
            raise IntrospectionError(f"{what}: cannot reach server ({exc})") from None
        session_id = response.headers.get("Mcp-Session-Id")
        if session_id:
            self.session_id = session_id
        return response

    def notify(self, method: str) -> None:
        with self._open("POST", {"jsonrpc": "2.0", "method": method}, method):
            pass

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.next_id += 1
        payload = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params}
        with self._open("POST", payload, method) as response:
            content_type = response.headers.get("Content-Type", "")
            if "text/event-stream" in content_type:
                message = self._read_sse(response, self.next_id, method)
            else:
                try:
                    body = json.loads(response.read(MAX_BODY) or b"null")
                except ValueError:
                    raise IntrospectionError(f"{method}: invalid JSON response") from None
                candidates = body if isinstance(body, list) else [body]
                message = next(
                    (m for m in candidates if isinstance(m, dict) and m.get("id") == self.next_id),
                    None,
                )
        if not isinstance(message, dict):
            raise IntrospectionError(f"{method}: no response from server")
        if "error" in message:
            raise _rpc_error(method, message["error"])
        result = message.get("result")
        if not isinstance(result, dict):
            raise IntrospectionError(f"{method} returned an invalid result")
        return result

    def _read_sse(self, response: Any, request_id: int, what: str) -> dict[str, Any] | None:
        """Return the message answering ``request_id`` from an SSE stream, if any."""
        data: list[str] = []
        for raw in response:
            self._remaining(what)
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line.startswith("data:"):
                data.append(line[5:].removeprefix(" "))
            elif not line and data:
                try:
                    message = json.loads("\n".join(data))
                except ValueError:
                    message = None
                data = []
                if isinstance(message, dict) and message.get("id") == request_id:
                    return message
        return None

    def close(self) -> None:
        """Terminate the server-side session, if any (best effort)."""
        if not self.session_id:
            return
        try:
            with self._open("DELETE", None, "session termination"):
                pass
        except IntrospectionError:
            pass


def _introspect_http(
    server: ServerConfig, timeout: float, environ: Mapping[str, str]
) -> ServerInventory:
    if not server.url:
        raise IntrospectionError("no URL configured")
    url = _expand(server.url, environ)
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise IntrospectionError(f"unsupported URL scheme {parts.scheme!r}")
    if parts.scheme == "http" and not is_loopback(parts.hostname):
        raise IntrospectionError(
            f"refusing to connect to {parts.hostname} over plain HTTP (credentials would leak)"
        )
    headers = {k: _expand(v, environ) for k, v in server.headers.items()}
    session = _HttpSession(url, headers, time.monotonic() + timeout)
    try:
        init = session.request("initialize", _initialize_params())
        version = init.get("protocolVersion")
        session.protocol = version if isinstance(version, str) else PROTOCOL_VERSION
        session.notify("notifications/initialized")
        listing = _enumerate(session.request, init)
    finally:
        session.close()
    return _inventory(server, init, listing)


def introspect(
    server: ServerConfig, timeout: float = 20.0, environ: Mapping[str, str] | None = None
) -> ServerInventory:
    """Fetch the tool, prompt and resource inventory of ``server``; stdio servers are executed.

    Variables in the configuration are expanded from ``environ`` (default:
    ``os.environ``). Raise :class:`IntrospectionError` if the session or
    ``tools/list`` fails, including unsupported transports. Failed prompt and
    resource listings are reported in ``inventory.notices`` instead.
    """
    environ = os.environ if environ is None else environ
    if server.transport == "stdio":
        return _introspect_stdio(server, timeout, environ)
    if server.transport == "http":
        return _introspect_http(server, timeout, environ)
    raise IntrospectionError(
        f"transport {server.transport!r} is not supported for introspection; use --tools"
    )
