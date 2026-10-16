"""Load MCP client configuration files and normalize their server entries.

Supported layouts (all detected by content, the file name only refines the
client label):

* ``mcpServers``            Claude Desktop, Claude Code (.mcp.json), Cursor,
                            Windsurf, Cline/Roo, Gemini CLI, Amazon Q
* ``projects.*.mcpServers`` Claude Code ``~/.claude.json`` (local scope)
* ``servers``               VS Code ``.vscode/mcp.json`` / user ``mcp.json``
* ``mcp.servers``           VS Code ``settings.json``
* ``context_servers``       Zed ``settings.json``
* ``mcp_servers``           OpenAI Codex CLI ``config.toml``
"""

from __future__ import annotations

import os
import platform
import re
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .jsonloc import JSONLocError, SourceDocument, load_document
from .models import Notice, ServerConfig, join_pointer

_TRANSPORTS = {
    "stdio": "stdio",
    "local": "stdio",
    "http": "http",
    "streamable-http": "http",
    "streamable_http": "http",
    "streamablehttp": "http",
    "remote": "http",
    "sse": "sse",
}


class ConfigError(Exception):
    pass


@dataclass
class LoadResult:
    servers: list[ServerConfig] = field(default_factory=list)
    documents: list[SourceDocument] = field(default_factory=list)
    notices: list[Notice] = field(default_factory=list)

    def extend(self, other: LoadResult) -> None:
        self.servers.extend(other.servers)
        self.documents.extend(other.documents)
        self.notices.extend(other.notices)


def guess_client(path: Path, data: Any) -> str:
    name = path.name.lower()
    parts = {p.lower() for p in path.parts}
    keys = set(data) if isinstance(data, dict) else set()
    if name == "claude_desktop_config.json":
        return "claude-desktop"
    if name in {".claude.json", ".mcp.json"}:
        return "claude-code"
    if name == "cline_mcp_settings.json":
        return "cline"
    if name == "mcp_config.json":
        return "windsurf"
    if name == "config.toml" or "mcp_servers" in keys:
        return "codex"
    if name == "mcp.json":
        if ".cursor" in parts:
            return "cursor"
        if ".vscode" in parts or ("code" in parts and "user" in parts) or "servers" in keys:
            return "vscode"
        if "amazonq" in parts:
            return "amazon-q"
    if name == "settings.json":
        if ".gemini" in parts:
            return "gemini-cli"
        if "zed" in parts or "context_servers" in keys:
            return "zed"
        if "mcp" in keys or any(k.startswith(("chat.", "mcp.")) for k in keys):
            return "vscode"
    if "context_servers" in keys:
        return "zed"
    if "servers" in keys and "mcpServers" not in keys:
        return "vscode"
    return "generic"


def _looks_like_servers(mapping: Mapping[str, Any]) -> bool:
    return any(
        isinstance(v, dict) and any(k in v for k in ("command", "url", "type", "serverUrl"))
        for v in mapping.values()
    )


def _containers(data: Any, client: str) -> list[tuple[str, dict[str, Any], str | None]]:
    """Return ``(pointer, mapping, scope)`` for every server map in a document."""
    found: list[tuple[str, dict[str, Any], str | None]] = []
    if not isinstance(data, dict):
        return found
    for key in ("mcpServers", "mcp_servers", "context_servers"):
        if isinstance(data.get(key), dict):
            found.append((join_pointer("", key), data[key], None))
    servers = data.get("servers")
    if isinstance(servers, dict) and (client == "vscode" or _looks_like_servers(servers)):
        found.append(("/servers", servers, None))
    mcp = data.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        found.append(("/mcp/servers", mcp["servers"], None))
    projects = data.get("projects")
    if isinstance(projects, dict):
        for project, cfg in projects.items():
            if isinstance(cfg, dict) and isinstance(cfg.get("mcpServers"), dict):
                pointer = join_pointer("", "projects", project, "mcpServers")
                found.append((pointer, cfg["mcpServers"], project))
    return found


def _stringify(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return "" if value is None else str(value)


def _normalize(
    name: str,
    entry: dict[str, Any],
    pointer: str,
    doc: SourceDocument,
    client: str,
    scope: str | None,
) -> ServerConfig:
    command = entry.get("command")
    args: Any = entry.get("args", [])
    env: Any = entry.get("env", {})
    if isinstance(command, dict):  # Zed legacy: {"command": {"path", "args", "env"}}
        args = command.get("args", args)
        env = command.get("env", env)
        command = command.get("path")
    if isinstance(command, list):  # some tools store the whole argv
        args = command[1:] + (args if isinstance(args, list) else [])
        command = command[0] if command else None
    if isinstance(args, str):
        args = [args]
    if not isinstance(args, list):
        args = []
    if not isinstance(env, dict):
        env = {}

    url = next(
        (entry[k] for k in ("url", "serverUrl", "httpUrl") if isinstance(entry.get(k), str)),
        None,
    )
    raw_transport = str(entry.get("type") or entry.get("transport") or "").strip().lower()
    transport = _TRANSPORTS.get(raw_transport)
    if transport is None:
        if command:
            transport = "stdio"
        elif isinstance(entry.get("httpUrl"), str):
            transport = "http"
        elif url:
            transport = "sse" if url.rstrip("/").endswith("/sse") else "http"
        else:
            transport = "unknown"
    headers = entry.get("headers") or entry.get("http_headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    cwd = entry.get("cwd")
    return ServerConfig(
        name=str(name),
        client=client,
        transport=transport,
        command=_stringify(command) if command is not None else None,
        args=[_stringify(a) for a in args],
        env={str(k): _stringify(v) for k, v in env.items()},
        url=url,
        headers={str(k): _stringify(v) for k, v in headers.items()},
        cwd=cwd if isinstance(cwd, str) else None,
        scope=scope,
        raw=entry,
        source=doc,
        pointer=pointer,
    )


def extract_servers(doc: SourceDocument, client: str) -> tuple[list[ServerConfig], list[Notice]]:
    servers: list[ServerConfig] = []
    notices: list[Notice] = []
    containers = _containers(doc.data, client)
    if not containers:
        notices.append(Notice("warning", "no MCP server definitions found", doc.path))
    for pointer, mapping, scope in containers:
        for name, entry in mapping.items():
            entry_pointer = join_pointer(pointer, name)
            if not isinstance(entry, dict):
                notices.append(
                    Notice("warning", f"server entry {name!r} is not an object; skipped", doc.path)
                )
                continue
            servers.append(_normalize(name, entry, entry_pointer, doc, client, scope))
    return servers, notices


def load_config(path: str | Path, client: str | None = None) -> LoadResult:
    """Load one configuration file. Errors are reported as notices, not raised."""
    result = LoadResult()
    file_path = Path(path)
    try:
        doc = load_document(file_path)
    except FileNotFoundError:
        result.notices.append(Notice("error", "file not found", str(file_path)))
        return result
    except (OSError, UnicodeDecodeError, ValueError, JSONLocError, tomllib.TOMLDecodeError) as exc:
        result.notices.append(Notice("error", f"cannot parse configuration: {exc}", str(file_path)))
        return result
    result.documents.append(doc)
    detected = client or guess_client(file_path, doc.data)
    servers, notices = extract_servers(doc, detected)
    result.servers.extend(servers)
    result.notices.extend(notices)
    return result


def load_configs(paths: Iterable[str | Path], client: str | None = None) -> LoadResult:
    result = LoadResult()
    seen: set[str] = set()
    for path in paths:
        key = os.path.normcase(os.path.abspath(path))
        if key in seen:
            continue
        seen.add(key)
        result.extend(load_config(path, client))
    return result


# --------------------------------------------------------------------------- discovery


def candidate_paths(
    home: Path,
    cwd: Path,
    environ: Mapping[str, str] | None = None,
    system: str | None = None,
) -> list[tuple[str, Path]]:
    """Well-known configuration locations for popular MCP clients."""
    environ = os.environ if environ is None else environ
    system = system or platform.system()
    if system == "Windows":
        appdata = Path(environ.get("APPDATA") or home / "AppData" / "Roaming")
        desktop = appdata / "Claude" / "claude_desktop_config.json"
        code_user = appdata / "Code" / "User"
        zed = appdata / "Zed" / "settings.json"
    elif system == "Darwin":
        support = home / "Library" / "Application Support"
        desktop = support / "Claude" / "claude_desktop_config.json"
        code_user = support / "Code" / "User"
        zed = home / ".config" / "zed" / "settings.json"
    else:
        xdg = Path(environ.get("XDG_CONFIG_HOME") or home / ".config")
        desktop = xdg / "Claude" / "claude_desktop_config.json"
        code_user = xdg / "Code" / "User"
        zed = xdg / "zed" / "settings.json"
    cline = code_user / "globalStorage" / "saoudrizwan.claude-dev" / "settings"
    return [
        ("claude-desktop", desktop),
        ("claude-code", home / ".claude.json"),
        ("claude-code", cwd / ".mcp.json"),
        ("cursor", home / ".cursor" / "mcp.json"),
        ("cursor", cwd / ".cursor" / "mcp.json"),
        ("vscode", code_user / "mcp.json"),
        ("vscode", code_user / "settings.json"),
        ("vscode", cwd / ".vscode" / "mcp.json"),
        ("cline", cline / "cline_mcp_settings.json"),
        ("windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"),
        ("gemini-cli", home / ".gemini" / "settings.json"),
        ("gemini-cli", cwd / ".gemini" / "settings.json"),
        ("zed", zed),
        ("codex", home / ".codex" / "config.toml"),
        ("amazon-q", home / ".aws" / "amazonq" / "mcp.json"),
    ]


def discover(
    home: Path | None = None,
    cwd: Path | None = None,
    environ: Mapping[str, str] | None = None,
    system: str | None = None,
) -> list[tuple[str, Path]]:
    """Return the candidate configuration files that exist on this machine."""
    found: list[tuple[str, Path]] = []
    seen: set[str] = set()
    for client, path in candidate_paths(home or Path.home(), cwd or Path.cwd(), environ, system):
        key = os.path.normcase(os.path.abspath(path))
        if key not in seen and path.is_file():
            seen.add(key)
            found.append((client, path))
    return found


# --------------------------------------------------------------------------- env expansion

_VAR = re.compile(r"\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class UnresolvedVariable(KeyError):
    pass


def expand_vars(value: str, environ: Mapping[str, str]) -> str:
    """Expand ``${VAR}``, ``${VAR:-default}`` and ``${env:VAR}`` references.

    ``${input:...}`` (VS Code prompts) and missing variables raise
    :class:`UnresolvedVariable`; callers decide whether that is fatal.
    """
    if "${input:" in value:
        raise UnresolvedVariable(value)

    def replace(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        if name in environ:
            return environ[name]
        if default is not None:
            return default
        raise UnresolvedVariable(name)

    return _VAR.sub(replace, value)
