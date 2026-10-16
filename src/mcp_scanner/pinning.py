"""Hash pinning of tool definitions and launch configurations (rug-pull detection).

Trust-on-first-use: the first time a server is seen, the SHA-256 of each tool
definition (and of the server instructions and launch configuration) is stored
in a pin file. Later scans compare against it and report every change until it
is explicitly approved with ``--update-pins``. Changed tools are never
re-pinned silently. ``--frozen-pins`` turns off TOFU for CI: nothing is
written and anything not already approved is reported.

The pin file is meant to be reviewable and committable: it stores hashes, the
approved tool definitions (so changes can be shown as a diff) and the *names*
of environment variables/headers, never their values.
"""

from __future__ import annotations

import datetime as _dt
import difflib
import hashlib
import json
import os
import re
import tempfile
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import TOOL_NAME, __version__
from .models import Finding, Location, ServerConfig, ServerInventory, ToolDefinition
from .rules.catalog import get
from .textutil import sanitize

PIN_VERSION = 1
ENV_PIN_PATH = "MCP_SCANNER_PINS"


class PinError(Exception):
    pass


def default_pin_path() -> Path:
    override = os.environ.get(ENV_PIN_PATH)
    return Path(override) if override else Path.home() / ".mcp-scanner" / "pins.json"


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_of(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def tool_digests(tool: ToolDefinition) -> dict[str, str]:
    raw = tool.raw
    return {
        "sha256": sha256_of(raw),
        "description_sha256": sha256_of(raw.get("description", "")),
        "schema_sha256": sha256_of(
            {"inputSchema": raw.get("inputSchema"), "outputSchema": raw.get("outputSchema")}
        ),
    }


def launch_components(server: ServerConfig) -> dict[str, str]:
    """Per-component hashes; values of env vars and headers are excluded."""
    return {
        "transport": sha256_of(server.transport),
        "command": sha256_of(server.command),
        "args": sha256_of(server.args),
        "url": sha256_of(server.url),
        "cwd": sha256_of(server.cwd),
        "env_keys": sha256_of(sorted(server.env)),
        "header_keys": sha256_of(sorted(k.lower() for k in server.headers)),
    }


def launch_record(server: ServerConfig) -> dict[str, Any]:
    components = launch_components(server)
    return {
        "sha256": sha256_of(components),
        "components": components,
        "env_keys": sorted(server.env),
    }


def text_diff(old: str, new: str, limit: int = 4) -> str:
    """Compact word-level diff, sanitized for display."""
    old_tokens = re.split(r"(\s+)", old)
    new_tokens = re.split(r"(\s+)", new)
    opcodes = difflib.SequenceMatcher(None, old_tokens, new_tokens, autojunk=False).get_opcodes()
    hunks: list[tuple[list[str], list[str]]] = []
    current: tuple[list[str], list[str]] | None = None
    for index, (tag, i1, i2, j1, j2) in enumerate(opcodes):
        if tag == "equal":
            segment = "".join(old_tokens[i1:i2])
            # Absorb short unchanged gaps so one edit is not split into fragments.
            if current is not None and len(segment.split()) <= 2 and index + 1 < len(opcodes):
                current[0].append(segment)
                current[1].append(segment)
            elif current is not None:
                hunks.append(current)
                current = None
            continue
        if current is None:
            current = ([], [])
        current[0].append("".join(old_tokens[i1:i2]))
        current[1].append("".join(new_tokens[j1:j2]))
    if current is not None:
        hunks.append(current)
    parts: list[str] = []
    for old_parts, new_parts in hunks:
        removed, added = "".join(old_parts).strip(), "".join(new_parts).strip()
        if removed:
            parts.append("- " + sanitize(removed, 120))
        if added:
            parts.append("+ " + sanitize(added, 120))
    if len(parts) > limit:
        parts = [*parts[:limit], f"(+{len(parts) - limit} more changes)"]
    return " | ".join(p for p in parts if p.strip("+- "))


def _pretty(value: Any) -> str:
    return json.dumps(value, sort_keys=True, indent=1, ensure_ascii=False)


@dataclass
class PinStore:
    path: Path
    servers: dict[str, dict[str, Any]] = field(default_factory=dict)
    exists: bool = False

    @classmethod
    def load(cls, path: str | Path) -> PinStore:
        file_path = Path(path)
        if not file_path.exists():
            return cls(file_path)
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PinError(f"cannot read pin file {file_path}: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("servers"), dict):
            raise PinError(f"invalid pin file {file_path}: missing 'servers' object")
        if data.get("version") != PIN_VERSION:
            raise PinError(f"unsupported pin file version {data.get('version')!r}")
        return cls(file_path, data["servers"], exists=True)

    def to_json(self) -> dict[str, Any]:
        return {
            "version": PIN_VERSION,
            "generator": f"{TOOL_NAME}/{__version__}",
            "updated_at": _now(),
            "servers": dict(sorted(self.servers.items())),
        }

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.to_json(), indent=2, ensure_ascii=False) + "\n"
        fd, tmp = tempfile.mkstemp(prefix=".pins-", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        self.exists = True


@dataclass
class PinOutcome:
    path: str
    mode: str  # "tofu" | "frozen" | "update"
    findings: list[Finding] = field(default_factory=list)
    pinned_servers: list[str] = field(default_factory=list)
    pinned_tools: int = 0
    approved_changes: int = 0
    dirty: bool = False


def _now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


def _tool_record(tool: ToolDefinition, now: str) -> dict[str, Any]:
    return {**tool_digests(tool), "pinned_at": now, "definition": tool.raw}


def _instructions_record(text: str) -> dict[str, Any]:
    return {"sha256": sha256_of(text), "text": text}


def _describe_tool_change(record: dict[str, Any], tool: ToolDefinition) -> tuple[str, str]:
    digests = tool_digests(tool)
    old_def = record.get("definition") if isinstance(record.get("definition"), dict) else {}
    if record.get("description_sha256") != digests["description_sha256"]:
        old = old_def.get("description", "") if isinstance(old_def.get("description"), str) else ""
        return "description", text_diff(old, tool.description)
    if record.get("schema_sha256") != digests["schema_sha256"]:
        old_schema = {k: old_def.get(k) for k in ("inputSchema", "outputSchema")}
        new_schema = {k: tool.raw.get(k) for k in ("inputSchema", "outputSchema")}
        return "input/output schema", text_diff(_pretty(old_schema), _pretty(new_schema))
    return "other fields (title, annotations, _meta)", text_diff(
        _pretty(old_def), _pretty(tool.raw)
    )


def check_pins(
    store: PinStore,
    servers: Iterable[ServerConfig],
    inventories: Iterable[ServerInventory],
    *,
    update: bool = False,
    frozen: bool = False,
    now: str | None = None,
) -> PinOutcome:
    """Compare current state with the pin store (mutating it unless frozen)."""
    now = now or _now()
    mode = "update" if update else "frozen" if frozen else "tofu"
    outcome = PinOutcome(str(store.path), mode)
    configs_by_name: dict[str, list[ServerConfig]] = defaultdict(list)
    for server in servers:
        configs_by_name[server.name].append(server)
    inventory_by_name = {inv.server: inv for inv in inventories}

    def report(rule_id: str, message: str, location: Location, **kwargs: Any) -> None:
        outcome.findings.append(Finding(get(rule_id), message, location, **kwargs))

    def mark_dirty() -> None:
        outcome.dirty = True

    for name in sorted(set(configs_by_name) | set(inventory_by_name)):
        configs = configs_by_name.get(name, [])
        inv = inventory_by_name.get(name)
        server_location = configs[0].locate() if configs else inv.locate() if inv else Location()
        entry = store.servers.get(name)
        first_time = entry is None
        if entry is None:
            if frozen:
                count = f" with {len(inv.tools)} tool(s)" if inv else ""
                report(
                    "MCPS402",
                    f"Server {name!r}{count} is not in the approved pin set",
                    server_location,
                    server=name,
                )
                continue
            entry = {"pinned_at": now, "launch": {}}
            store.servers[name] = entry
            outcome.pinned_servers.append(name)
            mark_dirty()

        launch = entry.setdefault("launch", {})
        for config in configs:
            current = launch_record(config)
            approved = launch.get(config.client)
            if approved is None:
                if frozen:
                    report(
                        "MCPS402",
                        f"Launch configuration of {name!r} in {config.client} is not approved",
                        config.locate(),
                        server=name,
                    )
                else:
                    launch[config.client] = current
                    mark_dirty()
            elif approved.get("sha256") != current["sha256"]:
                if update:
                    launch[config.client] = current
                    outcome.approved_changes += 1
                    mark_dirty()
                    continue
                old = approved.get("components", {})
                changed = [k for k, v in current["components"].items() if old.get(k) != v]
                evidence = None
                if "env_keys" in changed:
                    evidence = text_diff(
                        " ".join(approved.get("env_keys", [])), " ".join(current["env_keys"])
                    )
                report(
                    "MCPS404",
                    f"Launch configuration changed since approval ({', '.join(changed)})",
                    config.locate(),
                    server=name,
                    field=", ".join(changed),
                    evidence=evidence,
                )

        if inv is None:
            continue
        tools_entry = entry.get("tools")
        instructions = inv.instructions or ""
        if tools_entry is None:
            if frozen and not first_time:
                report(
                    "MCPS402",
                    f"Tools of server {name!r} have never been approved ({len(inv.tools)} tool(s))",
                    inv.locate(),
                    server=name,
                )
                continue
            entry["tools"] = {tool.name: _tool_record(tool, now) for tool in inv.tools}
            entry["instructions"] = _instructions_record(instructions)
            outcome.pinned_tools += len(inv.tools)
            mark_dirty()
            continue

        approved_instructions = entry.get("instructions")
        if approved_instructions is None:
            if not frozen:
                entry["instructions"] = _instructions_record(instructions)
                mark_dirty()
        elif approved_instructions.get("sha256") != sha256_of(instructions):
            if update:
                entry["instructions"] = _instructions_record(instructions)
                outcome.approved_changes += 1
                mark_dirty()
            else:
                report(
                    "MCPS405",
                    "Server instructions changed since approval",
                    inv.locate("instructions"),
                    server=name,
                    field="instructions",
                    evidence=text_diff(approved_instructions.get("text", ""), instructions),
                )

        current_tools = {tool.name: tool for tool in inv.tools}
        for tool_name, tool in current_tools.items():
            record = tools_entry.get(tool_name)
            if record is None:
                if update:
                    tools_entry[tool_name] = _tool_record(tool, now)
                    outcome.approved_changes += 1
                    mark_dirty()
                else:
                    report(
                        "MCPS402",
                        f"New tool {tool_name!r} appeared after the server was approved",
                        tool.locate("name"),
                        server=name,
                        tool=tool_name,
                        field="name",
                    )
            elif record.get("sha256") != tool_digests(tool)["sha256"]:
                if update:
                    tools_entry[tool_name] = _tool_record(tool, now)
                    outcome.approved_changes += 1
                    mark_dirty()
                else:
                    what, evidence = _describe_tool_change(record, tool)
                    report(
                        "MCPS401",
                        f"Definition of tool {tool_name!r} changed since approval ({what})",
                        tool.locate("description" if what == "description" else "name"),
                        server=name,
                        tool=tool_name,
                        field=what,
                        evidence=evidence or None,
                    )
        for tool_name in sorted(set(tools_entry) - set(current_tools)):
            if update:
                del tools_entry[tool_name]
                outcome.approved_changes += 1
                mark_dirty()
            else:
                report(
                    "MCPS403",
                    f"Approved tool {tool_name!r} is no longer exposed",
                    inv.locate(),
                    server=name,
                    tool=tool_name,
                )

    if frozen:
        outcome.dirty = False
    return outcome
