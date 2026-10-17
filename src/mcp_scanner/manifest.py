"""Load tool definitions captured from MCP servers (offline, nothing is executed).

Accepted shapes:

* scanner dump or multi-server manifest::

      {"servers": {"<name>": {"instructions": "...", "tools": [...],
                              "prompts": [...], "resources": [...],
                              "resourceTemplates": [...]}}}

* a ``tools/list`` result: ``{"tools": [...]}``
* a full JSON-RPC response: ``{"jsonrpc": "2.0", "id": 1, "result": {"tools": [...]}}``
* a bare JSON array of tools

``prompts``, ``resources`` and ``resourceTemplates`` are optional wherever a
``tools`` list is accepted and hold the items of ``prompts/list``,
``resources/list`` and ``resources/templates/list``. A missing key means "not
collected", so manifests written before these keys existed keep their meaning.

Single-server shapes take their server name from ``NAME=FILE`` on the command
line, then from a top-level ``"server"`` or ``serverInfo.name`` key, then from
the file stem.
"""

from __future__ import annotations

import datetime as _dt
import json
import tomllib
from pathlib import Path
from typing import Any

from . import TOOL_NAME, __version__
from .jsonloc import JSONLocError, SourceDocument, load_document
from .models import (
    Notice,
    PromptDefinition,
    ResourceDefinition,
    ServerInventory,
    ToolDefinition,
    join_pointer,
)


class ManifestError(Exception):
    """The document does not have a recognized tool manifest shape."""


def parse_spec(spec: str) -> tuple[str | None, Path]:
    """Split ``[NAME=]FILE``; an existing file whose name contains ``=`` is kept whole."""
    if "=" in spec and not Path(spec).exists():
        name, _, path = spec.partition("=")
        if name and path:
            return name, Path(path)
    return None, Path(spec)


def _tools_from(
    items: Any, doc: SourceDocument, pointer: str, server: str, notices: list[Notice]
) -> list[ToolDefinition]:
    tools: list[ToolDefinition] = []
    if not isinstance(items, list):
        notices.append(Notice("warning", f"'tools' for server {server!r} is not a list", doc.path))
        return tools
    for index, item in enumerate(items):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            notices.append(
                Notice(
                    "warning", f"tool #{index} of server {server!r} has no name; skipped", doc.path
                )
            )
            continue
        tools.append(
            ToolDefinition(item["name"], item, source=doc, pointer=join_pointer(pointer, index))
        )
    return tools


def _prompts_from(
    entry: dict[str, Any], doc: SourceDocument, pointer: str, server: str, notices: list[Notice]
) -> list[PromptDefinition] | None:
    if "prompts" not in entry:
        return None
    items = entry["prompts"]
    if not isinstance(items, list):
        notices.append(
            Notice("warning", f"'prompts' for server {server!r} is not a list", doc.path)
        )
        return None
    prompts: list[PromptDefinition] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            notices.append(
                Notice(
                    "warning",
                    f"prompt #{index} of server {server!r} has no name; skipped",
                    doc.path,
                )
            )
            continue
        prompts.append(
            PromptDefinition(
                item["name"], item, source=doc, pointer=join_pointer(pointer, "prompts", index)
            )
        )
    return prompts


def _resources_from(
    entry: dict[str, Any],
    doc: SourceDocument,
    pointer: str,
    server: str,
    notices: list[Notice],
    *,
    template: bool,
) -> list[ResourceDefinition] | None:
    key, uri_key = ("resourceTemplates", "uriTemplate") if template else ("resources", "uri")
    if key not in entry:
        return None
    items = entry[key]
    if not isinstance(items, list):
        notices.append(Notice("warning", f"{key!r} for server {server!r} is not a list", doc.path))
        return None
    what = "resource template" if template else "resource"
    resources: list[ResourceDefinition] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict) or not isinstance(item.get(uri_key), str):
            notices.append(
                Notice(
                    "warning",
                    f"{what} #{index} of server {server!r} has no {uri_key}; skipped",
                    doc.path,
                )
            )
            continue
        name = item.get("name")
        resources.append(
            ResourceDefinition(
                name if isinstance(name, str) else "",
                item,
                source=doc,
                pointer=join_pointer(pointer, key, index),
                template=template,
            )
        )
    return resources


def _inventory(
    server: str, entry: dict[str, Any], doc: SourceDocument, pointer: str, notices: list[Notice]
) -> ServerInventory:
    instructions = entry.get("instructions")
    server_info = entry.get("serverInfo")
    return ServerInventory(
        server=server,
        tools=_tools_from(
            entry.get("tools", []), doc, join_pointer(pointer, "tools"), server, notices
        ),
        instructions=instructions if isinstance(instructions, str) else None,
        server_info=server_info if isinstance(server_info, dict) else {},
        origin="manifest",
        source=doc,
        pointer=pointer,
        prompts=_prompts_from(entry, doc, pointer, server, notices),
        resources=_resources_from(entry, doc, pointer, server, notices, template=False),
        resource_templates=_resources_from(entry, doc, pointer, server, notices, template=True),
    )


def inventories_from_document(
    doc: SourceDocument, server_name: str | None = None
) -> tuple[list[ServerInventory], list[Notice]]:
    """Extract server inventories from a parsed manifest.

    Raise :class:`ManifestError` if the document has none of the accepted shapes.
    """
    data = doc.data
    notices: list[Notice] = []
    fallback_name = server_name or Path(doc.path).stem

    if isinstance(data, dict) and isinstance(data.get("servers"), dict):
        inventories = []
        for name, entry in data["servers"].items():
            if isinstance(entry, list):
                entry = {"tools": entry}
            if not isinstance(entry, dict):
                notices.append(
                    Notice("warning", f"server {name!r} entry is not an object", doc.path)
                )
                continue
            inventories.append(
                _inventory(str(name), entry, doc, join_pointer("/servers", name), notices)
            )
        return inventories, notices

    if isinstance(data, list):
        tools = _tools_from(data, doc, "", fallback_name, notices)
        return [ServerInventory(fallback_name, tools, source=doc, pointer="")], notices

    if isinstance(data, dict):
        entry, pointer = data, ""
        if isinstance(data.get("result"), dict) and "tools" in data["result"]:
            entry, pointer = data["result"], "/result"
        if "tools" in entry:
            info = entry.get("serverInfo") if isinstance(entry.get("serverInfo"), dict) else {}
            name = server_name or data.get("server") or info.get("name") or fallback_name
            return [_inventory(str(name), entry, doc, pointer, notices)], notices

    raise ManifestError("unrecognised tool manifest (expected 'servers', 'tools' or a list)")


def load_manifest(spec: str) -> tuple[list[ServerInventory], list[Notice]]:
    """Load ``[NAME=]FILE``; errors are returned as notices instead of raised."""
    name, path = parse_spec(spec)
    try:
        doc = load_document(path)
    except FileNotFoundError:
        return [], [Notice("error", "tool manifest not found", str(path))]
    except (OSError, UnicodeDecodeError, ValueError, JSONLocError, tomllib.TOMLDecodeError) as exc:
        return [], [Notice("error", f"cannot parse tool manifest: {exc}", str(path))]
    try:
        return inventories_from_document(doc, name)
    except ManifestError as exc:
        return [], [Notice("error", str(exc), str(path))]


def _dump_entry(inv: ServerInventory) -> dict[str, Any]:
    entry: dict[str, Any] = {}
    if inv.server_info:
        entry["serverInfo"] = inv.server_info
    if inv.instructions is not None:
        entry["instructions"] = inv.instructions
    entry["tools"] = [tool.raw for tool in inv.tools]
    # Uncollected kinds are omitted rather than written as [], so a reload keeps their meaning.
    if inv.prompts is not None:
        entry["prompts"] = [prompt.raw for prompt in inv.prompts]
    if inv.resources is not None:
        entry["resources"] = [resource.raw for resource in inv.resources]
    if inv.resource_templates is not None:
        entry["resourceTemplates"] = [template.raw for template in inv.resource_templates]
    return entry


def dump_inventories(inventories: list[ServerInventory], path: str | Path) -> None:
    """Write inventories in the multi-server manifest format (re-loadable)."""
    payload = {
        "generator": f"{TOOL_NAME}/{__version__}",
        "generated_at": _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds"),
        "servers": {inv.server: _dump_entry(inv) for inv in inventories},
    }
    # A lone surrogate is written as its JSON escape, which reads back as the same character.
    Path(path).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="backslashreplace",
    )
