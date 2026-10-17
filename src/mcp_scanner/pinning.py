"""Hash pinning of tool, prompt and resource definitions and launch configurations.

Trust on first use (TOFU): the first scan of a server stores SHA-256 hashes of
its tool definitions, prompts, resources, resource templates, instructions and
launch configuration in a pin file. Later scans report every change until it is
approved with ``--update-pins``; changes are never re-pinned silently.
``--frozen-pins`` (for CI) disables TOFU: nothing is written and anything not
already approved is reported (rug-pull detection).

The pin file is meant to be reviewed and committed. It stores hashes, the
approved definitions (to show diffs) and the *names* of environment variables
and headers, never their values. Every definition and the server instructions
are stored with provider tokens and URL credentials masked, and servers, tools,
prompts and resources are keyed by their masked name or URI (as are the stored
variable names), so the pin file holds no secret a server embeds in its
metadata; :func:`pinned_form` explains how masked values stay bound.

Format history: version 1 pinned tools, instructions and launch configurations.
Version 2 adds ``prompts``, ``resources`` and ``resource_templates`` per server.
Version 3 masks tool definitions and instructions too, binds masked values in
the hashes and adds a per-file ``salt``; its records carry ``"scheme": 3``.
Older files still load. Their servers get prompts and resources pinned on first
use (or reported with ``--frozen-pins``); records without a scheme are verified
the way they were written (tools and instructions over the raw definition,
prompts and resources over the version-2 masking), so upgrading reports no
change, and are rewritten in the current form. The file is written back as
version 3 the next time it changes, or right away when it held secrets.
"""

from __future__ import annotations

import datetime as _dt
import difflib
import hashlib
import hmac
import json
import os
import re
import tempfile
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import TOOL_NAME, __version__
from .models import (
    Finding,
    Location,
    PromptDefinition,
    ResourceDefinition,
    ServerConfig,
    ServerInventory,
    Severity,
    ToolDefinition,
)
from .rules.catalog import get
from .rules.resources import resource_key
from .rules.secrets import MaskedSpan, mask, mask_spans
from .textutil import redact, sanitize

PIN_VERSION = 3
SUPPORTED_PIN_VERSIONS = frozenset({1, 2, 3})
SCHEME = 3  # Hash scheme of the records this version writes (see pinned_form).
ENV_PIN_PATH = "MCP_SCANNER_PINS"
_DIGEST_TAG = "mcp-scanner/pin-digest/3"
_SECRET_TAG = b"mcp-scanner/pin-secret/3\x00"


class PinError(Exception):
    """The pin file cannot be read or has an unsupported format."""


def default_pin_path() -> Path:
    """Return ``$MCP_SCANNER_PINS`` if set, else ``~/.mcp-scanner/pins.json``."""
    override = os.environ.get(ENV_PIN_PATH)
    return Path(override) if override else Path.home() / ".mcp-scanner" / "pins.json"


def canonical_json(value: Any) -> bytes:
    """Serialize ``value`` deterministically (sorted keys, no whitespace, UTF-8).

    Lone surrogates, which JSON escapes allow, are encoded as such ("surrogatepass")
    instead of failing; every other string is plain UTF-8, as before.
    """
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8", "surrogatepass")


def sha256_of(value: Any) -> str:
    """Return the hex SHA-256 of the canonical JSON form of ``value``."""
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _masked(value: Any, spans: list[MaskedSpan], *, legacy: bool = False) -> Any:
    """Return a copy of ``value`` with provider tokens and URL credentials masked.

    The masked values are appended to ``spans`` in an order that does not depend
    on the order of object keys.
    """
    if isinstance(value, str):
        text, found = mask_spans(value, legacy=legacy)
        spans.extend(found)
        return text
    if isinstance(value, list):
        return [_masked(item, spans, legacy=legacy) for item in value]
    if isinstance(value, dict):
        pairs = {}
        taken: set[str] = set()
        for key in sorted(value, key=str):
            masked_key = _masked(str(key), spans, legacy=legacy)
            if not legacy:
                # Keys that mask alike (two tokens of one format and length) get a
                # numbered suffix: keeping one value would hide changes to the other
                # and make the result depend on the key order.
                unique, number = masked_key, 1
                while unique in taken:
                    number += 1
                    unique = f"{masked_key} ({number})"
                masked_key = unique
                taken.add(masked_key)
            pairs[key] = (masked_key, _masked(value[key], spans, legacy=legacy))
        return dict(pairs[key] for key in value)
    return value


def _secret_marker(span: MaskedSpan, salt: bytes) -> str:
    if span.kind == "token":
        value = span.value.encode("utf-8", "surrogatepass")
        digest = hmac.new(salt, _SECRET_TAG + value, hashlib.sha256).hexdigest()
        return f"token:{digest}"
    return f"url:{len(span.value)}"


def pinned_form(value: Any, salt: bytes = b"") -> tuple[Any, str]:
    """Return ``value`` with secrets masked and the digest that pins it.

    The digest covers the masked form plus one marker per masked value, so a
    change confined to a masked span is still detected, while the pin file holds
    nothing that confirms a guess of a low-entropy secret:

    - A provider token is bound by its HMAC-SHA256 keyed with the per-file
      ``salt``. Values that match the provider formats are long random strings,
      so the digest cannot be brute-forced; the salt keeps digests of the same
      token from being linked across pin files or matched against published
      hash lists.
    - A URL password or sensitive query value is bound by its length only.
      These values are often chosen by people, and any digest of them, salted
      or not (the salt is stored next to it), would let whoever reads the pin
      file test guesses offline.

    Without masked values the digest is the SHA-256 of the canonical JSON form,
    exactly as in earlier formats.
    """
    spans: list[MaskedSpan] = []
    masked = _masked(value, spans)
    if not spans:
        return masked, sha256_of(masked)
    markers = [_secret_marker(span, salt) for span in spans]
    return masked, sha256_of([_DIGEST_TAG, masked, markers])


def legacy_digest(value: Any) -> str:
    """Return the digest of ``value`` as format-2 pin files hashed prompts and resources."""
    return sha256_of(_masked(value, [], legacy=True))


def _schema(raw: dict[str, Any]) -> dict[str, Any]:
    return {"inputSchema": raw.get("inputSchema"), "outputSchema": raw.get("outputSchema")}


def tool_digests(tool: ToolDefinition, salt: bytes = b"") -> dict[str, str]:
    """Return the digests of a tool: whole definition, description and schemas."""
    raw = tool.raw
    return {
        "sha256": pinned_form(raw, salt)[1],
        "description_sha256": pinned_form(raw.get("description", ""), salt)[1],
        "schema_sha256": pinned_form(_schema(raw), salt)[1],
    }


def prompt_definition(prompt: PromptDefinition) -> dict[str, Any]:
    """Return the pinned part of a prompt: its listing metadata."""
    return prompt.raw


def resource_definition(resource: ResourceDefinition) -> dict[str, Any]:
    """Return the pinned part of a resource or template.

    ``size`` and ``annotations.lastModified`` describe the content rather than
    the definition and change whenever the resource is edited, so they are left
    out of the hash.
    """
    raw = {k: v for k, v in resource.raw.items() if k != "size"}
    annotations = raw.get("annotations")
    if isinstance(annotations, dict) and "lastModified" in annotations:
        raw["annotations"] = {k: v for k, v in annotations.items() if k != "lastModified"}
    return raw


@dataclass(frozen=True)
class _Kind:
    """How one kind of prompt or resource definition is pinned and reported."""

    attr: str  # ServerInventory attribute and pin-file key.
    label: str
    plural: str
    subject: str  # Finding attribute naming the item: "prompt" or "resource".
    pointer: str  # Field that locates the item: "name", "uri" or "uriTemplate".
    changed_rule: str
    key: Callable[[Any], str]
    definition: Callable[[Any], dict[str, Any]]
    new_severity: Severity | None = None


_KINDS = (
    _Kind(
        "prompts",
        "prompt",
        "prompts",
        "prompt",
        "name",
        "MCPS406",
        lambda prompt: mask(prompt.name),
        prompt_definition,
    ),
    # Concrete resource lists are often dynamic (files, rows), so a new one is only LOW.
    _Kind(
        "resources",
        "resource",
        "resources",
        "resource",
        "uri",
        "MCPS407",
        resource_key,
        resource_definition,
        Severity.LOW,
    ),
    _Kind(
        "resource_templates",
        "resource template",
        "resource templates",
        "resource",
        "uriTemplate",
        "MCPS407",
        resource_key,
        resource_definition,
    ),
)


def pin_key(name: Any) -> str:
    """Return the key of a server, tool, prompt or resource in the pin file.

    It is the name (or URI) with provider tokens and URL credentials masked, so a
    credential embedded in an identifier never reaches the file. Ordinary names are
    their own key.
    """
    return mask(str(name))


def _rekeyed(records: dict[Any, Any]) -> dict[str, Any]:
    """Return ``records`` keyed by :func:`pin_key`; the first of colliding keys wins."""
    rekeyed: dict[str, Any] = {}
    for key, record in records.items():
        rekeyed.setdefault(pin_key(key), record)
    return rekeyed


def launch_components(server: ServerConfig) -> dict[str, str]:
    """Hash each launch component; only the names of env vars and headers are included."""
    return {
        "transport": sha256_of(server.transport),
        "command": sha256_of(server.command),
        "args": sha256_of(server.args),
        "url": sha256_of(server.url),
        "cwd": sha256_of(server.cwd),
        "env_keys": sha256_of(sorted(server.env)),
        "header_keys": sha256_of(sorted(k.lower() for k in server.headers)),
    }


def _env_names(names: Iterable[str]) -> list[str]:
    """Return environment variable names as stored for diffs, with tokens masked.

    A token pasted as a variable name would otherwise be copied to the pin file.
    """
    return sorted(mask(str(name)) for name in names)


def launch_record(server: ServerConfig) -> dict[str, Any]:
    components = launch_components(server)
    return {
        "sha256": sha256_of(components),
        "components": components,
        "env_keys": _env_names(server.env),
    }


def text_diff(old: str, new: str, limit: int = 4) -> str:
    """Return a compact word-level diff, sanitized for display."""
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


@dataclass(frozen=True)
class StoredSecret:
    """A credential found in clear text in the pin file as it was loaded."""

    target: str  # "server", "server/tool:NAME", "server/instructions", ...
    span: MaskedSpan


_ITEM_LABELS = {
    "tools": "tool",
    "prompts": "prompt",
    "resources": "resource",
    "resource_templates": "resource",
}


def _secret_target(path: tuple[str, ...]) -> str:
    if len(path) >= 3 and path[1] in _ITEM_LABELS:
        return f"{path[0]}/{_ITEM_LABELS[path[1]]}:{mask(path[2])}"
    if len(path) >= 2 and path[1] == "instructions":
        return f"{path[0]}/instructions"
    return path[0] if path else "-"


def find_stored_secrets(servers: Any) -> list[StoredSecret]:
    """Return the credentials stored in clear text anywhere in the ``servers`` object.

    Files written by format 3 hold none; earlier formats stored tool definitions
    and instructions verbatim.
    """
    found: list[StoredSecret] = []

    def walk(value: Any, path: tuple[str, ...]) -> None:
        if isinstance(value, str):
            target = _secret_target(path)
            spans = mask_spans(value)[1]
            found.extend(StoredSecret(target, span) for span in spans if not span.placeholder)
        elif isinstance(value, list):
            for item in value:
                walk(item, path)
        elif isinstance(value, dict):
            for key, item in value.items():
                walk(str(key), (*path, str(key)))
                walk(item, (*path, str(key)))

    walk(servers, ())
    return found


@dataclass
class PinStore:
    """Approved pins per server, as stored in the pin file."""

    path: Path
    servers: dict[str, dict[str, Any]] = field(default_factory=dict)
    exists: bool = False
    version: int = PIN_VERSION  # Format of the file as loaded; saving writes PIN_VERSION.
    salt: bytes = field(default_factory=lambda: os.urandom(16))  # Keys token digests.
    stored_secrets: list[StoredSecret] = field(default_factory=list)  # Found when loading.

    @classmethod
    def load(cls, path: str | Path) -> PinStore:
        """Load the pin file, or return an empty store if it does not exist.

        Every version in ``SUPPORTED_PIN_VERSIONS`` is accepted; records written
        by earlier formats are brought to the current form in memory. Credentials
        found in clear text are listed in ``stored_secrets``. Raise
        :class:`PinError` if the file is unreadable, invalid or from a newer
        format.
        """
        file_path = Path(path)
        if not file_path.exists():
            return cls(file_path)
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PinError(f"cannot read pin file {file_path}: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("servers"), dict):
            raise PinError(f"invalid pin file {file_path}: missing 'servers' object")
        version = data.get("version")
        if isinstance(version, bool) or version not in SUPPORTED_PIN_VERSIONS:
            raise PinError(f"unsupported pin file version {version!r}")
        store = cls(file_path, data["servers"], exists=True, version=version)
        salt = data.get("salt")
        if salt is not None:
            try:
                store.salt = bytes.fromhex(salt)
            except (TypeError, ValueError):
                raise PinError(f"invalid pin file {file_path}: malformed 'salt'") from None
        store.stored_secrets = find_stored_secrets(store.servers)
        _migrate(store)
        return store

    def to_json(self) -> dict[str, Any]:
        return {
            "version": PIN_VERSION,
            "generator": f"{TOOL_NAME}/{__version__}",
            "updated_at": _now(),
            "salt": self.salt.hex(),
            "servers": dict(sorted(self.servers.items())),
        }

    def save(self) -> None:
        """Write the pin file atomically (temporary file, then rename).

        The file is meant to be committed, so it has LF line endings on every
        platform. A lone surrogate is written as its JSON escape, which reads back
        as the same character.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.to_json(), indent=2, ensure_ascii=False) + "\n"
        fd, tmp = tempfile.mkstemp(prefix=".pins-", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(
                fd, "w", encoding="utf-8", errors="backslashreplace", newline="\n"
            ) as handle:
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
    pinned_prompts: int = 0
    pinned_resources: int = 0  # Resources and resource templates.
    approved_changes: int = 0
    dirty: bool = False


def _now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


_SECRET_CHANGED = "a masked secret value changed"  # noqa: S105 - evidence text


def _tool_record(tool: ToolDefinition, now: str, salt: bytes) -> dict[str, Any]:
    definition = _masked(tool.raw, [])
    return {
        **tool_digests(tool, salt),
        "pinned_at": now,
        "definition": definition,
        "scheme": SCHEME,
    }


def _instructions_record(text: str, salt: bytes) -> dict[str, Any]:
    masked, digest = pinned_form(text, salt)
    return {"sha256": digest, "text": masked, "scheme": SCHEME}


def _item_record(prepared: dict[str, Any], now: str, salt: bytes) -> dict[str, Any]:
    definition, digest = pinned_form(prepared, salt)
    return {"sha256": digest, "pinned_at": now, "definition": definition, "scheme": SCHEME}


def _verified(record: dict[str, Any], digest: str, legacy: Callable[[], str]) -> bool:
    """Return whether ``record`` approves ``digest`` (or, for an old record, ``legacy()``)."""
    stored = record.get("sha256")
    return stored == digest or (record.get("scheme") is None and stored == legacy())


def _refresh(
    container: dict[str, Any],
    key: str,
    record: dict[str, Any],
    fresh: dict[str, Any],
    outcome: PinOutcome,
) -> None:
    """Replace a verified record of an earlier format by its current form.

    The approval time is kept. The pin file only needs writing when the stored
    content changes (masked values are now bound in the digest); the scheme
    marker alone waits for the next write.
    """
    if record.get("scheme") == SCHEME:
        return
    if "pinned_at" in record:
        fresh["pinned_at"] = record["pinned_at"]
    container[key] = fresh
    if {**record, "scheme": SCHEME} != fresh:
        outcome.dirty = True


def _describe_tool_change(
    record: dict[str, Any], tool: ToolDefinition, salt: bytes
) -> tuple[str, str]:
    digests = tool_digests(tool, salt)
    old_def = record.get("definition") if isinstance(record.get("definition"), dict) else {}
    new_def = _masked(tool.raw, [])
    if record.get("description_sha256") != digests["description_sha256"]:
        old, new = old_def.get("description"), new_def.get("description")
        old = old if isinstance(old, str) else ""
        new = new if isinstance(new, str) else ""
        return "description", text_diff(old, new) or _SECRET_CHANGED
    if record.get("schema_sha256") != digests["schema_sha256"]:
        diff = text_diff(_pretty(_schema(old_def)), _pretty(_schema(new_def)))
        return "input/output schema", diff or _SECRET_CHANGED
    diff = text_diff(_pretty(old_def), _pretty(new_def))
    return "other fields (title, annotations, _meta)", diff or _SECRET_CHANGED


def _describe_item_change(old_def: Any, new_def: dict[str, Any]) -> tuple[str, str]:
    """Return the changed top-level fields of a prompt or resource and a compact diff."""
    old_def = old_def if isinstance(old_def, dict) else {}
    changed = sorted(k for k in {*old_def, *new_def} if old_def.get(k) != new_def.get(k))
    if not changed:
        return "masked secret", _SECRET_CHANGED
    old, new = old_def.get("description"), new_def.get("description")
    if changed == ["description"] and isinstance(old, str) and isinstance(new, str):
        return "description", text_diff(old, new)
    old_part = {k: old_def.get(k) for k in changed}
    new_part = {k: new_def.get(k) for k in changed}
    return ", ".join(changed), text_diff(_pretty(old_part), _pretty(new_part))


def _migrate_tool(name: str, record: dict[str, Any], salt: bytes) -> dict[str, Any]:
    definition = record.get("definition")
    if isinstance(definition, dict) and record.get("sha256") == sha256_of(definition):
        fresh = _tool_record(ToolDefinition(name, definition), "", salt)
        if "pinned_at" in record:
            fresh["pinned_at"] = record["pinned_at"]
        else:
            del fresh["pinned_at"]
        return fresh
    # The definition does not match its hash: keep the raw-definition hash, which is
    # verified against the current tool, and mask the copy kept for diffs.
    return {**record, "definition": _masked(definition, [])}


def _migrate_instructions(record: dict[str, Any], salt: bytes) -> dict[str, Any]:
    text = record.get("text")
    if isinstance(text, str) and record.get("sha256") == sha256_of(text):
        return _instructions_record(text, salt)
    return {**record, "text": _masked(text, [])}


def _migrate(store: PinStore) -> None:
    """Bring records written by earlier formats to the current form, in memory.

    Tool and instruction records stored the raw definition, so they are converted
    from it. Prompt and resource records only stored a masked definition: they
    keep their format-2 digest until it is verified against the current item,
    but their copy is masked again and resources are re-keyed, because the
    format-2 masking missed percent-encoded query values. Names of servers, tools and
    prompts, which key the records, and environment variable names kept for launch
    diffs are masked too: they were stored verbatim before (see :func:`pin_key`).
    """
    store.servers = _rekeyed(store.servers)
    for entry in store.servers.values():
        if not isinstance(entry, dict):
            continue
        launch = entry.get("launch")
        for record in launch.values() if isinstance(launch, dict) else ():
            if isinstance(record, dict) and isinstance(record.get("env_keys"), list):
                record["env_keys"] = _env_names(record["env_keys"])
        tools = entry.get("tools")
        if isinstance(tools, dict):
            tools = entry["tools"] = _rekeyed(tools)
            for name, record in tools.items():
                if isinstance(record, dict) and record.get("scheme") is None:
                    tools[name] = _migrate_tool(str(name), record, store.salt)
        instructions = entry.get("instructions")
        if isinstance(instructions, dict) and instructions.get("scheme") is None:
            entry["instructions"] = _migrate_instructions(instructions, store.salt)
        for kind in _KINDS:
            approved = entry.get(kind.attr)
            if not isinstance(approved, dict):
                continue
            migrated: dict[str, Any] = {}
            for key, record in approved.items():
                if isinstance(record, dict) and record.get("scheme") is None:
                    record = {**record, "definition": _masked(record.get("definition"), [])}
                migrated.setdefault(pin_key(key), record)
            entry[kind.attr] = migrated


def _stored_secrets_finding(store: PinStore, frozen: bool) -> Finding:
    """Report the credentials found in clear text in the pin file (MCPS304)."""
    stored = store.stored_secrets
    targets = sorted({sanitize(item.target, 80) for item in stored})
    where = ", ".join(targets[:3])
    if len(targets) > 3:
        where += f" and {len(targets) - 3} more"
    if frozen:
        action = "run once without --frozen-pins to rewrite it without them"
    else:
        action = "it was rewritten without them, but earlier copies still hold them"
    values = sorted({f"{item.span.label} {redact(item.span.value)}" for item in stored})
    evidence = "; ".join(values[:3]) + (f" (+{len(values) - 3} more)" if len(values) > 3 else "")
    return Finding(
        get("MCPS304"),
        f"Pin file stores {len(stored)} credential(s) in clear text ({where}); {action}",
        Location(path=str(store.path)),
        evidence=evidence,
        severity=max(item.span.severity for item in stored),
    )


def _inventory_summary(inv: ServerInventory) -> str:
    parts = [f"{len(inv.tools)} tool(s)"]
    for kind in _KINDS:
        items = getattr(inv, kind.attr)
        if items:
            parts.append(f"{len(items)} {kind.label}(s)")
    return ", ".join(parts)


def _check_items(
    entry: dict[str, Any],
    inv: ServerInventory,
    outcome: PinOutcome,
    report: Callable[..., None],
    *,
    now: str,
    salt: bytes,
    update: bool,
    frozen: bool,
) -> None:
    """Pin or compare the prompts, resources and resource templates of one server."""
    name = inv.server
    for kind in _KINDS:
        items = getattr(inv, kind.attr)
        if items is None:
            continue  # Not collected (older manifest, failed listing): keep the approval.
        current = {kind.key(item): item for item in items}
        approved = entry.get(kind.attr)
        if not isinstance(approved, dict):
            # Never pinned: a new server, or one pinned by a format-1 file or before
            # this kind was collected.
            if frozen:
                if current:
                    report(
                        "MCPS408",
                        f"{kind.plural.capitalize()} of server {name!r} have never been "
                        f"approved ({len(current)} {kind.label}(s))",
                        inv.locate(),
                        server=name,
                    )
                continue
            entry[kind.attr] = {
                key: _item_record(kind.definition(item), now, salt)
                for key, item in current.items()
            }
            if kind.attr == "prompts":
                outcome.pinned_prompts += len(current)
            else:
                outcome.pinned_resources += len(current)
            outcome.dirty = True
            continue

        for key, item in current.items():
            prepared = kind.definition(item)
            definition, digest = pinned_form(prepared, salt)
            record = approved.get(key)
            subject = {kind.subject: key}
            if isinstance(record, dict) and _verified(
                record, digest, lambda prepared=prepared: legacy_digest(prepared)
            ):
                if not frozen:
                    _refresh(approved, key, record, _item_record(prepared, now, salt), outcome)
                continue
            if update:
                approved[key] = _item_record(prepared, now, salt)
                outcome.approved_changes += 1
                outcome.dirty = True
            elif not isinstance(record, dict):
                report(
                    "MCPS408",
                    f"New {kind.label} {key!r} appeared after the server was approved",
                    item.locate(kind.pointer),
                    server=name,
                    field=kind.pointer,
                    severity=kind.new_severity,
                    **subject,
                )
            else:
                what, evidence = _describe_item_change(record.get("definition"), definition)
                report(
                    kind.changed_rule,
                    f"Definition of {kind.label} {key!r} changed since approval ({what})",
                    item.locate("description" if what == "description" else kind.pointer),
                    server=name,
                    field=what,
                    evidence=evidence or None,
                    **subject,
                )
        for key in sorted(set(approved) - set(current)):
            if update:
                del approved[key]
                outcome.approved_changes += 1
                outcome.dirty = True
            else:
                report(
                    "MCPS409",
                    f"Approved {kind.label} {key!r} is no longer exposed",
                    inv.locate(),
                    server=name,
                    **{kind.subject: key},
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
    """Compare the current servers, tools, prompts and resources with ``store``.

    Unless ``frozen``, new servers and definitions are pinned in ``store`` (in
    memory; the caller saves it when ``outcome.dirty`` is set). ``update``
    approves every change.
    """
    now = now or _now()
    salt = store.salt
    mode = "update" if update else "frozen" if frozen else "tofu"
    outcome = PinOutcome(str(store.path), mode)
    configs_by_name: dict[str, list[ServerConfig]] = defaultdict(list)
    for server in servers:
        configs_by_name[pin_key(server.name)].append(server)
    inventory_by_name = {pin_key(inv.server): inv for inv in inventories}

    def report(rule_id: str, message: str, location: Location, **kwargs: Any) -> None:
        outcome.findings.append(Finding(get(rule_id), message, location, **kwargs))

    def mark_dirty() -> None:
        outcome.dirty = True

    if store.stored_secrets:
        # The records were masked when loading; writing the file removes the secrets.
        outcome.findings.append(_stored_secrets_finding(store, frozen))
        mark_dirty()

    for name in sorted(set(configs_by_name) | set(inventory_by_name)):
        configs = configs_by_name.get(name, [])
        inv = inventory_by_name.get(name)
        server_location = configs[0].locate() if configs else inv.locate() if inv else Location()
        entry = store.servers.get(name)
        first_time = entry is None
        if entry is None:
            if frozen:
                count = f" with {_inventory_summary(inv)}" if inv else ""
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

        # Launch configurations are pinned per client that defines the server.
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
        _check_items(entry, inv, outcome, report, now=now, salt=salt, update=update, frozen=frozen)
        tools_entry = entry.get("tools")
        instructions = inv.instructions or ""
        if tools_entry is None:
            if frozen and not first_time:
                report(
                    "MCPS402",
                    f"Tools of server {name!r} have never been approved "
                    f"({len(inv.tools)} tool(s))",
                    inv.locate(),
                    server=name,
                )
                continue
            entry["tools"] = {
                pin_key(tool.name): _tool_record(tool, now, salt) for tool in inv.tools
            }
            entry["instructions"] = _instructions_record(instructions, salt)
            outcome.pinned_tools += len(inv.tools)
            mark_dirty()
            continue

        approved_instructions = entry.get("instructions")
        masked_instructions, instructions_digest = pinned_form(instructions, salt)
        if approved_instructions is None:
            if not frozen:
                entry["instructions"] = _instructions_record(instructions, salt)
                mark_dirty()
        elif _verified(
            approved_instructions,
            instructions_digest,
            lambda text=instructions: sha256_of(text),
        ):
            if not frozen:
                fresh = _instructions_record(instructions, salt)
                _refresh(entry, "instructions", approved_instructions, fresh, outcome)
        elif update:
            entry["instructions"] = _instructions_record(instructions, salt)
            outcome.approved_changes += 1
            mark_dirty()
        else:
            old_text = approved_instructions.get("text")
            old_text = old_text if isinstance(old_text, str) else ""
            report(
                "MCPS405",
                "Server instructions changed since approval",
                inv.locate("instructions"),
                server=name,
                field="instructions",
                evidence=text_diff(old_text, masked_instructions) or _SECRET_CHANGED,
            )

        current_tools = {pin_key(tool.name): tool for tool in inv.tools}
        for tool_name, tool in current_tools.items():
            record = tools_entry.get(tool_name)
            if record is None:
                if update:
                    tools_entry[tool_name] = _tool_record(tool, now, salt)
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
            elif _verified(
                record, tool_digests(tool, salt)["sha256"], lambda tool=tool: sha256_of(tool.raw)
            ):
                if not frozen:
                    fresh = _tool_record(tool, now, salt)
                    _refresh(tools_entry, tool_name, record, fresh, outcome)
            else:
                if update:
                    tools_entry[tool_name] = _tool_record(tool, now, salt)
                    outcome.approved_changes += 1
                    mark_dirty()
                else:
                    what, evidence = _describe_tool_change(record, tool, salt)
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

    if frozen:  # Frozen mode never writes the pin file.
        outcome.dirty = False
    return outcome
