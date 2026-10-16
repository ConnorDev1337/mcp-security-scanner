"""Core data model shared by loaders, rules, pinning and reporters."""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .jsonloc import SourceDocument


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> Severity:
        """Parse a case-insensitive severity name; raise ``ValueError`` if unknown."""
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {value!r}") from None


def escape_token(token: str | int) -> str:
    """Escape a single JSON Pointer reference token (RFC 6901)."""
    return str(token).replace("~", "~0").replace("/", "~1")


def join_pointer(base: str, *parts: str | int) -> str:
    """Append ``parts`` as escaped reference tokens to the JSON Pointer ``base``."""
    return base + "".join("/" + escape_token(p) for p in parts)


@dataclass(frozen=True)
class Location:
    path: str | None = None
    line: int | None = None
    column: int | None = None
    pointer: str = ""

    def __str__(self) -> str:
        if not self.path:
            return "-"
        return f"{self.path}:{self.line}" if self.line else self.path


@dataclass(frozen=True)
class Notice:
    """A non-finding message: unreadable files, failed introspection, etc."""

    level: str  # "error" | "warning" | "note"
    message: str
    path: str | None = None


@dataclass
class ServerConfig:
    """One MCP server entry, normalized across client configuration formats."""

    name: str
    client: str
    transport: str  # "stdio" | "http" | "sse" | "unknown"
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None
    scope: str | None = None  # Project path of a Claude Code local-scope server.
    raw: dict[str, Any] = field(default_factory=dict)
    source: SourceDocument | None = None
    pointer: str = ""

    def locate(self, *parts: str | int) -> Location:
        pointer = join_pointer(self.pointer, *parts)
        if self.source is None:
            return Location(pointer=pointer)
        return self.source.locate(pointer, hint=self.name)


@dataclass
class _Definition:
    """Common shape of server-declared metadata: the raw JSON object and its origin."""

    name: str
    raw: dict[str, Any]
    source: SourceDocument | None = None
    pointer: str = ""
    fallback: Location | None = None

    @property
    def description(self) -> str:
        value = self.raw.get("description")
        return value if isinstance(value, str) else ""

    @property
    def title(self) -> str | None:
        value = self.raw.get("title")
        return value if isinstance(value, str) else None

    def locate(self, *parts: str | int) -> Location:
        if self.source is not None:
            return self.source.locate(join_pointer(self.pointer, *parts))
        return self.fallback or Location()


@dataclass
class ToolDefinition(_Definition):
    """A tool as returned by ``tools/list`` (kept raw for hashing)."""

    @property
    def input_schema(self) -> dict[str, Any]:
        value = self.raw.get("inputSchema")
        return value if isinstance(value, dict) else {}

    @property
    def annotations(self) -> dict[str, Any]:
        value = self.raw.get("annotations")
        return value if isinstance(value, dict) else {}


@dataclass
class PromptDefinition(_Definition):
    """A prompt template as returned by ``prompts/list``.

    Only the listing metadata is kept; the rendered messages (``prompts/get``)
    depend on arguments and are never fetched.
    """

    @property
    def arguments(self) -> list[Any]:
        """Return the raw ``arguments`` list (items are not validated)."""
        value = self.raw.get("arguments")
        return value if isinstance(value, list) else []


@dataclass
class ResourceDefinition(_Definition):
    """A resource (``resources/list``) or resource template (``resources/templates/list``).

    Only metadata is kept; resource contents (``resources/read``) are never read.
    """

    template: bool = False

    @property
    def uri_key(self) -> str:
        """Return the key that identifies the resource: ``uriTemplate`` or ``uri``."""
        return "uriTemplate" if self.template else "uri"

    @property
    def uri(self) -> str:
        value = self.raw.get(self.uri_key)
        return value if isinstance(value, str) else ""

    @property
    def kind(self) -> str:
        """Return a human-readable kind: ``resource template`` or ``resource``."""
        return "resource template" if self.template else "resource"


@dataclass
class ServerInventory:
    """Tools, prompts, resources and server instructions declared by one server.

    ``prompts``, ``resources`` and ``resource_templates`` are None when they were
    not collected (a manifest without the key, or a listing that failed), as
    opposed to an empty list for a server that declares none. Pinning leaves the
    approved entries of uncollected kinds untouched.
    """

    server: str
    tools: list[ToolDefinition] = field(default_factory=list)
    instructions: str | None = None
    server_info: dict[str, Any] = field(default_factory=dict)
    origin: str = "manifest"  # "manifest" | "introspection"
    source: SourceDocument | None = None
    pointer: str = ""
    fallback: Location | None = None
    prompts: list[PromptDefinition] | None = None
    resources: list[ResourceDefinition] | None = None
    resource_templates: list[ResourceDefinition] | None = None
    notices: list[Notice] = field(default_factory=list)  # E.g. a failed prompts/list.

    def all_resources(self) -> list[ResourceDefinition]:
        """Return the collected resources followed by the resource templates."""
        return [*(self.resources or ()), *(self.resource_templates or ())]

    def locate(self, *parts: str | int) -> Location:
        if self.source is not None:
            return self.source.locate(join_pointer(self.pointer, *parts))
        return self.fallback or Location()


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    title: str
    severity: Severity
    category: str
    description: str
    remediation: str


@dataclass
class Finding:
    """A rule match; ``severity`` defaults to the rule's own severity."""

    rule: Rule
    message: str
    location: Location
    server: str | None = None
    tool: str | None = None
    field: str | None = None
    evidence: str | None = None
    severity: Severity | None = None
    prompt: str | None = None  # Prompt name, for findings about a prompt.
    resource: str | None = None  # Masked URI or URI template, for findings about a resource.

    def __post_init__(self) -> None:
        if self.severity is None:
            self.severity = self.rule.severity

    @property
    def subject(self) -> str | None:
        """Return the tool, ``prompt:NAME`` or ``resource:URI`` the finding is about."""
        if self.tool:
            return self.tool
        if self.prompt is not None:
            return f"prompt:{self.prompt}"
        if self.resource is not None:
            return f"resource:{self.resource}"
        return None

    @property
    def target(self) -> str:
        subject = self.subject
        if self.server and subject:
            return f"{self.server}/{subject}"
        return self.server or subject or "-"

    def fingerprint(self) -> str:
        """Stable identifier used for de-duplication and SARIF fingerprints.

        Built only from already-redacted data, so it never encodes a secret.
        """
        parts = [self.rule.id, self.server or "", self.tool or "", self.field or ""]
        # Appended only when set so fingerprints of tool and server findings stay stable.
        if self.prompt is not None:
            parts.append(f"prompt:{self.prompt}")
        if self.resource is not None:
            parts.append(f"resource:{self.resource}")
        parts.append(self.evidence or self.message)
        return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:32]
