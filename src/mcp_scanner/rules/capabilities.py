"""MCPS211-MCPS213: high-impact tool capabilities inferred from tool definitions."""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..models import Finding, ServerInventory, Severity, ToolDefinition
from ..textutil import normalize_for_matching, word_parts
from .catalog import get

# Words of a tool name (as split by word_parts) that reveal what the tool can do.
EXEC_WORDS = frozenset(
    {
        "exec",
        "execute",
        "shell",
        "bash",
        "sh",
        "zsh",
        "cmd",
        "powershell",
        "pwsh",
        "terminal",
        "eval",
        "subprocess",
        "spawn",
        "repl",
    }
)
RUN_OBJECTS = frozenset(
    {
        "command",
        "commands",
        "cmd",
        "script",
        "scripts",
        "code",
        "shell",
        "process",
        "program",
        "python",
        "javascript",
        "js",
        "sql",
    }
)
DESTRUCTIVE_WORDS = frozenset(
    {
        "delete",
        "remove",
        "rm",
        "unlink",
        "rmdir",
        "drop",
        "destroy",
        "truncate",
        "wipe",
        "purge",
        "erase",
        "overwrite",
        "kill",
        "terminate",
        "uninstall",
    }
)
FINANCIAL_WORDS = frozenset(
    {
        "transfer",
        "payment",
        "payments",
        "pay",
        "withdraw",
        "withdrawal",
        "refund",
        "charge",
        "purchase",
        "checkout",
        "trade",
    }
)
# Words with a common harmless meaning ("git checkout", transferring an issue,
# drag and drop). When the description is known, they count only if the name or
# description confirms the risky meaning.
AMBIGUOUS_FINANCIAL_WORDS = frozenset({"transfer", "charge", "checkout"})
AMBIGUOUS_DESTRUCTIVE_WORDS = frozenset({"drop"})
_MONEY_CONTEXT = re.compile(
    r"\b(?:money|funds?|payments?|paid|amounts?|currenc(?:y|ies)|prices?|pricing|invoices?|"
    r"billing|cards?|wallets?|balances?|bank|iban|crypto|stripe|paypal|cart|orders?|"
    r"transactions?|stocks?|shares|usd|eur)\b|[$€£]\s?\d"
)
_DRAG_AND_DROP = re.compile(r"\bdrag(?:s|ged|ging)?\b|\bonto\b")
# A leading read verb turns later write words into objects ("get_commit").
READ_VERBS = frozenset(
    {
        "get",
        "list",
        "read",
        "search",
        "fetch",
        "find",
        "view",
        "show",
        "describe",
        "query",
        "inspect",
        "lookup",
        "count",
    }
)
WRITE_WORDS = frozenset(
    {
        "write",
        "edit",
        "create",
        "update",
        "modify",
        "move",
        "rename",
        "upload",
        "push",
        "commit",
        "merge",
        "deploy",
        "publish",
        "patch",
        "append",
        "insert",
        "send",
        "set",
        "save",
        "replace",
    }
)
# Parameter names that usually carry code or commands.
CODE_PARAMS = frozenset(
    {
        "command",
        "cmd",
        "commands",
        "shell_command",
        "shellcommand",
        "script",
        "code",
        "source_code",
        "sourcecode",
        "sql",
        "expression",
        "eval",
        "javascript",
        "js",
        "python",
        "bash",
        "powershell",
        "statement",
    }
)

_EXEC_DESCRIPTION = re.compile(
    r"\b(?:execute|executes|run|runs|evaluate|evaluates)\b[^.]{0,30}?"
    r"\b(?:arbitrary|any|shell|system|terminal|bash|powershell|python|javascript|sql)\b[^.]{0,20}?"
    r"\b(?:commands?|code|scripts?|statements?|quer(?:y|ies))\b"
    # An unqualified object ("Run code/commands in a dyno") is free-form too, unless it is
    # part of a longer noun ("run code analysis").
    r"|\b(?:execute|executes|run|runs)\s+(?:code|commands?|scripts?)"
    r"(?=\s*(?:$|[/.,;:)])|\s+(?:in|on|inside|within|against|via|through|from|with|as|and|or)\b)"
)

_LABELS = {
    "exec": ("can execute commands or code", Severity.HIGH),
    "destructive": ("can delete or overwrite data", Severity.MEDIUM),
    "financial": ("can move money or execute transactions", Severity.MEDIUM),
}


def classify_name(name: str, description: str | None = None) -> str | None:
    """Return ``"exec"``, ``"destructive"``, ``"financial"`` or None for a tool name.

    Ambiguous words are judged by the name and ``description``; without a
    description (e.g. a name in an auto-approve list) they are assumed risky.
    """
    words = set(word_parts(name))
    if (
        words & EXEC_WORDS
        or ("run" in words and words & RUN_OBJECTS)
        or {"system", "command"} <= words
    ):
        return "exec"
    context = None
    if description is not None:
        context = normalize_for_matching(f"{' '.join(sorted(words))} {description}")
    destructive = words & DESTRUCTIVE_WORDS
    if destructive - AMBIGUOUS_DESTRUCTIVE_WORDS or (
        destructive and (context is None or not _DRAG_AND_DROP.search(context))
    ):
        return "destructive"
    financial = words & FINANCIAL_WORDS
    if financial - AMBIGUOUS_FINANCIAL_WORDS or (
        financial and (context is None or _MONEY_CONTEXT.search(context))
    ):
        return "financial"
    return None


def _declares_write(name: str) -> bool:
    """Return whether the action of a tool name is a write ("get_commit" is a read)."""
    words = word_parts(name)
    if {"and", "or", "then"} & set(words):  # "get_or_create": any write counts.
        return bool(set(words) & WRITE_WORDS)
    action = next((w for w in words if w in READ_VERBS or w in WRITE_WORDS), None)
    return action in WRITE_WORDS


def classify_tool(tool: ToolDefinition) -> tuple[str, str] | None:
    """Return ``(capability, reason)`` judged from the name, then the description, or None."""
    by_name = classify_name(tool.name, tool.description)
    if by_name:
        return by_name, f"name {tool.name!r}"
    if _EXEC_DESCRIPTION.search(normalize_for_matching(tool.description)):
        return "exec", "description"
    return None


def check_tool(inv: ServerInventory, tool: ToolDefinition) -> Iterator[Finding]:
    capability = classify_tool(tool)
    if capability:
        kind, reason = capability
        label, severity = _LABELS[kind]
        yield Finding(
            get("MCPS211"),
            f"Tool {label} (based on its {reason})",
            tool.locate("name"),
            server=inv.server,
            tool=tool.name,
            field="name",
            severity=severity,
        )

    annotations = tool.annotations
    if annotations.get("readOnlyHint") is True:
        modifies = capability is not None and capability[0] in {"exec", "destructive", "financial"}
        if modifies or _declares_write(tool.name):
            yield Finding(
                get("MCPS212"),
                "Tool declares readOnlyHint=true but its name/description indicates it modifies "
                "state or executes code",
                tool.locate("annotations", "readOnlyHint"),
                server=inv.server,
                tool=tool.name,
                field="annotations.readOnlyHint",
            )
    destructive = capability is not None and capability[0] == "destructive"
    if annotations.get("destructiveHint") is False and destructive:
        yield Finding(
            get("MCPS212"),
            "Tool declares destructiveHint=false but its name indicates a destructive operation",
            tool.locate("annotations", "destructiveHint"),
            server=inv.server,
            tool=tool.name,
            field="annotations.destructiveHint",
            severity=Severity.MEDIUM,
        )

    properties = tool.input_schema.get("properties")
    if not isinstance(properties, dict):
        return
    for name, schema in properties.items():
        if not isinstance(schema, dict):
            continue
        key = str(name).lower()
        context = normalize_for_matching(f"{tool.description} {schema.get('description', '')}")
        is_code = key in CODE_PARAMS or (key in {"query", "q"} and "sql" in context)
        if not is_code:
            continue
        kind = schema.get("type")
        if kind not in (None, "string") and not (isinstance(kind, list) and "string" in kind):
            continue
        if any(k in schema for k in ("enum", "const", "pattern")):
            continue
        yield Finding(
            get("MCPS213"),
            f"Parameter {name!r} accepts free-form code/commands without constraints",
            tool.locate("inputSchema", "properties", name),
            server=inv.server,
            tool=tool.name,
            field=f"inputSchema.properties.{name}",
        )
