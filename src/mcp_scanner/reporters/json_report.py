"""Machine-readable JSON report (secrets masked)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .. import TOOL_NAME, __version__
from ..models import Finding, ResourceDefinition, ServerInventory, Severity
from ..rules.resources import resource_key
from ..rules.secrets import mask, mask_args
from ..scanner import ScanReport
from . import display_path

SCHEMA_ID = "mcp-security-scanner/report/v1"


def _finding(finding: Finding, root: Path) -> dict[str, Any]:
    location = finding.location
    return {
        "rule_id": finding.rule.id,
        "rule_name": finding.rule.name,
        "title": finding.rule.title,
        "category": finding.rule.category,
        "severity": finding.severity.label,
        "message": finding.message,
        "server": finding.server,
        "tool": finding.tool,
        "prompt": finding.prompt,
        "resource": finding.resource,
        "field": finding.field,
        "evidence": finding.evidence,
        "location": {
            "path": display_path(location.path, root) if location.path else None,
            "line": location.line,
            "column": location.column,
            "pointer": location.pointer or None,
        },
        "remediation": finding.rule.remediation,
        "fingerprint": finding.fingerprint(),
    }


def _keys(resources: list[ResourceDefinition] | None) -> list[str] | None:
    return None if resources is None else [resource_key(r) for r in resources]


def _counts(inv: ServerInventory | None) -> tuple[int | None, int | None]:
    """Return the prompt and resource (plus template) counts; None when not collected."""
    if inv is None:
        return None, None
    prompts = None if inv.prompts is None else len(inv.prompts)
    if inv.resources is None and inv.resource_templates is None:
        return prompts, None
    return prompts, len(inv.all_resources())


def _inventory(inv: ServerInventory) -> dict[str, Any]:
    """Summarize an inventory; None marks kinds that were not collected."""
    return {
        "server": inv.server,
        "origin": inv.origin,
        "tools": [t.name for t in inv.tools],
        "prompts": None if inv.prompts is None else [p.name for p in inv.prompts],
        "resources": _keys(inv.resources),
        "resource_templates": _keys(inv.resource_templates),
    }


def build(
    report: ScanReport, *, root: Path | None = None, min_severity: Severity = Severity.INFO
) -> dict[str, Any]:
    """Return the report as a JSON-serializable dict (schema ``SCHEMA_ID``)."""
    root = root or Path.cwd()
    findings = [f for f in report.findings if f.severity >= min_severity]
    tools_by_server = {inv.server: inv for inv in report.inventories}
    servers = []
    for server in report.servers:
        location = server.locate()
        inventory = tools_by_server.get(server.name)
        prompt_count, resource_count = _counts(inventory)
        servers.append(
            {
                "name": server.name,
                "client": server.client,
                "scope": server.scope,
                "transport": server.transport,
                "command": mask(server.command) if server.command else None,
                "args": mask_args(server.args),
                "url": mask(server.url) if server.url else None,
                "env_keys": sorted(mask(key) for key in server.env),
                "header_keys": sorted(mask(key) for key in server.headers),
                "source": display_path(location.path, root) if location.path else None,
                "line": location.line,
                "tools": len(inventory.tools) if inventory else None,
                "prompts": prompt_count,
                "resources": resource_count,
                "tools_origin": inventory.origin if inventory else None,
            }
        )
    configured = {s.name for s in report.servers}
    inventories = [_inventory(inv) for inv in report.inventories]
    pins = None
    if report.pins:
        pins = {
            "path": display_path(report.pins.path, root),
            "mode": report.pins.mode,
            "pinned_servers": report.pins.pinned_servers,
            "pinned_tools": report.pins.pinned_tools,
            "pinned_prompts": report.pins.pinned_prompts,
            "pinned_resources": report.pins.pinned_resources,
            "approved_changes": report.pins.approved_changes,
        }
    return {
        "schema": SCHEMA_ID,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "started_at": report.started_at,
        "finished_at": report.finished_at,
        "summary": {
            "servers": len(report.servers),
            "manifest_only_servers": sorted(
                inv.server for inv in report.inventories if inv.server not in configured
            ),
            "tools": report.tool_count,
            "prompts": report.prompt_count,
            "resources": report.resource_count,
            "resource_templates": report.resource_template_count,
            "findings": len(findings),
            "by_severity": report.counts(findings),
        },
        "servers": servers,
        "inventories": inventories,
        "findings": [_finding(f, root) for f in findings],
        "pins": pins,
        "notices": [
            {
                "level": n.level,
                "message": mask(n.message),
                "path": display_path(n.path, root) if n.path else None,
            }
            for n in report.notices
        ],
    }


def render(
    report: ScanReport, *, root: Path | None = None, min_severity: Severity = Severity.INFO
) -> str:
    """Serialize :func:`build` as indented JSON."""
    payload = build(report, root=root, min_severity=min_severity)
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
