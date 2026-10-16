"""Run every static rule over loaded configurations and tool inventories."""

from __future__ import annotations

from collections.abc import Iterable

from .jsonloc import SourceDocument
from .models import Finding, ServerConfig, ServerInventory
from .rules import capabilities, config, poisoning, secrets, unicode


def analyze(
    servers: Iterable[ServerConfig],
    inventories: Iterable[ServerInventory] = (),
    documents: Iterable[SourceDocument] = (),
) -> list[Finding]:
    inventories = list(inventories)
    findings: list[Finding] = []
    for doc in documents:
        findings.extend(config.check_document(doc))
    for server in servers:
        findings.extend(unicode.check_server_name(server))
        findings.extend(config.check_server(server))
        findings.extend(secrets.check_server(server))
    for inv in inventories:
        for tool in inv.tools:
            findings.extend(poisoning.check_tool(inv, tool))
            findings.extend(capabilities.check_tool(inv, tool))
        findings.extend(poisoning.check_instructions(inv))
    findings.extend(poisoning.check_cross_server(inventories))
    return finalize(findings)


def finalize(findings: Iterable[Finding]) -> list[Finding]:
    """De-duplicate (keeping the most severe) and sort most severe first."""
    unique: dict[str, Finding] = {}
    for finding in findings:
        key = finding.fingerprint()
        current = unique.get(key)
        if current is None or finding.severity > current.severity:
            unique[key] = finding
    return sorted(
        unique.values(),
        key=lambda f: (
            -int(f.severity),
            f.server or "",
            f.tool or "",
            f.rule.id,
            f.location.path or "",
            f.location.line or 0,
        ),
    )
