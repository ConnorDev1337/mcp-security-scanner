"""SARIF 2.1.0 output for GitHub Code Scanning and other SARIF consumers.

* Every rule in the catalog is listed with ``security-severity`` so GitHub
  ranks alerts as critical/high/medium/low.
* Paths under ``root`` are emitted relative to ``%SRCROOT%`` so alerts are
  annotated on the right file in the repository.
* ``partialFingerprints`` carry a stable hash so alerts survive line shifts.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .. import TOOL_NAME, __version__
from ..models import Finding, Location, Rule, Severity
from ..rules.catalog import all_rules
from ..rules.secrets import mask
from ..scanner import ScanReport

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub ranks security-severity >= 9.0 as critical, >= 7.0 high, >= 4.0 medium, else low.
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}
NOTICE_LEVELS = {"error": "error", "warning": "warning", "note": "note"}


def artifact_location(path: str, root: Path) -> dict[str, str]:
    """Return a SARIF artifactLocation, relative to ``%SRCROOT%`` when under ``root``."""
    absolute = Path(os.path.abspath(path))
    try:
        relative = absolute.relative_to(os.path.abspath(root))
    except ValueError:
        return {"uri": absolute.as_uri()}
    return {"uri": quote(relative.as_posix()), "uriBaseId": "%SRCROOT%"}


def _physical(location: Location, root: Path) -> dict[str, Any] | None:
    if not location.path:
        return None
    physical: dict[str, Any] = {"artifactLocation": artifact_location(location.path, root)}
    if location.line:
        region: dict[str, int] = {"startLine": location.line}
        if location.column:
            region["startColumn"] = location.column
        physical["region"] = region
    return physical


def _rule_descriptor(rule: Rule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.name,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description},
        "help": {
            "text": f"{rule.description}\n\nRemediation: {rule.remediation}",
            "markdown": f"**{rule.title}**\n\n{rule.description}\n\n"
            f"**Remediation:** {rule.remediation}",
        },
        "defaultConfiguration": {"level": LEVELS[rule.severity]},
        "properties": {
            "tags": ["security", rule.category, "mcp"],
            "precision": "medium",
            "problem.severity": "error"
            if rule.severity >= Severity.HIGH
            else LEVELS[rule.severity],
            "security-severity": SECURITY_SEVERITY[rule.severity],
        },
    }


def _result(finding: Finding, index: dict[str, int], root: Path) -> dict[str, Any]:
    text = finding.message
    if finding.evidence:
        text += f"\nEvidence: {finding.evidence}"
    location: dict[str, Any] = {}
    physical = _physical(finding.location, root)
    if physical:
        location["physicalLocation"] = physical
    if finding.server:
        location["logicalLocations"] = [
            {"name": finding.tool or finding.server, "fullyQualifiedName": finding.target}
        ]
    result: dict[str, Any] = {
        "ruleId": finding.rule.id,
        "ruleIndex": index[finding.rule.id],
        "level": LEVELS[finding.severity],
        "message": {"text": text},
        "partialFingerprints": {"mcpScanner/v1": finding.fingerprint()},
        "properties": {
            "severity": finding.severity.label,
            "server": finding.server,
            "tool": finding.tool,
            "field": finding.field,
        },
    }
    if location:
        result["locations"] = [location]
    return result


def build(
    report: ScanReport, *, root: Path | None = None, min_severity: Severity = Severity.INFO
) -> dict[str, Any]:
    root = root or Path.cwd()
    rules = all_rules()
    index = {rule.id: i for i, rule in enumerate(rules)}
    findings = [f for f in report.findings if f.severity >= min_severity]
    notifications = []
    for notice in report.notices:
        item: dict[str, Any] = {
            "level": NOTICE_LEVELS.get(notice.level, "note"),
            "message": {"text": mask(notice.message)},
        }
        if notice.path:
            item["locations"] = [
                {"physicalLocation": {"artifactLocation": artifact_location(notice.path, root)}}
            ]
        notifications.append(item)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "semanticVersion": __version__,
                        "rules": [_rule_descriptor(rule) for rule in rules],
                    }
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": Path(os.path.abspath(root)).as_uri() + "/"}
                },
                "invocations": [
                    {
                        "executionSuccessful": not any(n.level == "error" for n in report.notices),
                        "startTimeUtc": report.started_at,
                        "endTimeUtc": report.finished_at,
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "columnKind": "unicodeCodePoints",
                "results": [_result(f, index, root) for f in findings],
            }
        ],
    }


def render(
    report: ScanReport, *, root: Path | None = None, min_severity: Severity = Severity.INFO
) -> str:
    payload = build(report, root=root, min_severity=min_severity)
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
