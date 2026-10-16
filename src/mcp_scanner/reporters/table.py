"""Human-readable console report (ASCII only, safe on any terminal)."""

from __future__ import annotations

import shutil
import textwrap
from pathlib import Path

from .. import TOOL_NAME, __version__
from ..models import Finding, Severity
from ..rules.secrets import mask
from ..scanner import ScanReport
from ..textutil import sanitize
from . import display_path

COLORS = {
    Severity.CRITICAL: "\x1b[1;97;41m",
    Severity.HIGH: "\x1b[1;31m",
    Severity.MEDIUM: "\x1b[33m",
    Severity.LOW: "\x1b[36m",
    Severity.INFO: "\x1b[2m",
}
RESET = "\x1b[0m"
SEV_W, RULE_W = 8, 7


def _wrap(text: str, width: int) -> list[str]:
    lines: list[str] = []
    for paragraph in text.split("\n"):
        lines.extend(
            textwrap.wrap(paragraph, width, break_long_words=True, break_on_hyphens=False) or [""]
        )
    return lines


def _rule(widths: list[int]) -> str:
    return "+" + "+".join("-" * (w + 2) for w in widths) + "+"


def _row(cells: list[list[str]], widths: list[int], color: str | None = None) -> list[str]:
    height = max(len(c) for c in cells)
    out = []
    for i in range(height):
        parts = []
        for col, (cell, width) in enumerate(zip(cells, widths, strict=True)):
            text = (cell[i] if i < len(cell) else "").ljust(width)
            if col == 0 and color and i == 0:
                text = f"{color}{text}{RESET}"
            parts.append(f" {text} ")
        out.append("|" + "|".join(parts) + "|")
    return out


def _finding_cells(finding: Finding, root: Path, target_w: int, text_w: int) -> list[list[str]]:
    detail = sanitize(finding.message, 1000)
    if finding.evidence:
        detail += f"\nevidence: {sanitize(finding.evidence, 400)}"
    location = display_path(finding.location.path, root)
    if finding.location.line:
        location += f":{finding.location.line}"
    detail += f"\nat {location}"
    return [
        [finding.severity.label.upper()],
        [finding.rule.id],
        _wrap(sanitize(finding.target, 200), target_w),
        _wrap(detail, text_w),
    ]


def render(
    report: ScanReport,
    *,
    color: bool = False,
    width: int | None = None,
    root: Path | None = None,
    min_severity: Severity = Severity.INFO,
) -> str:
    root = root or Path.cwd()
    width = max(width or shutil.get_terminal_size((120, 24)).columns, 80)
    findings = [f for f in report.findings if f.severity >= min_severity]
    lines = [f"{TOOL_NAME} {__version__}"]

    sources = sorted({display_path(s.source.path, root) for s in report.servers if s.source})
    lines.append(
        f"Scanned {len(report.servers)} server(s) from {len(sources)} config file(s); "
        f"{report.tool_count} tool definition(s) from {len(report.inventories)} inventory(ies)."
    )
    for source in sources:
        lines.append(f"  - {source}")
    lines.append("")

    if findings:
        target_w = min(28, max(len(sanitize(f.target, 200)) for f in findings))
        target_w = max(target_w, 6)
        text_w = width - (SEV_W + RULE_W + target_w) - 13
        widths = [SEV_W, RULE_W, target_w, text_w]
        lines.append(_rule(widths))
        lines.extend(_row([["SEVERITY"], ["RULE"], ["TARGET"], ["FINDING"]], widths))
        lines.append(_rule(widths).replace("-", "="))
        for finding in findings:
            cells = _finding_cells(finding, root, target_w, text_w)
            lines.extend(_row(cells, widths, COLORS[finding.severity] if color else None))
            lines.append(_rule(widths))
    else:
        lines.append("No findings.")

    counts = report.counts(findings)
    summary = ", ".join(f"{n} {label}" for label, n in counts.items() if n) or "none"
    lines.append(f"Findings: {summary}.")
    hidden = len(report.findings) - len(findings)
    if hidden:
        lines.append(f"({hidden} finding(s) below --min-severity {min_severity.label} not shown)")

    if report.pins:
        pins = report.pins
        detail = []
        if pins.pinned_servers:
            detail.append(f"{len(pins.pinned_servers)} server(s) pinned on first use")
        if pins.pinned_tools:
            detail.append(f"{pins.pinned_tools} tool(s) pinned")
        if pins.approved_changes:
            detail.append(f"{pins.approved_changes} change(s) approved")
        suffix = f": {', '.join(detail)}" if detail else ""
        lines.append(f"Pins ({pins.mode}): {display_path(pins.path, root)}{suffix}")

    if report.notices:
        lines.append("Notices:")
        for notice in report.notices:
            where = f"{display_path(notice.path, root)}: " if notice.path else ""
            lines.append(f"  [{notice.level}] {where}{sanitize(mask(notice.message), 500)}")
    return "\n".join(lines) + "\n"
