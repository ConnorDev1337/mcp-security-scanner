"""MCPS120-MCPS122: invisible Unicode, control characters, confusable names."""

from __future__ import annotations

import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass

from ..models import Finding, ServerConfig, Severity
from ..textutil import INVISIBLE_EXTRA, is_hidden_char, is_tag_char, is_variation_selector, sanitize
from .catalog import get

BIDI_CONTROLS = frozenset({0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)})
ZERO_WIDTH = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF})
ZERO_WIDTH |= INVISIBLE_EXTRA


@dataclass(frozen=True)
class UnicodeIssue:
    rule_id: str
    severity: Severity
    kind: str
    codepoints: tuple[int, ...]
    decoded: str | None = None

    @property
    def evidence(self) -> str:
        unique = sorted(set(self.codepoints))
        shown = ", ".join(f"U+{cp:04X}" for cp in unique[:6])
        if len(unique) > 6:
            shown += ", ..."
        text = f"{len(self.codepoints)} char(s): {shown}"
        if self.decoded:
            text += f"; decoded hidden text: {sanitize(self.decoded, 160)!r}"
        return text


def _joiner_is_legit(text: str, index: int) -> bool:
    """ZWJ/ZWNJ are legitimate inside emoji sequences and some scripts."""
    if index == 0 or index + 1 >= len(text):
        return False
    return ord(text[index - 1]) > 0x7F and ord(text[index + 1]) > 0x7F


def _decode_tags(codepoints: list[int]) -> str:
    return "".join(chr(cp - 0xE0000) for cp in codepoints if 0xE0020 <= cp <= 0xE007E)


def _decode_selectors(run: list[int]) -> str:
    data = bytes(cp - 0xFE00 if cp <= 0xFE0F else cp - 0xE0100 + 16 for cp in run)
    return data.decode("utf-8", errors="replace")


def _readable(text: str) -> bool:
    return sum(ch.isalnum() for ch in text) >= 3


def analyze_text(text: str) -> list[UnicodeIssue]:
    tags: list[int] = []
    bidi: list[int] = []
    zero: list[int] = []
    fmt: list[int] = []
    pua: list[int] = []
    ctrl: list[int] = []
    selector_runs: list[list[int]] = []
    run: list[int] = []

    for index, ch in enumerate(text):
        cp = ord(ch)
        if is_variation_selector(cp):
            run.append(cp)
            continue
        if len(run) >= 2:  # a single selector is normal (emoji presentation)
            selector_runs.append(run)
        run = []
        if is_tag_char(cp):
            tags.append(cp)
        elif cp in BIDI_CONTROLS:
            bidi.append(cp)
        elif cp in ZERO_WIDTH:
            if cp in (0x200C, 0x200D) and _joiner_is_legit(text, index):
                continue
            zero.append(cp)
        else:
            category = unicodedata.category(ch)
            if category == "Cc" and ch not in "\t\n\r":
                ctrl.append(cp)
            elif category in {"Cf", "Zl", "Zp"}:
                fmt.append(cp)
            elif category == "Co":
                pua.append(cp)
    if len(run) >= 2:
        selector_runs.append(run)

    issues: list[UnicodeIssue] = []
    if tags:
        decoded = _decode_tags(tags)
        severity = Severity.CRITICAL if _readable(decoded) else Severity.HIGH
        issues.append(
            UnicodeIssue(
                "MCPS120",
                severity,
                "Unicode tag characters (ASCII smuggling)",
                tuple(tags),
                decoded or None,
            )
        )
    for selectors in selector_runs:
        decoded = _decode_selectors(selectors)
        readable = _readable(decoded)
        issues.append(
            UnicodeIssue(
                "MCPS120",
                Severity.CRITICAL if readable else Severity.HIGH,
                "variation-selector sequence (data smuggling)",
                tuple(selectors),
                decoded if readable else None,
            )
        )
    if bidi:
        issues.append(
            UnicodeIssue("MCPS120", Severity.HIGH, "bidirectional control characters", tuple(bidi))
        )
    if zero:
        issues.append(UnicodeIssue("MCPS120", Severity.HIGH, "zero-width characters", tuple(zero)))
    if fmt:
        issues.append(
            UnicodeIssue("MCPS120", Severity.MEDIUM, "invisible format characters", tuple(fmt))
        )
    if pua:
        issues.append(UnicodeIssue("MCPS120", Severity.LOW, "private-use characters", tuple(pua)))
    if ctrl:
        kind = "ANSI escape sequence" if 0x1B in ctrl else "control characters"
        issues.append(UnicodeIssue("MCPS121", Severity.HIGH, kind, tuple(ctrl)))
    return issues


def _script(ch: str) -> str:
    try:
        return unicodedata.name(ch).split()[0]
    except ValueError:
        return "UNKNOWN"


def identifier_issue(name: str) -> tuple[Severity, str] | None:
    """Return ``(severity, explanation)`` for non-ASCII or mixed-script names."""
    visible = [ch for ch in name if ord(ch) > 0x7F and not is_hidden_char(ch)]
    if not visible:
        return None
    scripts = sorted({_script(ch) for ch in name if ch.isalpha()})
    if len(scripts) > 1:
        return Severity.HIGH, f"mixes scripts ({', '.join(scripts)})"
    shown = ", ".join(f"U+{ord(ch):04X}" for ch in visible[:5])
    return Severity.MEDIUM, f"contains non-ASCII characters ({shown})"


def check_server_name(server: ServerConfig) -> Iterator[Finding]:
    location = server.locate()
    for issue in analyze_text(server.name):
        yield Finding(
            get(issue.rule_id),
            f"Server name contains {issue.kind}",
            location,
            server=server.name,
            field="name",
            evidence=issue.evidence,
            severity=issue.severity,
        )
    problem = identifier_issue(server.name)
    if problem:
        severity, why = problem
        yield Finding(
            get("MCPS122"),
            f"Server name {sanitize(server.name)!r} {why}",
            location,
            server=server.name,
            field="name",
            severity=severity,
        )
