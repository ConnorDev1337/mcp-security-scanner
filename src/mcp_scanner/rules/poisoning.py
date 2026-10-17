"""MCPS101-MCPS110: tool poisoning, plus the text checks of MCPS120-MCPS122 and MCPS301.

Every text the model reads is scanned: tool titles and descriptions, parameter
descriptions, defaults and enums, output schemas, server ``instructions``, and
the names, titles and descriptions of prompts, prompt arguments, resources and
resource templates. Keyword rules match a normalized copy (hidden characters
removed, NFKC, homoglyphs folded) so trivial obfuscation does not evade them.
Payloads hidden in Unicode tag characters, variation selectors or base64 are
decoded and scanned too.
"""

from __future__ import annotations

import base64
import binascii
import bisect
import re
from collections import defaultdict
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace

from ..models import (
    Finding,
    Location,
    PromptDefinition,
    ResourceDefinition,
    ServerInventory,
    Severity,
    ToolDefinition,
)
from ..textutil import normalize_for_matching, redact, sanitize, snippet, strip_hidden
from . import secrets as secret_rules
from . import unicode as unicode_rules
from .catalog import get
from .resources import resource_key

OVERSIZED_DESCRIPTION = 5000  # Characters (MCPS110).
MAX_SCHEMA_DEPTH = 32


@dataclass(frozen=True)
class TextField:
    """One piece of tool or server metadata that the model reads."""

    parts: tuple[str | int, ...]  # JSON Pointer parts relative to the owner.
    label: str  # Human-readable, e.g. "description of parameter 'path'".
    text: str
    kind: str  # "description" | "parameter" | "value" | "name" | "instructions"

    @property
    def path(self) -> str:
        return ".".join(str(p) for p in self.parts)


@dataclass(frozen=True)
class _Pattern:
    rule_id: str
    regex: re.Pattern[str]
    severity: Severity | None = None
    raw: bool = False  # Match the text before normalization (hidden characters stripped).
    unless: re.Pattern[str] | None = None  # Discard matches whose sentence matches this.
    # Every match ends with this literal, so the text after its last occurrence is not
    # searched: a start there could only fail after scanning the rest of the text.
    tail: str | None = None


def _n(
    rule_id: str,
    pattern: str,
    severity: Severity | None = None,
    unless: re.Pattern[str] | None = None,
) -> _Pattern:
    """Build a pattern matched against the normalized (lowercase) text."""
    return _Pattern(rule_id, re.compile(pattern), severity, unless=unless)


def _r(
    rule_id: str, pattern: str, severity: Severity | None = None, tail: str | None = None
) -> _Pattern:
    """Build a case-insensitive pattern matched against the non-normalized text."""
    flags = re.IGNORECASE | re.DOTALL
    return _Pattern(rule_id, re.compile(pattern, flags), severity, raw=True, tail=tail)


_NEG = r"(?:do\s+not|don't|dont|never|must\s+not|mustn't|should\s+not|shouldn't|avoid)"
_TELL = (
    r"(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|notify(?:ing)?|alert(?:ing)?|reveal(?:ing)?|"
    r"show(?:ing)?|disclos(?:e|ing)|let(?:ting)?|warn(?:ing)?|explain(?:ing)?|say(?:ing)?)"
)
# Negated guidance ("do not include secrets") is advice, not an attack.
_NOT = r"(?<!not )(?<!never )(?<!n't )(?<!dont )(?<!no )"
_SECRETS = (
    r"(?:api[\s_\-]?keys?|passwords?|passphrases?|secrets?|credentials?|private[\s_\-]?keys?|"
    r"access[\s_\-]?tokens?|auth(?:entication)?[\s_\-]?tokens?|"
    r"session[\s_\-]?(?:cookies?|tokens?)|"
    r"cookies|\.env(?:\s+files?)?|environment\s+variables?)"
)
# A boolean option ("Whether Grafana should forward credentials such as cookies")
# describes what the server does, not what the model should do. Sentences with a
# clause break or addressed to "you" are not exempt.
_OPTION_SENTENCE = re.compile(r"^whether\b(?!\s+or\s+not\b)(?!.*\byou)[^,;:]*$")

PATTERNS: tuple[_Pattern, ...] = (
    # MCPS101 prompt-injection markup
    _n(
        "MCPS101",
        r"<\s*/?\s*(?:important|system|system[_\- ]?(?:prompt|message|instructions?)|"
        r"instructions?|secret|hidden|admin|assistant(?:[_\- ]?(?:instructions?|only))?|"
        r"ai[_\- ]?(?:instructions?|only|note)|"
        r"note[_\- ]?(?:to|for)[_\- ]?(?:the[_\- ]?)?(?:ai|assistant|model|llm|agent)|"
        r"model[_\- ]?instructions?|prompt)\b[^>]{0,40}>",
    ),
    _n(
        "MCPS101",
        r"<\|(?:im_start|im_end|system|user|assistant|endoftext|start_header_id|"
        r"end_header_id|eot_id)\|>",
    ),
    _n("MCPS101", r"\[/?inst\]|<<\s*/?sys\s*>>"),
    _n(
        "MCPS101", r"(?:^|\s)#{1,6}\s*(?:system|assistant)\s*(?:prompt|message|instructions?)?\s*:"
    ),
    _n(
        "MCPS101",
        r"\b(?:begin|start|end)\s+(?:of\s+)?(?:system|hidden|secret|admin)\s+"
        r"(?:prompt|instructions?|message)\b",
    ),
    # MCPS102 instruction override
    _n(
        "MCPS102",
        r"\b(?:ignore|disregard|forget|override|bypass|skip)\s+(?:all\s+|any\s+|every\s+)?"
        r"(?:of\s+)?(?:the\s+|your\s+|my\s+|these\s+|those\s+)?(?:previous|prior|above|earlier|"
        r"preceding|existing|original|initial|other|system|safety|security|developer)\s+"
        r"(?:instructions?|prompts?|rules?|directions?|guidelines?|messages?|constraints?|"
        r"polic(?:y|ies)|guardrails?)\b",
    ),
    _n("MCPS102", r"\byou\s+are\s+now\s+(?:a|an|in|the|acting|operating|free|no\s+longer)\b"),
    _n("MCPS102", r"\bfrom\s+now\s+on,?\s+you\s+(?:will|must|are|should)\b"),
    _n("MCPS102", r"\b(?:new|updated|real|actual|true)\s+(?:system\s+)?instructions?\s*:"),
    _n("MCPS102", r"\b(?:developer|god|admin|jailbreak|dan|unrestricted)\s+mode\b"),
    _n(
        "MCPS102",
        r"\bdo\s+not\s+follow\s+(?:the\s+|your\s+|any\s+)?(?:previous|system|original)\b",
    ),
    # MCPS103 concealment from the user
    _n("MCPS103", rf"\b{_NEG}\s+(?:ever\s+)?{_TELL}\b[^.!?]{{0,80}}?\buser\b"),
    _n(
        "MCPS103",
        r"\b(?:do\s+not|don't|dont|never)\s+(?:mention|reveal|disclose|report)\s+"
        r"(?:that|this|it|these|the\s+fact|anything\s+about)\b",
    ),
    _n(
        "MCPS103",
        r"\bwithout\s+(?:the\s+)?user'?s?\s+(?:knowledge|consent|permission|approval|"
        r"awareness|noticing|knowing)\b",
    ),
    _n(
        "MCPS103",
        r"\bwithout\s+(?:telling|informing|notifying|alerting|asking|warning)\s+"
        r"(?:the\s+)?(?:user|them|anyone)\b",
    ),
    _n(
        "MCPS103",
        r"\bwithout\s+(?:the\s+)?(?:user|them|anyone)\s+(?:knowing|noticing|"
        r"being\s+(?:told|informed|aware))\b",
    ),
    _n("MCPS103", r"\b(?:hide|conceal|keep|mask)\b[^.!?]{0,40}\bfrom\s+(?:the\s+)?user\b"),
    _n(
        "MCPS103",
        r"\b(?:the\s+)?user\s+(?:must|should|will|does|need|needs|is)\s*(?:not|never|n't)"
        r"\s+(?:to\s+)?(?:know|see|notice|be\s+(?:told|informed|aware|notified)|"
        r"find\s+out)\b",
    ),
    _n(
        "MCPS103",
        r"\buser\s+(?:won't|wont|doesn't|will\s+not|does\s+not|cannot|can't)\s+"
        r"(?:see|notice|know|find\s+out)\b",
    ),
    _n("MCPS103", r"\b(?:secretly|covertly|surreptitiously|stealthily)\b"),
    _n(
        "MCPS103",
        r"\b(?:silently|quietly|discreetly|invisibly)\s+(?:send|forward|copy|upload|"
        r"include|add|read|exfiltrate|transmit|call|invoke|post|bcc|cc|collect|attach|"
        r"append|log|save|store)\b",
    ),
    _n(
        "MCPS103",
        r"\b(?:not|never)\s+(?:be\s+)?(?:visible|shown|displayed|revealed)\s+to\s+"
        r"(?:the\s+)?user\b|\binvisible\s+to\s+(?:the\s+)?user\b",
    ),
    _n(
        "MCPS103",
        r"\b(?:keep|treat)\s+(?:this|it|these\s+instructions?)\s+(?:a\s+)?"
        r"(?:secret|confidential|private)\b",
    ),
    # MCPS104 sensitive data
    _n(
        "MCPS104",
        r"[\\/]\.ssh\b|~\s*/\s*\.ssh|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\bauthorized_keys\b|"
        r"\.aws[\\/](?:credentials|config)\b|\.azure[\\/]|\.config[\\/]gcloud\b|"
        r"application_default_credentials\.json|\.kube[\\/]config\b|\.docker[\\/]config\.json|"
        r"\.npmrc\b|\.pypirc\b|\.netrc\b|\.git-credentials\b|\.gnupg\b|/etc/(?:passwd|shadow|"
        r"sudoers)\b|\bclaude_desktop_config\.json\b|\bmcp\.json\b|\.claude\.json\b|"
        r"\bcline_mcp_settings\.json\b|\bmcp_config\.json\b|\.(?:bash|zsh)_history\b|"
        r"\bwallet\.dat\b|\blogin\s+data\b|\bkeychain\b|\b(?:seed|recovery)\s+phrase\b|"
        r"\bmnemonic\s+(?:phrase|words)\b",
    ),
    _n(
        "MCPS104",
        rf"{_NOT}\b(?:read|send|include|pass|forward|upload|provide|append|attach|copy|extract|"
        rf"collect|leak|post|share|output|print|dump)\b[^.!?]{{0,50}}?\b{_SECRETS}\b",
        Severity.MEDIUM,
        unless=_OPTION_SENTENCE,
    ),
    # MCPS105 exfiltration
    _n(
        "MCPS105",
        rf"{_NOT}\b(?:send|post|upload|forward|transmit|report|exfiltrate|submit|"
        r"beacon|leak|deliver|mail|email)\b[^.!?]{0,60}?\bhttps?://",
    ),
    _n(
        "MCPS105",
        r"\b(?:webhook\.site|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|"
        r"burpcollaborator\.net|oastify\.com|oast\.(?:fun|live|site|online|me|pro)|interact\.sh|"
        r"canarytokens\.(?:com|org)|hookbin\.com|beeceptor\.com|requestcatcher\.com|"
        r"trycloudflare\.com|pastebin\.com|transfer\.sh)\b",
    ),
    _n(
        "MCPS105",
        r"\b(?:curl|wget|invoke-webrequest|invoke-restmethod|iwr|irm)\b[^|]{0,120}\|\s*"
        r"(?:sudo\s+)?(?:sh|bash|zsh|python3?|node|iex|invoke-expression|pwsh|"
        r"powershell)\b",
    ),
    _n(
        "MCPS105",
        rf"{_NOT}\b(?:include|pass|put|add|append|provide|insert|attach|copy|paste|send|forward|"
        r"summari[sz]e)\b[^.!?]{0,60}?\b(?:(?:entire|full|whole|complete|previous|prior|earlier|"
        r"all)\s+(?:conversation|chat|dialog(?:ue)?|messages?|context)|(?:conversation|chat)\s+"
        r"history|system\s+prompt|(?:your|the)\s+instructions)\b",
    ),
    _n(
        "MCPS105",
        r"\b(?:pass|put|include|send|provide)\s+(?:its|their)\s+(?:full\s+|entire\s+|"
        r"raw\s+)?contents?\s+(?:as|in|into|via|through)\b",
    ),
    # MCPS106 cross-tool shadowing
    _n(
        "MCPS106",
        r"\bwhen\s+this\s+tool\s+is\s+(?:available|present|loaded|installed|enabled|"
        r"active|connected)\b",
    ),
    _n(
        "MCPS106",
        r"\b(?:the|any|all|every|each|other)\s+(?:other\s+)?[\w.\-]+\s+tools?\s+(?:must|should|"
        r"shall|will|needs?\s+to|has\s+to)\s+(?:always\s+|now\s+|also\s+|only\s+)?(?:send|"
        r"forward|redirect|include|add|bcc|cc|use\s+(?:the\s+)?(?:address|recipient|url|endpoint|"
        r"account))\b",
    ),
    _n(
        "MCPS106",
        r"\b(?:redirect|forward|send|bcc|cc|copy|reroute)\s+(?:all|every|any)\s+"
        r"(?:outgoing\s+)?(?:emails?|messages?|mails?|requests?|payments?|transactions?|"
        r"transfers?|funds|data|files?)\s+to\b",
    ),
    _n(
        "MCPS106",
        r"\b(?:change|replace|override|modify|swap|set)\s+(?:the\s+)?(?:recipient|"
        r"recipients|destination|receiver|to\s+address|account\s+number|iban|"
        r"wallet\s+address|beneficiary)\b",
    ),
    _n(
        "MCPS106",
        r"\b(?:before|after|instead\s+of)\s+(?:using|calling|invoking|running)\s+"
        r"(?:any|every|all|each)\s+(?:other\s+)?tools?\b",
        Severity.MEDIUM,
    ),
    _n(
        "MCPS106",
        r"\binstead\s+of\s+(?:using\s+|calling\s+)?(?:the\s+)?[\w.\-]+\s+tool\b",
        Severity.MEDIUM,
    ),
    # MCPS107 hidden content (matched before normalization)
    _r("MCPS107", r"<!--.*?-->", tail="-->"),
    _r(
        "MCPS107",
        r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em|rem)?"
        r"\b|opacity\s*:\s*0(?:\.0+)?\b|color\s*:\s*(?:transparent|white|#fff(?:fff)?\b)",
    ),
    _r("MCPS107", r"(?:[ \t]*\n){12,}|[ \t\u00a0]{80,}"),
    # MCPS108 model-directed imperatives
    _n(
        "MCPS108",
        r"\b(?:the\s+)?(?:ai|assistant|model|llm|agent|claude|chatgpt|gpt|copilot|"
        r"gemini)\s+(?:model\s+|assistant\s+|agent\s+)?(?:must|should|needs?\s+to|"
        r"has\s+to|is\s+required\s+to|shall)\b",
    ),
    _n(
        "MCPS108",
        r"\bit\s+is\s+(?:very\s+|extremely\s+|really\s+|absolutely\s+)?(?:important|"
        r"critical|crucial|essential|imperative|mandatory|vital)\s+(?:that\s+you|"
        r"for\s+you|to\s+always|to\s+never)\b",
    ),
    _n(
        "MCPS108",
        r"\byou\s+(?:must|have\s+to|need\s+to|should|are\s+required\s+to)\s+"
        r"(?:always|never|first|immediately|absolutely)\b",
    ),
    _n(
        "MCPS108",
        r"\bbefore\s+(?:using|calling|invoking|running)\s+(?:this|the)\s+(?:tool|"
        r"function)\s*,?\s*(?:you\s+)?(?:must|should|need\s+to|have\s+to|always)\b",
    ),
    _n("MCPS108", r"\b(?:very|extremely)\s+important\s*[:!]"),
)

_SUMMARY = {
    "MCPS101": "Prompt-injection markup",
    "MCPS102": "Instruction-override phrasing",
    "MCPS103": "Instruction to hide actions from the user",
    "MCPS104": "Reference to sensitive files or credentials",
    "MCPS105": "Data-exfiltration instruction",
    "MCPS106": "Attempt to alter other tools' behaviour",
    "MCPS107": "Content hidden from reviewers",
    "MCPS108": "Imperative addressed to the model",
    "MCPS109": "Encoded payload",
}

_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{48,}={0,2}(?![A-Za-z0-9+/=])")


@dataclass(frozen=True)
class TextHit:
    """The most severe match of one rule in one text; ``count`` totals all matches."""

    rule_id: str
    severity: Severity
    evidence: str
    count: int = 1
    note: str | None = None


def _decode_base64(blob: str) -> str | None:
    """Return the decoded text if ``blob`` is base64 of mostly printable UTF-8."""
    try:
        data = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        text = data.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    printable = sum(ch.isprintable() or ch in "\n\t" for ch in text)
    return text if len(text) >= 8 and printable / len(text) >= 0.9 else None


_SENTENCE_END = re.compile(r"[.!?]")


def _matches(pattern: _Pattern, subject: str) -> list[re.Match[str]]:
    """Return the matches of ``pattern`` in ``subject`` that its ``unless`` does not discard.

    ``unless`` is tested on the sentence that contains the match, found by bisecting
    the sentence ends and evaluated once per sentence, so the cost stays linear when
    one long sentence holds many matches.
    """
    end = len(subject)
    if pattern.tail is not None:
        last = subject.rfind(pattern.tail)
        if last < 0:
            return []
        end = last + len(pattern.tail)
    matches = list(pattern.regex.finditer(subject, 0, end))
    if pattern.unless is None or not matches:
        return matches
    marks = [mark.start() for mark in _SENTENCE_END.finditer(subject)]
    verdicts: dict[tuple[int, int], bool] = {}
    kept = []
    for match in matches:
        before = bisect.bisect_left(marks, match.start())
        after = bisect.bisect_left(marks, match.end())
        bounds = (
            marks[before - 1] + 1 if before else 0,
            marks[after] if after < len(marks) else len(subject),
        )
        if bounds not in verdicts:
            verdicts[bounds] = bool(pattern.unless.search(subject[bounds[0] : bounds[1]].strip()))
        if not verdicts[bounds]:
            kept.append(match)
    return kept


def scan_text(text: str, kind: str, _depth: int = 0) -> list[TextHit]:
    """Run the keyword and structure rules on ``text``.

    Return at most one hit per rule. Base64 payloads are decoded and scanned
    recursively, up to two levels deep.
    """
    normalized = normalize_for_matching(text)
    stripped = strip_hidden(text)
    hits: dict[str, TextHit] = {}

    def add(hit: TextHit) -> None:
        current = hits.get(hit.rule_id)
        if current is None:
            hits[hit.rule_id] = hit
        elif hit.severity > current.severity:
            hits[hit.rule_id] = replace(hit, count=hit.count + current.count)
        else:
            hits[hit.rule_id] = replace(current, count=current.count + hit.count)

    for pattern in PATTERNS:
        if kind == "instructions" and pattern.rule_id == "MCPS108":
            continue  # Server instructions legitimately address the model.
        subject = stripped if pattern.raw else normalized
        matches = _matches(pattern, subject)
        if matches:
            first = matches[0]
            add(
                TextHit(
                    pattern.rule_id,
                    pattern.severity or get(pattern.rule_id).severity,
                    snippet(subject, first.start(), first.end()),
                    len(matches),
                )
            )

    if _depth < 2:
        for match in _BASE64.finditer(stripped):
            decoded = _decode_base64(match.group())
            if decoded is None:
                continue
            add(
                TextHit(
                    "MCPS109",
                    get("MCPS109").severity,
                    f"base64 decodes to {sanitize(decoded, 120)!r}",
                )
            )
            for inner in scan_text(decoded, kind, _depth + 1):
                add(replace(inner, note="inside base64 payload"))
    return list(hits.values())


# --------------------------------------------------------------------------- text fields


def _schema_fields(
    schema: object, parts: tuple[str | int, ...], param: str, root: str, depth: int
) -> Iterator[TextField]:
    """Yield the text fields of a JSON Schema, recursing into nested schemas."""
    if depth > MAX_SCHEMA_DEPTH or not isinstance(schema, dict):
        return
    where = f"parameter '{param}'" if param else root
    for key in ("description", "title"):
        if isinstance(schema.get(key), str):
            yield TextField((*parts, key), f"{key} of {where}", schema[key], "parameter")
    for key in ("default", "const"):
        if isinstance(schema.get(key), str):
            yield TextField((*parts, key), f"{key} value of {where}", schema[key], "value")
    for key in ("enum", "examples"):
        values = schema.get(key)
        if isinstance(values, list):
            for index, value in enumerate(values):
                if isinstance(value, str):
                    yield TextField(
                        (*parts, key, index), f"{key} value of {where}", value, "value"
                    )
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, sub in properties.items():
            child = f"{param}.{name}" if param else str(name)
            prop_parts = (*parts, "properties", name)
            yield TextField(prop_parts, f"name of parameter '{child}'", str(name), "name")
            yield from _schema_fields(sub, prop_parts, child, root, depth + 1)
    for key in ("items", "additionalProperties", "not"):
        sub = schema.get(key)
        sub_param = f"{param}[]" if key == "items" and param else param
        if isinstance(sub, dict):
            yield from _schema_fields(sub, (*parts, key), sub_param, root, depth + 1)
        elif key == "items" and isinstance(sub, list):
            for index, item in enumerate(sub):
                yield from _schema_fields(item, (*parts, key, index), sub_param, root, depth + 1)
    for key in ("anyOf", "oneOf", "allOf"):
        variants = schema.get(key)
        if isinstance(variants, list):
            for index, item in enumerate(variants):
                yield from _schema_fields(item, (*parts, key, index), param, root, depth + 1)
    for key in ("$defs", "definitions", "patternProperties"):
        defs = schema.get(key)
        if isinstance(defs, dict):
            for name, item in defs.items():
                yield from _schema_fields(
                    item, (*parts, key, name), param or str(name), root, depth + 1
                )


def tool_text_fields(tool: ToolDefinition) -> Iterator[TextField]:
    """Yield every text of ``tool`` that the model reads, including schema contents."""
    raw = tool.raw
    yield TextField(("name",), "tool name", tool.name, "name")
    if isinstance(raw.get("title"), str):
        yield TextField(("title",), "tool title", raw["title"], "description")
    if isinstance(raw.get("description"), str):
        yield TextField(("description",), "tool description", raw["description"], "description")
    annotations = raw.get("annotations")
    if isinstance(annotations, dict) and isinstance(annotations.get("title"), str):
        yield TextField(
            ("annotations", "title"), "annotation title", annotations["title"], "description"
        )
    yield from _schema_fields(raw.get("inputSchema"), ("inputSchema",), "", "input schema", 0)
    yield from _schema_fields(raw.get("outputSchema"), ("outputSchema",), "", "output schema", 0)


# --------------------------------------------------------------------------- findings


def _field_findings(
    field: TextField,
    locate: Callable[..., Location],
    server: str,
    tool: str | None,
    *,
    prompt: str | None = None,
    resource: str | None = None,
) -> Iterator[Finding]:
    location = locate(*field.parts)

    def make(
        rule_id: str, message: str, evidence: str | None, severity: Severity | None
    ) -> Finding:
        return Finding(
            get(rule_id),
            message,
            location,
            server=server,
            tool=tool,
            field=field.path,
            evidence=evidence,
            severity=severity,
            prompt=prompt,
            resource=resource,
        )

    for issue in unicode_rules.analyze_text(field.text):
        yield make(issue.rule_id, f"{issue.kind} in {field.label}", issue.evidence, issue.severity)
        if issue.decoded:
            for hit in scan_text(issue.decoded, field.kind):
                message = f"{_SUMMARY[hit.rule_id]} in {field.label} (hidden in invisible Unicode)"
                yield make(hit.rule_id, message, hit.evidence, max(hit.severity, Severity.HIGH))

    if field.kind == "name":
        problem = unicode_rules.identifier_issue(field.text)
        if problem:
            severity, why = problem
            message = f"{field.label.capitalize()} {sanitize(field.text)!r} {why}"
            yield make("MCPS122", message, None, severity)
        return

    for hit in scan_text(field.text, field.kind):
        message = f"{_SUMMARY[hit.rule_id]} in {field.label}"
        if hit.note:
            message += f" ({hit.note})"
        if hit.count > 1:
            message += f" [{hit.count} matches]"
        yield make(hit.rule_id, message, hit.evidence, hit.severity)

    for pattern, secret in secret_rules.find_known_secrets(field.text):
        message = f"{pattern.label} embedded in {field.label}"
        yield make("MCPS301", message, redact(secret), pattern.severity)


def check_tool(inv: ServerInventory, tool: ToolDefinition) -> Iterator[Finding]:
    for field in tool_text_fields(tool):
        yield from _field_findings(field, tool.locate, inv.server, tool.name)
    length = len(tool.description)
    if length > OVERSIZED_DESCRIPTION:
        yield Finding(
            get("MCPS110"),
            f"Tool description is {length} characters long",
            tool.locate("description"),
            server=inv.server,
            tool=tool.name,
            field="description",
        )


def check_instructions(inv: ServerInventory) -> Iterator[Finding]:
    if inv.instructions:
        field = TextField(
            ("instructions",), "server instructions", inv.instructions, "instructions"
        )
        yield from _field_findings(field, inv.locate, inv.server, None)


def _distinctive(name: str) -> bool:
    """Return whether a tool name is specific enough to search for in free text."""
    return len(name) >= 5 and bool(re.search(r"[_\-.]|[a-z][A-Z]", name))


def _own_names(inv: ServerInventory) -> set[str]:
    """Return the names a server defines itself: its tool names and enum/const values.

    Servers that multiplex operations through one tool (``"method": "create_project"``)
    mention those operations by name; that is not a reference to another server's tool.
    """
    names = {tool.name for tool in inv.tools}
    for tool in inv.tools:
        for field in tool_text_fields(tool):
            if field.kind == "value" and (field.parts[-1] == "const" or field.parts[-2] == "enum"):
                names.add(field.text)
    return names


def check_cross_server(inventories: list[ServerInventory]) -> Iterator[Finding]:
    """Report tool names shared by several servers and references to other servers' tools."""
    owners: dict[str, list[str]] = defaultdict(list)
    for inv in inventories:
        for tool in inv.tools:
            if inv.server not in owners[tool.name]:
                owners[tool.name].append(inv.server)

    for inv in inventories:
        for tool in inv.tools:
            others = [s for s in owners[tool.name] if s != inv.server]
            if others:
                yield Finding(
                    get("MCPS106"),
                    f"Tool name {tool.name!r} is also exposed by server(s) {', '.join(others)}; "
                    "the model may call the wrong one",
                    tool.locate("name"),
                    server=inv.server,
                    tool=tool.name,
                    field="name",
                    severity=Severity.MEDIUM,
                )

    candidates = {name: servers for name, servers in owners.items() if _distinctive(name)}
    for inv in inventories:
        # Names the server defines itself are its own vocabulary (tool-name clashes are
        # reported above).
        own = _own_names(inv)
        texts: list[tuple[ToolDefinition | None, str]] = [
            (tool, " ".join(f.text for f in tool_text_fields(tool) if f.kind != "name"))
            for tool in inv.tools
        ]
        if inv.instructions:
            texts.append((None, inv.instructions))
        for tool, text in texts:
            for name, servers in candidates.items():
                foreign = [s for s in servers if s != inv.server]
                # The substring test is a cheap pre-filter: this loop is quadratic in tools.
                if not foreign or name in own or name not in text:
                    continue
                if re.search(rf"(?<![\w\-]){re.escape(name)}(?![\w\-])", text):
                    where = f"tool {tool.name!r}" if tool else "server instructions"
                    yield Finding(
                        get("MCPS106"),
                        f"Metadata of {where} references tool {name!r} of server(s) "
                        f"{', '.join(foreign)}",
                        tool.locate("description") if tool else inv.locate("instructions"),
                        server=inv.server,
                        tool=tool.name if tool else None,
                        field="description" if tool else "instructions",
                        evidence=name,
                        severity=Severity.MEDIUM,
                    )


# --------------------------------------------------------------------------- prompts and resources


def prompt_text_fields(prompt: PromptDefinition) -> Iterator[TextField]:
    """Yield every text of ``prompt`` listed by ``prompts/list``, argument texts included."""
    raw = prompt.raw
    yield TextField(("name",), "prompt name", prompt.name, "name")
    if isinstance(raw.get("title"), str):
        yield TextField(("title",), "prompt title", raw["title"], "description")
    if isinstance(raw.get("description"), str):
        yield TextField(("description",), "prompt description", raw["description"], "description")
    for index, argument in enumerate(prompt.arguments):
        if not isinstance(argument, dict):
            continue
        name = argument.get("name")
        where = (
            f"prompt argument '{name}'" if isinstance(name, str) else f"prompt argument #{index}"
        )
        if isinstance(name, str):
            yield TextField(("arguments", index, "name"), f"name of {where}", name, "name")
        for key in ("title", "description"):
            if isinstance(argument.get(key), str):
                yield TextField(
                    ("arguments", index, key), f"{key} of {where}", argument[key], "parameter"
                )


def resource_text_fields(resource: ResourceDefinition) -> Iterator[TextField]:
    """Yield the texts of a resource or resource template, except its URI.

    Resource names are display names (often file names), so they are scanned as
    text rather than checked as identifiers. The URI is checked by
    :mod:`.resources`.
    """
    raw = resource.raw
    for key, kind in (
        ("name", "description"),
        ("title", "description"),
        ("description", "description"),
        ("mimeType", "value"),
    ):
        if isinstance(raw.get(key), str):
            yield TextField((key,), f"{resource.kind} {key}", raw[key], kind)


def _oversized(
    what: str, description: str, locate: Callable[..., Location], **subject: str | None
) -> Iterator[Finding]:
    if len(description) > OVERSIZED_DESCRIPTION:
        yield Finding(
            get("MCPS110"),
            f"{what} description is {len(description)} characters long",
            locate("description"),
            field="description",
            **subject,
        )


def check_prompt(inv: ServerInventory, prompt: PromptDefinition) -> Iterator[Finding]:
    for field in prompt_text_fields(prompt):
        yield from _field_findings(field, prompt.locate, inv.server, None, prompt=prompt.name)
    yield from _oversized(
        "Prompt", prompt.description, prompt.locate, server=inv.server, prompt=prompt.name
    )


def check_resource(inv: ServerInventory, resource: ResourceDefinition) -> Iterator[Finding]:
    key = resource_key(resource)
    for field in resource_text_fields(resource):
        yield from _field_findings(field, resource.locate, inv.server, None, resource=key)
    yield from _oversized(
        resource.kind.capitalize(),
        resource.description,
        resource.locate,
        server=inv.server,
        resource=key,
    )


def check_prompt_resource_references(inventories: list[ServerInventory]) -> Iterator[Finding]:
    """Report prompts and resources whose metadata names a tool of another server (MCPS106)."""
    owners: dict[str, set[str]] = defaultdict(set)
    for inv in inventories:
        for tool in inv.tools:
            owners[tool.name].add(inv.server)
    candidates = [
        (name, servers, re.compile(rf"(?<![\w\-]){re.escape(name)}(?![\w\-])"))
        for name, servers in owners.items()
        if _distinctive(name)
    ]
    if not candidates:
        return
    for inv in inventories:
        items: list[tuple[str, Callable[..., Location], dict[str, str], list[TextField]]] = [
            (f"prompt {p.name!r}", p.locate, {"prompt": p.name}, list(prompt_text_fields(p)))
            for p in inv.prompts or ()
        ]
        for resource in inv.all_resources():
            key = resource_key(resource)
            fields = list(resource_text_fields(resource))
            items.append((f"{resource.kind} {key!r}", resource.locate, {"resource": key}, fields))
        own = _own_names(inv) if items else set()
        for label, locate, subject, fields in items:
            texts = [f for f in fields if f.kind != "name"]
            joined = " ".join(f.text for f in texts)
            for name, servers, pattern in candidates:
                foreign = sorted(servers - {inv.server})
                # Same exemptions and substring pre-filter as check_cross_server.
                if not foreign or name in own or name not in joined:
                    continue
                hit = next((f for f in texts if pattern.search(f.text)), None)
                if hit is None:
                    continue
                yield Finding(
                    get("MCPS106"),
                    f"Metadata of {label} references tool {name!r} of server(s) "
                    f"{', '.join(foreign)}",
                    locate(*hit.parts),
                    server=inv.server,
                    field=hit.path,
                    evidence=name,
                    severity=Severity.MEDIUM,
                    **subject,
                )
