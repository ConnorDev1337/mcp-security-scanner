"""MCPS301-MCPS303: plaintext secrets in configuration and tool metadata.

Detected values are always redacted before they reach a Finding, so reports
(which may be uploaded to GitHub as SARIF) never contain the secret itself.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from ..models import Finding, ServerConfig, Severity
from ..textutil import redact, sanitize, shannon_entropy
from .catalog import get


@dataclass(frozen=True)
class SecretPattern:
    label: str
    regex: re.Pattern[str]
    severity: Severity = Severity.CRITICAL


def _p(label: str, pattern: str, severity: Severity = Severity.CRITICAL) -> SecretPattern:
    return SecretPattern(label, re.compile(pattern), severity)


# Order matters: more specific prefixes first (sk-ant- before sk-).
KNOWN_SECRETS: tuple[SecretPattern, ...] = (
    _p("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    _p("OpenAI API key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}"),
    _p("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    _p("GitHub fine-grained token", r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"),
    _p("GitLab token", r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    _p("AWS access key ID", r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
    _p("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    _p("Slack token", r"\bxox[abposr]-[A-Za-z0-9\-]{10,}\b"),
    _p("Slack webhook URL", r"https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]{20,}"),
    _p("Stripe secret key", r"\b[rs]k_live_[A-Za-z0-9]{16,}\b"),
    _p("Stripe test key", r"\b[rs]k_test_[A-Za-z0-9]{16,}\b", Severity.HIGH),
    _p("Hugging Face token", r"\bhf_[A-Za-z0-9]{30,}\b"),
    _p("npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    _p("PyPI token", r"\bpypi-[A-Za-z0-9_\-]{50,}"),
    _p("SendGrid API key", r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"),
    _p("Telegram bot token", r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b"),
    _p("Notion token", r"\b(?:secret_|ntn_)[A-Za-z0-9]{40,}\b"),
    _p("Linear API key", r"\blin_api_[A-Za-z0-9]{40}\b"),
    _p("Azure storage key", r"AccountKey=[A-Za-z0-9+/=]{40,}"),
    _p("Private key", r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
    _p(
        "JSON Web Token",
        r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
        Severity.HIGH,
    ),
)

_REFERENCE = re.compile(
    r"\$\{[^}]+\}|^\$[A-Za-z_][A-Za-z0-9_]*$|^%[A-Za-z_][A-Za-z0-9_]*%$|^\{\{.*\}\}$|^<[^>]*>$"
)
_PLACEHOLDER = re.compile(
    r"(?i)^(?:x+|\*+|\.+|-+|changeme|change[-_ ]?me|placeholder|example|sample|dummy|test|"
    r"redacted|none|null|undefined|todo|fixme|secret|password|token|api[-_ ]?key|"
    r"(?:your|insert[_\-\s]|enter[_\-\s]|replace[_\-\s]?me|replace[_\-\s])[\w\s.\-]*)$"
)
_PLACEHOLDER_PART = re.compile(
    r"(?i)x{6,}|your[_\-\s]|[_\-]here\b|example|placeholder|dummy|0{8,}|1234567"
)
_SENSITIVE_KEY = re.compile(
    r"(?i)(?:^|[_\-.])(?:api[_\-]?key|apikey|token|secret|password|passwd|pwd|pass|passphrase|"
    r"auth|credentials?|private[_\-]?key|access[_\-]?key|client[_\-]?secret|bearer|cookie|"
    r"session|signing[_\-]?key|encryption[_\-]?key|webhook|dsn|pat)(?:$|[_\-.])"
)
_NOT_SECRET_KEY = re.compile(
    r"(?i)(?:_|-|\.)(?:id|file|path|dir|url|uri|host|port|user|username|name|limit|ttl|expiry|"
    r"timeout|mode|type|enabled|header|length|count|max|min|size)$"
)
_SENSITIVE_HEADER = re.compile(
    r"(?i)^(?:authorization|proxy-authorization|cookie|"
    r"x-[\w-]*(?:key|token|secret|auth)[\w-]*|[\w-]*api[-_]?key)$"
)
_AUTH_SCHEME = re.compile(r"(?i)^(?:bearer|basic|token|apikey|api-key)\s+")
_CRED_FLAG = re.compile(
    r"(?i)^--?(?:[\w-]*[-_])?(?:api[-_]?key|apikey|token|access[-_]?token|auth[-_]?token|secret|"
    r"client[-_]?secret|password|passwd|pwd|pat|bearer|private[-_]?key)$"
)
_SENSITIVE_PARAM = re.compile(
    r"(?i)^(?:access_token|token|api_?key|apikey|key|secret|client_secret|password|pass|pwd|auth|"
    r"sig|signature|code|session|jwt)$"
)
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s\"'<>]+")
_ENV_ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.+)$")


def is_reference(value: str) -> bool:
    """Return whether ``value`` is a reference rather than a literal secret.

    References are ``${VAR}`` anywhere in the value, or a whole value of the form
    ``$VAR``, ``%VAR%``, ``{{x}}`` or ``<x>``.
    """
    return bool(_REFERENCE.search(value.strip()))


def is_placeholder(value: str) -> bool:
    """Return whether ``value`` is empty or an obvious placeholder (``changeme``, ``xxxx``)."""
    v = value.strip().strip("'\"")
    return not v or bool(_PLACEHOLDER.match(v)) or bool(_PLACEHOLDER_PART.search(v))


def _looks_like_path(value: str) -> bool:
    return value.startswith(("/", "./", "../", "~", "\\")) or bool(
        re.match(r"^[A-Za-z]:[\\/]", value)
    )


def looks_secret(value: str) -> bool:
    """Return whether a literal value looks like a credential (by length and entropy)."""
    v = value.strip()
    if len(v) < 8 or is_reference(v) or is_placeholder(v):
        return False
    if v.isdigit() or v.lower() in {"true", "false", "yes", "no", "on", "off"}:
        return False
    if _looks_like_path(v) or "://" in v:
        return False
    return shannon_entropy(v) >= 2.5


def find_known_secrets(text: str) -> list[tuple[SecretPattern, str]]:
    """Return non-overlapping ``(pattern, value)`` matches of provider-format secrets."""
    found: list[tuple[SecretPattern, str]] = []
    taken: list[tuple[int, int]] = []
    for pattern in KNOWN_SECRETS:
        for match in pattern.regex.finditer(text):
            span = match.span()
            if any(span[0] < end and start < span[1] for start, end in taken):
                continue
            value = match.group()
            if pattern.label != "Private key" and (
                _PLACEHOLDER_PART.search(value) or shannon_entropy(value) < 3.0
            ):
                continue
            taken.append(span)
            found.append((pattern, value))
    return found


def url_credentials(url: str) -> list[str]:
    """Return redacted descriptions of the credentials embedded in ``url``."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return []
    if not parts.scheme or not parts.netloc:
        return []
    problems: list[str] = []
    password = parts.password
    if password and not is_reference(password) and not is_placeholder(password):
        problems.append(f"password in URL userinfo ({parts.username}:****@{parts.hostname})")
    for key, value in parse_qsl(parts.query, keep_blank_values=False):
        literal = not is_reference(value) and not is_placeholder(value)
        if _SENSITIVE_PARAM.match(key) and len(value) >= 6 and literal:
            problems.append(f"query parameter '{key}={redact(value)}'")
    return problems


@dataclass(frozen=True)
class MaskedSpan:
    """A value replaced by :func:`mask_spans`: a provider token or a URL credential."""

    kind: str  # "token" (provider format) or "url" (URL password or query value).
    label: str
    value: str
    severity: Severity
    placeholder: bool = False  # An obvious placeholder ("password", "****"), not a credential.


def _mask_query(url: str, spans: list[MaskedSpan]) -> str:
    """Mask the values of sensitive query parameters, percent-encoded or not."""
    start = url.find("?")
    if start < 0:
        return url
    end = url.find("#", start)
    end = len(url) if end < 0 else end
    pairs = url[start + 1 : end].split("&")
    for index, pair in enumerate(pairs):
        key, sep, value = pair.partition("=")
        decoded = unquote_plus(value)
        if (
            not sep
            or not decoded
            or not _SENSITIVE_PARAM.match(unquote_plus(key))
            or is_reference(decoded)
            # Values that mask() already redacted as provider tokens ("ghp_****(40 chars)").
            or "****" in decoded
        ):
            continue
        pairs[index] = f"{key}=****"
        placeholder = len(decoded) < 6 or is_placeholder(decoded)
        label = f"URL query parameter {sanitize(unquote_plus(key), 40)!r}"
        spans.append(MaskedSpan("url", label, value, Severity.HIGH, placeholder))
    return url[: start + 1] + "&".join(pairs) + url[end:]


def _mask_url(url: str, spans: list[MaskedSpan], legacy: bool) -> str:
    try:
        parts = urlsplit(url)
        password = parts.password
    except ValueError:
        return url
    if password and not is_reference(password):
        masked = url.replace(f":{password}@", ":****@", 1)
        if masked != url:
            placeholder = is_placeholder(password)
            spans.append(MaskedSpan("url", "URL password", password, Severity.HIGH, placeholder))
        url = masked
    if not legacy:
        return _mask_query(url, spans)
    for key, value in parse_qsl(parts.query):
        # Skip values that mask() already redacted as provider tokens ("ghp_****(40 chars)").
        if (
            _SENSITIVE_PARAM.match(key)
            and value
            and not is_reference(value)
            and "****" not in value
        ):
            url = url.replace(f"{key}={value}", f"{key}=****", 1)
    return url


def mask_spans(text: str, *, legacy: bool = False) -> tuple[str, list[MaskedSpan]]:
    """Mask provider tokens and URL credentials; return the text and the masked values.

    Values are listed in a deterministic order: provider tokens (by pattern, then
    position), then URL credentials in order of appearance. Masking is idempotent.
    ``legacy`` reproduces the masking of format-2 pin files, which left
    percent-encoded query values in clear text; it only serves to verify those pins.
    """
    spans: list[MaskedSpan] = []
    for pattern, secret in find_known_secrets(text):
        spans.append(MaskedSpan("token", pattern.label, secret, pattern.severity))
        text = text.replace(secret, redact(secret))
    text = _URL.sub(lambda match: _mask_url(match.group(), spans, legacy), text)
    return text, spans


def mask(text: str) -> str:
    """Mask provider tokens and URL credentials inside arbitrary text."""
    return mask_spans(text)[0]


def mask_args(args: list[str]) -> list[str]:
    """Return a copy of a command line with credential values redacted for reports."""
    masked: list[str] = []
    for index, arg in enumerate(args):
        if arg.startswith("-") and "=" in arg:
            flag, _, value = arg.partition("=")
            if _CRED_FLAG.match(flag) and value and not is_reference(value):
                masked.append(f"{flag}={redact(value)}")
                continue
        elif index > 0 and _CRED_FLAG.match(args[index - 1]) and not is_reference(arg):
            masked.append(redact(arg))
            continue
        assignment = _ENV_ASSIGNMENT.match(arg)
        if assignment and _sensitive_key(assignment.group(1)) and not is_reference(arg):
            masked.append(f"{assignment.group(1)}={redact(assignment.group(2))}")
            continue
        masked.append(mask(arg))
    return masked


def _sensitive_key(key: str) -> bool:
    return bool(_SENSITIVE_KEY.search(key)) and not _NOT_SECRET_KEY.search(key)


def _value_findings(
    server: ServerConfig,
    parts: tuple[str | int, ...],
    field: str,
    key: str | None,
    value: str,
    what: str,
) -> Iterator[Finding]:
    if not value or (is_reference(value) and "://" not in value):
        return
    location = server.locate(*parts)
    known = find_known_secrets(value)
    for pattern, secret in known:
        yield Finding(
            get("MCPS301"),
            f"{pattern.label} hard-coded in {what}",
            location,
            server=server.name,
            field=field,
            evidence=redact(secret),
            severity=pattern.severity,
        )
    if known:
        return
    for url in _URL.findall(value):
        for problem in url_credentials(url):
            yield Finding(
                get("MCPS303"),
                f"Credentials embedded in URL in {what}",
                location,
                server=server.name,
                field=field,
                evidence=problem,
            )
    candidate = _AUTH_SCHEME.sub("", value.strip())
    if key is not None and "://" not in value and looks_secret(candidate):
        yield Finding(
            get("MCPS302"),
            f"Literal credential in {what}",
            location,
            server=server.name,
            field=field,
            evidence=redact(candidate),
        )


def check_server(server: ServerConfig) -> Iterator[Finding]:
    for key, value in server.env.items():
        sensitive = key if _sensitive_key(key) else None
        yield from _value_findings(
            server, ("env", key), f"env.{key}", sensitive, value, f"environment variable {key}"
        )
    for key, value in server.headers.items():
        sensitive = key if _SENSITIVE_HEADER.match(key) or _sensitive_key(key) else None
        yield from _value_findings(
            server, ("headers", key), f"headers.{key}", sensitive, value, f"HTTP header {key}"
        )
    if server.url:
        url_key = next((k for k in ("url", "serverUrl", "httpUrl") if k in server.raw), "url")
        yield from _value_findings(server, (url_key,), "url", None, server.url, "server URL")

    args = server.args
    for index, arg in enumerate(args):
        where = f"command-line argument #{index}"
        key: str | None = None
        value = arg
        if arg.startswith("-") and "=" in arg:
            flag, _, value = arg.partition("=")
            key = flag if _CRED_FLAG.match(flag) else None
        elif index > 0 and _CRED_FLAG.match(args[index - 1]):
            key = args[index - 1]
        else:
            assignment = _ENV_ASSIGNMENT.match(arg)  # KEY=value, as in docker -e TOKEN=...
            if assignment and _sensitive_key(assignment.group(1)):
                key, value = assignment.group(1), assignment.group(2)
        yield from _value_findings(server, ("args", index), f"args[{index}]", key, value, where)
