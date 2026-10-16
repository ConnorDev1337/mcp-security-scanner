"""MCPS214 and MCPS206 for resource URIs, plus hidden-character and secret checks on them.

URIs are identifiers rather than prose, so the keyword rules of
:mod:`.poisoning` do not run on them. Each resource URI and resource template is
checked for invisible or control characters (MCPS120-MCPS121), embedded
credentials (MCPS301, MCPS303), sensitive local files such as SSH keys or cloud
credentials (MCPS214) and ``file:`` URIs that expose the filesystem root or a
home directory (MCPS206). Hosts may attach resources to the model context, so a
server that lists ``~/.ssh/id_rsa`` as a resource can leak it without any tool
call.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from urllib.parse import unquote, urlsplit

from ..models import Finding, ResourceDefinition, ServerInventory, Severity
from ..textutil import redact, sanitize
from . import unicode as unicode_rules
from .catalog import get
from .config import path_breadth
from .secrets import find_known_secrets, mask, url_credentials

# Schemes the client fetches from the network itself; their paths are not local files.
WEB_SCHEMES = frozenset({"http", "https", "ws", "wss"})
_EXPRESSION = re.compile(r"\{[^{}]*\}")  # RFC 6570 template expression.
_DRIVE = re.compile(r"^/[A-Za-z]:")
# Matched against the lowercase, percent-decoded path with forward slashes.
_SENSITIVE_PATH = re.compile(
    r"(?:^|/)(?:"
    r"\.ssh(?:/|$)|id_(?:rsa|dsa|ecdsa|ed25519)$|\.gnupg(?:/|$)|"
    r"\.aws/(?:credentials|config)$|\.azure(?:/|$)|\.config/gcloud(?:/|$)|"
    r"application_default_credentials\.json$|\.kube/config$|\.docker/config\.json$|"
    r"\.config/gh/hosts\.yml$|credentials\.tfrc\.json$|\.vault-token$|\.s3cfg$|\.boto$|"
    r"\.(?:npmrc|pypirc|netrc|pgpass|git-credentials)$|_netrc$|"
    r"\.env(?:\.(?!(?:example|sample|template|dist)$)[\w.-]+)?$|"
    r"etc/(?:shadow|gshadow|sudoers|master\.passwd)$|etc/ssl/private(?:/|$)|"
    r"proc/[^/]+/environ$|"
    r"claude_desktop_config\.json$|\.claude\.json$|\.cursor/mcp\.json$|"
    r"cline_mcp_settings\.json$|mcp_config\.json$|\.codex/config\.toml$|"
    r"\.gemini/settings\.json$|"
    r"\.(?:bash|zsh|sh|fish|python|psql|mysql|node_repl)_history$|consolehost_history\.txt$|"
    r"login data$|web data$|logins\.json$|key[34]\.db$|cookies\.sqlite$|"
    r"library/keychains(?:/|$)|[^/]*\.keychain(?:-db)?$|wallet\.dat$|"
    r"microsoft/(?:credentials|protect)(?:/|$)|windows/system32/config/(?:sam|security|system)$|"
    r"[^/]*\.(?:ppk|p12|pfx|jks|keystore)$|[^/]*private[^/]*\.(?:pem|key)$"
    r")"
)


def resource_key(resource: ResourceDefinition) -> str:
    """Return the identifier of a resource used in findings and pins: its masked URI.

    Credentials embedded in the URI (passwords, token query parameters, provider
    tokens) are masked so they never reach reports or the pin file.
    """
    return mask(resource.uri)


def local_path(uri: str) -> str | None:
    """Return the percent-decoded path of a non-web URI with forward slashes, or None."""
    try:
        parts = urlsplit(uri)
    except ValueError:
        return None
    if parts.scheme.lower() in WEB_SCHEMES:
        return None
    return unquote(parts.path).replace("\\", "/")


def sensitive_reference(uri: str) -> str | None:
    """Return the sensitive part of the path of ``uri`` (e.g. ``.ssh/``), or None."""
    path = local_path(uri)
    if not path:
        return None
    match = _SENSITIVE_PATH.search(path.lower())
    return match.group().lstrip("/") if match else None


def file_breadth(uri: str, template: bool) -> str | None:
    """Classify a ``file:`` URI as exposing the filesystem ``root``, a ``home`` dir, or None.

    For a template only the literal prefix before the first expression is fixed,
    so ``file:///{path}`` exposes the root and ``file:///home/alice/{path}`` a
    home directory. A template that ends in a fixed file name, such as
    ``file:///home/{user}/notes.txt``, only reaches that file in each directory.
    """
    prefix = uri
    if template:
        first = _EXPRESSION.search(uri)
        if first is None:
            return file_breadth(uri, template=False)
        rest = _EXPRESSION.sub("", uri[first.end() :]).split("?", 1)[0].split("#", 1)[0]
        if rest.strip("/"):
            return None
        prefix = uri[: first.start()]
    try:
        parts = urlsplit(prefix)
    except ValueError:
        return None
    if parts.scheme.lower() != "file" or parts.netloc.lower() not in {"", "localhost"}:
        return None  # Not a file URI, or a remote share.
    path = unquote(parts.path).replace("\\", "/")
    if _DRIVE.match(path):
        path = path[1:]  # file:///C:/Users -> C:/Users
    return path_breadth(path or "/")


def check_resource(inv: ServerInventory, resource: ResourceDefinition) -> Iterator[Finding]:
    """Check the URI or URI template of a resource definition."""
    uri, template, kind = resource.uri, resource.template, resource.kind
    if not uri:
        return
    key = resource_key(resource)
    location = resource.locate(resource.uri_key)

    def make(
        rule_id: str, message: str, evidence: str | None, severity: Severity | None = None
    ) -> Finding:
        return Finding(
            get(rule_id),
            message,
            location,
            server=inv.server,
            field=resource.uri_key,
            evidence=evidence,
            severity=severity,
            resource=key,
        )

    for issue in unicode_rules.analyze_text(uri):
        yield make(issue.rule_id, f"{issue.kind} in {kind} URI", issue.evidence, issue.severity)

    # Template expressions are placeholders, not values: '?token={token}' is not a credential.
    literal = _EXPRESSION.sub("", uri) if template else uri
    known = find_known_secrets(literal)
    for pattern, secret in known:
        yield make(
            "MCPS301", f"{pattern.label} embedded in {kind} URI", redact(secret), pattern.severity
        )
    if not known:
        for problem in url_credentials(literal):
            yield make("MCPS303", f"Credentials embedded in {kind} URI", problem)

    sensitive = sensitive_reference(uri)
    if sensitive:
        yield make(
            "MCPS214",
            f"{kind.capitalize()} URI points at sensitive local data ({sanitize(sensitive, 80)})",
            sanitize(key, 200),
        )

    breadth = file_breadth(uri, template)
    if breadth:
        what = "the filesystem root" if breadth == "root" else "a home directory"
        verb = "exposes every file under" if template else "exposes"
        yield make(
            "MCPS206",
            f"{kind.capitalize()} {verb} {what}",
            sanitize(key, 200),
            Severity.HIGH if breadth == "root" else Severity.MEDIUM,
        )
