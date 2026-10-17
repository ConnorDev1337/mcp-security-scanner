"""Tests for secret detection.

Token-shaped values are generated at runtime so the repository never contains
strings that look like real credentials.
"""

import json
import random
import string

import pytest

from mcp_scanner.engine import analyze
from mcp_scanner.models import ServerConfig, Severity
from mcp_scanner.rules.secrets import (
    find_known_secrets,
    is_placeholder,
    looks_secret,
    mask,
    mask_spans,
)

_RNG = random.Random(1337)


def _rand(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(_RNG.choice(alphabet) for _ in range(n))


TOKENS = {
    "GitHub token": "ghp_" + _rand(36),
    "GitHub fine-grained token": "github_pat_"
    + _rand(60, string.ascii_letters + string.digits + "_"),
    "AWS access key ID": "AKIA" + _rand(16, string.ascii_uppercase + string.digits),
    "Anthropic API key": "sk-ant-api03-" + _rand(40),
    "OpenAI API key": "sk-proj-" + _rand(40),
    "Slack token": "xoxb-" + _rand(12, string.digits) + "-" + _rand(24),
    "Google API key": "AIza" + _rand(35),
    "GitLab token": "glpat-" + _rand(20),
    "Stripe secret key": "sk_" + "live_" + _rand(24),
    "Hugging Face token": "hf_" + _rand(34),
}


def _server(**kwargs) -> ServerConfig:
    kwargs.setdefault("name", "srv")
    kwargs.setdefault("client", "generic")
    kwargs.setdefault("transport", "stdio")
    return ServerConfig(**kwargs)


def _by_rule(server: ServerConfig) -> dict[str, list]:
    out: dict[str, list] = {}
    for finding in analyze([server]):
        out.setdefault(finding.rule.id, []).append(finding)
    return out


@pytest.mark.parametrize(("label", "token"), TOKENS.items())
def test_known_formats_in_env(label, token):
    findings = _by_rule(_server(command="x", env={"SOME_VALUE": token}))
    (finding,) = findings["MCPS301"]
    assert label in finding.message
    assert finding.severity == Severity.CRITICAL
    assert token not in finding.evidence and token not in finding.message


def test_private_key_block():
    pem = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAA\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )
    assert [p.label for p, _ in find_known_secrets(pem)] == ["Private key"]


@pytest.mark.parametrize(
    "value",
    [
        "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "${GITHUB_TOKEN}",
        "$GITHUB_TOKEN",
        "%GITHUB_TOKEN%",
        "<your-token>",
        "your-api-key-here",
        "",
    ],
)
def test_placeholders_and_references_are_ignored(value):
    assert analyze([_server(command="x", env={"GITHUB_TOKEN": value})]) == []


def test_generic_credential_by_key_name():
    findings = _by_rule(_server(command="x", env={"SERVICE_API_KEY": "4f9c2e7b1a8d6e3f0c5b"}))
    assert findings["MCPS302"][0].evidence == "4f9c****(20 chars)"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("MAX_TOKEN_LIMIT", "4000"),
        ("TOKEN_FILE", "/run/secrets/token"),
        ("AUTH_MODE", "oauth-device-flow"),
        ("SESSION_TIMEOUT", "3600"),
        ("PASSWORD_MIN_LENGTH", "12"),
        ("LOG_LEVEL", "debug"),
    ],
)
def test_non_secret_keys(key, value):
    assert analyze([_server(command="x", env={key: value})]) == []


def test_secrets_in_arguments():
    token = TOKENS["GitHub token"]
    findings = _by_rule(
        _server(
            command="docker",
            args=[
                "run",
                "-e",
                f"GITHUB_TOKEN={token}",
                "--api-key",
                "Zq8vR2mK5tY9wB3n",
                "--token=Lp4xN7cV1bM6kJ3h",
                "img@sha256:" + "a" * 64,
            ],
        )
    )
    assert findings["MCPS301"][0].field == "args[2]"
    assert sorted(f.field for f in findings["MCPS302"]) == ["args[4]", "args[5]"]


def test_headers_and_urls():
    findings = _by_rule(
        _server(
            transport="http",
            url="https://mcp.example.com/mcp?api_key=Hk29dLq8Zr7Xv1Pm",
            headers={"Authorization": "Bearer Hk29dLq8Zr7Xv1PmQ4", "X-Trace": "abc"},
            raw={"url": "x"},
        )
    )
    assert findings["MCPS302"][0].field == "headers.Authorization"
    assert "api_key=Hk29****" in findings["MCPS303"][0].evidence
    assert "MCPS303" not in _by_rule(_server(transport="http", url="https://user@example.com/"))
    assert analyze([_server(transport="http", headers={"Authorization": "Bearer ${TOKEN}"})]) == []


def test_database_url_password():
    findings = _by_rule(_server(command="x", env={"DATABASE_URL": "mysql://root:Tr0ub4dor3@db/x"}))
    (finding,) = findings["MCPS303"]
    assert "Tr0ub4dor3" not in json.dumps([finding.message, finding.evidence])


def test_helpers():
    assert is_placeholder("changeme")
    assert is_placeholder("REPLACE_ME")
    assert not is_placeholder("mySecretPass123")
    assert looks_secret("mySecretPass123")
    assert not looks_secret("/etc/token")
    assert not looks_secret("true")


def test_mask_spans_lists_every_masked_value():
    token = TOKENS["GitHub token"]
    text = (
        f"Use {token} or https://admin:Tr0ub4dor3@db.internal/app?sslmode=require"
        "&api_key=k3y-v4lue-9&code=12 and https://u:password@example.com/"
    )
    masked, spans = mask_spans(text)
    assert masked == mask(text)
    assert masked == (
        "Use ghp_****(40 chars) or https://admin:****@db.internal/app?sslmode=require"
        "&api_key=****&code=**** and https://u:****@example.com/"
    )
    found = [(s.kind, s.label, s.value, s.placeholder) for s in spans]
    assert found == [
        ("token", "GitHub token", token, False),
        ("url", "URL password", "Tr0ub4dor3", False),
        ("url", "URL query parameter 'api_key'", "k3y-v4lue-9", False),
        ("url", "URL query parameter 'code'", "12", True),
        ("url", "URL password", "password", True),
    ]
    assert mask_spans("Adds two numbers.") == ("Adds two numbers.", [])


def test_mask_covers_percent_encoded_query_values():
    signed = "https://acct.blob.core.windows.net/c/f?sv=2024-01-01&sig=Ab%2Bc9%2Fd3%3D&x=1"
    assert mask(signed) == "https://acct.blob.core.windows.net/c/f?sv=2024-01-01&sig=****&x=1"
    plus = "https://api.example.com/?token=Ab+cd+ef+12"
    assert mask(plus) == "https://api.example.com/?token=****"
    # A sensitive name that is a suffix of another parameter is not confused with it.
    shadow = "https://api.example.com/?mytoken=abcdef123&token=abcdef123"
    assert mask(shadow) == "https://api.example.com/?mytoken=abcdef123&token=****"
    # The legacy mode reproduces the masking of format-2 pin files, bugs included.
    assert mask_spans(signed, legacy=True)[0] == signed
    assert mask_spans(shadow, legacy=True)[0] == (
        "https://api.example.com/?mytoken=****&token=abcdef123"
    )


@pytest.mark.parametrize(
    "text",
    [
        f"key {TOKENS['OpenAI API key']} and {TOKENS['Slack token']}",
        f"https://x-access-token:{TOKENS['GitHub token']}@github.com/o/r.git",
        f"https://api.example.com/v1?token={TOKENS['GitLab token']}&page=2",
        "https://u:p%40ss-w0rd@h/?secret=a%26b%3Dc&password=hunter22#frag",
        "postgres://admin:****@db/app?token=****",
    ],
)
def test_masking_is_idempotent(text):
    once = mask(text)
    assert mask(once) == once
    assert mask_spans(once)[1] == []
    for value in TOKENS.values():
        assert value not in once


def test_mask_hides_the_whole_private_key():
    body = "\n".join(_rand(64, string.ascii_letters + string.digits + "+/") for _ in range(3))
    pem = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"
    masked, spans = mask_spans(f"Signs with:\n{pem}\nThen uploads.")
    assert masked == f"Signs with:\n----****({len(pem)} chars)\nThen uploads."
    assert [(s.label, s.value) for s in spans] == [("Private key", pem)]
    # Without a footer, the base64 that follows the header is masked.
    masked = mask(f"-----BEGIN PRIVATE KEY-----\n{body}")
    assert body.splitlines()[0] not in masked
    assert mask(masked) == masked
