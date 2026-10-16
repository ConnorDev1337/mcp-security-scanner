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
from mcp_scanner.rules.secrets import find_known_secrets, is_placeholder, looks_secret

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
