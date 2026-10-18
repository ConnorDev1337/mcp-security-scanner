"""Property-based tests of the text rules: poisoning, hidden Unicode and secrets.

The rules read untrusted text of any size, so they must never crash (lone
surrogates, combining marks, controls), must stay fast on adversarial input
(every call is time-boxed), and masking must be idempotent and never let a
detected secret through.
"""

import random
import string
from urllib.parse import quote, unquote_plus, urlsplit

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from fuzzing import (
    PROVIDER_TOKENS,
    REGEX_FRAGMENTS,
    SEPARATORS,
    SOFT_LIMIT,
    UNICODE_TEXT,
    assert_linear,
    provider_tokens,
    pumped_text,
    scaled,
    timed,
)
from mcp_scanner.engine import analyze
from mcp_scanner.models import (
    PromptDefinition,
    ResourceDefinition,
    ServerConfig,
    ServerInventory,
    ToolDefinition,
)
from mcp_scanner.rules import capabilities, config, poisoning, resources, secrets, unicode
from mcp_scanner.textutil import (
    is_hidden_char,
    normalize_for_matching,
    sanitize,
    snippet,
    strip_hidden,
)

KINDS = ["description", "parameter", "value", "name", "instructions"]


def _tool(text: str) -> ToolDefinition:
    raw = {
        "name": text[:64] or "t",
        "title": text,
        "description": text,
        "inputSchema": {
            "type": "object",
            "properties": {text[:32]: {"type": "string", "description": text, "default": text}},
            "required": [text[:32]],
        },
    }
    return ToolDefinition(raw["name"], raw)


def _inventory(text: str) -> ServerInventory:
    return ServerInventory(
        server=text[:40] or "s",
        tools=[_tool(text)],
        instructions=text,
        prompts=[
            PromptDefinition(
                text or "p",
                {"name": text or "p", "description": text, "arguments": [{"name": text}]},
            )
        ],
        resources=[ResourceDefinition(text, {"uri": text, "name": text, "description": text})],
        resource_templates=[
            ResourceDefinition("", {"uriTemplate": text + "/{x}", "name": text}, template=True)
        ],
    )


def _server(text: str) -> ServerConfig:
    return ServerConfig(
        name=text[:40] or "s",
        client="generic",
        transport="stdio",
        command=text,
        args=[text, "--token", text, f"--api-key={text}", f"TOKEN={text}", "-c", text],
        env={"API_TOKEN": text, text[:20] or "K": text, "NODE_OPTIONS": text},
        url=f"https://host/{text}?token={text}",
        headers={"Authorization": f"Bearer {text}", text[:20] or "H": text},
        cwd=text,
    )


TEXT_FUNCTIONS = [
    *(lambda text, kind=kind: poisoning.scan_text(text, kind) for kind in KINDS),
    unicode.analyze_text,
    unicode.identifier_issue,
    secrets.mask_spans,
    secrets.find_known_secrets,
    secrets.looks_secret,
    secrets.is_reference,
    secrets.is_placeholder,
    secrets.url_credentials,
    lambda text: secrets.mask_args([text, "--token", text, f"KEY={text}"]),
    normalize_for_matching,
    sanitize,
]


def _text_functions(text: str) -> None:
    for function in TEXT_FUNCTIONS:
        timed(function, text)


def _rules(text: str, *, full: bool = False) -> None:
    """Run every rule on metadata made of ``text``; ``full`` adds a whole analysis."""
    inventory = _inventory(text)
    server = _server(text)
    checks = {
        "check_tool": lambda: list(poisoning.check_tool(inventory, inventory.tools[0])),
        "check_prompt": lambda: list(poisoning.check_prompt(inventory, inventory.prompts[0])),
        "check_instructions": lambda: list(poisoning.check_instructions(inventory)),
        "check_resource": lambda: [
            finding
            for resource in inventory.all_resources()
            for finding in (
                *poisoning.check_resource(inventory, resource),
                *resources.check_resource(inventory, resource),
            )
        ],
        "capabilities": lambda: list(capabilities.check_tool(inventory, inventory.tools[0])),
        "config": lambda: list(config.check_server(server)),
        "secrets": lambda: list(secrets.check_server(server)),
        "server_name": lambda: list(unicode.check_server_name(server)),
    }
    if full:
        checks["analyze"] = lambda: [f.fingerprint() for f in analyze([server], [inventory])]
    for name, function in checks.items():
        # A rule reads the text in several fields, so it gets a multiple of the limit.
        timed(function, name=f"{name} ({len(text)} characters)", limit=4 * SOFT_LIMIT)


@given(UNICODE_TEXT)
def test_rules_never_crash_on_arbitrary_unicode(text):
    _text_functions(text)
    _rules(text, full=True)


@scaled(0.25)
@given(UNICODE_TEXT.filter(bool), st.integers(1_000, 10_000))
def test_rules_never_crash_on_huge_strings(text, size):
    text = (text * (size // len(text) + 1))[:size]
    _text_functions(text)
    _rules(text, full=True)


@scaled(0.25)
@given(pumped_text(size=20_000))
def test_rules_run_in_bounded_time_on_adversarial_input(text):
    _text_functions(text)
    _rules(text)


@given(UNICODE_TEXT)
def test_sanitized_text_is_visible_and_bounded(text):
    shown = sanitize(text, 60)
    assert len(shown) <= 60
    assert not any(is_hidden_char(ch) for ch in shown)
    assert not any(is_hidden_char(ch) for ch in snippet(text, 0, len(text)))


# --------------------------------------------------------------------------- masking


@given(st.lists(REGEX_FRAGMENTS | UNICODE_TEXT, max_size=8).map("".join))
def test_masking_is_idempotent(text):
    once = secrets.mask(text)
    assert secrets.mask(once) == once
    assert secrets.mask_spans(once)[1] == [] or all(
        "****" in span.value or span.placeholder for span in secrets.mask_spans(once)[1]
    )


@given(st.lists(REGEX_FRAGMENTS | UNICODE_TEXT, max_size=8).map("".join))
def test_masked_tokens_never_survive(text):
    masked, spans = secrets.mask_spans(text)
    for span in spans:
        if span.kind == "token":
            assert span.value not in masked


@given(provider_tokens, UNICODE_TEXT, SEPARATORS, SEPARATORS, UNICODE_TEXT)
def test_provider_tokens_in_random_text_are_masked(labelled, before, left, right, after):
    _, token = labelled
    assume(any(value == token for _, value in secrets.find_known_secrets(token)))
    text = before + left + token + right + after
    masked = secrets.mask(text)
    assert token not in masked
    assert secrets.mask(masked) == masked


def test_every_provider_format_has_a_strategy():
    assert sorted(PROVIDER_TOKENS) == sorted(p.label for p in secrets.KNOWN_SECRETS)


SENSITIVE_KEYS = st.sampled_from(
    ["token", "access_token", "api_key", "apikey", "key", "secret", "password", "sig", "code"]
)
PLAIN_KEYS = st.sampled_from(["page", "q", "lang", "format", "id", "redirect"])


@st.composite
def query_values(draw):
    kind = draw(st.sampled_from(["text", "token", "reference", "percent"]))
    if kind == "token":  # Tokens that fit in a URL (no PEM block, no nested URL).
        return draw(provider_tokens.map(lambda labelled: labelled[1]).filter(_url_safe))
    if kind == "reference":
        return "${" + draw(st.sampled_from(["TOKEN", "env:KEY"])) + "}"
    value = draw(UNICODE_TEXT.filter(lambda v: v.strip()))
    return quote(value.encode("utf-8", "surrogatepass"), safe="")


def _url_safe(token: str) -> bool:
    return not any(ch in token for ch in " \n\\\"'<>&#?/:")


def _encode_key(key: str, draw) -> str:
    if draw(st.booleans()):
        index = draw(st.integers(0, len(key) - 1))
        return key[:index] + f"%{ord(key[index]):02X}" + key[index + 1 :]
    return key


@st.composite
def credential_urls(draw):
    params = []
    for _ in range(draw(st.integers(1, 5))):
        sensitive = draw(st.booleans())
        key = draw(SENSITIVE_KEYS if sensitive else PLAIN_KEYS)
        params.append((sensitive, _encode_key(key, draw), draw(query_values())))
    password = draw(st.none() | query_values())
    userinfo = f"user:{password}@" if password else ""
    host = draw(st.sampled_from(["example.com", "10.0.0.1:8080", "[::1]", "h"]))
    url = f"https://{userinfo}{host}/p?" + "&".join(f"{k}={v}" for _, k, v in params)
    if draw(st.booleans()):
        url += "#frag"
    return url, password, params


def _masked_or_reference(value: str) -> bool:
    decoded = unquote_plus(value)
    return "****" in decoded or secrets.is_reference(decoded)


@given(credential_urls(), SEPARATORS, SEPARATORS)
def test_url_credentials_are_masked(case, left, right):
    url, password, params = case
    masked = secrets.mask(left + url + right)
    assert secrets.mask(masked) == masked
    masked_url = masked[len(left) : len(masked) - len(right)]
    parts = urlsplit(masked_url)
    if password and not secrets.is_reference(password):
        assert parts.password is not None and _masked_or_reference(parts.password)
    pairs = parts.query.split("&")
    assert len(pairs) == len(params)
    for (sensitive, _, value), pair in zip(params, pairs, strict=True):
        masked_value = pair.partition("=")[2]
        if sensitive:
            assert _masked_or_reference(masked_value), (value, masked_value)
        else:
            assert masked_value == value or "****" in unquote_plus(masked_value)


# --------------------------------------------------------------------------- regressions


_RNG = random.Random(4242)


def _fake(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(_RNG.choice(alphabet) for _ in range(n))


# Inputs on which one regular expression took quadratic time, found by pumping
# fragments: (function, input of size n, n). At 4 * n each took 10 to 25 seconds.
ADVERSARIAL = {
    # "<!--.*?-->" (MCPS107) scanned to the end of the text from every "<!--".
    "html-comment": (lambda text: poisoning.scan_text(text, "description"), "<!--".__mul__, 5_000),
    # The private key body could cross every later header.
    "pem-header": (secrets.mask_spans, ("-----BEGIN PRIVATE" + " KEY-----").__mul__, 2_000),
    # Each letter of a long word was tried as the start of a URL scheme.
    "url-scheme": (secrets.mask_spans, "a".__mul__, 25_000),
    # "${[^}]+}" scanned to the end from every "${".
    "reference": (secrets.is_reference, "${".__mul__, 25_000),
    # The sentence of every MCPS104 match was searched from scratch.
    "sentence": (
        lambda text: poisoning.scan_text(text, "value"),
        lambda n: ("read secrets " + "~" * 60 + " ") * n,
        4_000,
    ),
    # "curl[^|]*|" scanned to the pipe from every "curl" (MCPS202).
    "curl": (config._DOWNLOAD_EXEC.search, lambda n: "curl " * n + "| x", 12_500),
    # "x-[\w-]*key[\w-]*$" re-scanned the name after every "key".
    "header": (secrets._SENSITIVE_HEADER.match, lambda n: "x-" + "key" * n + "!", 7_500),
    # Every provider token was compared with every token found before it.
    "tokens": (
        secrets.find_known_secrets,
        lambda n: " ".join("ghp_" + _fake(36) for _ in range(n)),
        2_000,
    ),
}


@pytest.mark.parametrize(
    ("function", "make", "size"), ADVERSARIAL.values(), ids=ADVERSARIAL.keys()
)
def test_adversarial_inputs_regressions(function, make, size):
    assert_linear(function, make, size)


def test_query_credentials_after_a_masked_token_are_masked():
    # Found by fuzzing: the redacted token "AKIA****(20 chars)" holds a space, which ended
    # the URL, so the credential after it stayed in clear text.
    value = _fake(16)
    key_id = "AKIA" + _fake(16, string.ascii_uppercase + string.digits)
    masked = secrets.mask(f"https://example.com/p?page={key_id}&token={value}")
    assert value not in masked
    assert masked.endswith("&token=****")


def test_password_redacted_as_a_token_is_kept():
    token = "ghp_" + _fake(36)
    masked, spans = secrets.mask_spans(f"https://user:{token}@github.com/org/repo")
    assert masked == "https://user:ghp_****(40 chars)@github.com/org/repo"
    assert [span.kind for span in spans] == ["token"]


@given(st.text(alphabet=st.characters(max_codepoint=0x7F)) | UNICODE_TEXT)
def test_strip_hidden_fast_path_matches_the_definition(text):
    expected = "".join(ch for ch in text if not is_hidden_char(ch))
    assert strip_hidden(text) == expected
