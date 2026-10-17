"""Shared Hypothesis strategies and helpers for the property-based tests.

Provider-shaped tokens are generated at run time from the formats the scanner
detects, so the repository holds no credential-shaped literal.
"""

from __future__ import annotations

import faulthandler
import string
import time
from collections.abc import Callable
from typing import Any

from hypothesis import settings
from hypothesis import strategies as st

ALNUM = string.ascii_letters + string.digits
UPPER_ALNUM = string.ascii_uppercase + string.digits
TOKEN_CHARS = ALNUM + "_-"

# A call on adversarial input fails the test when it takes longer than SOFT_LIMIT
# seconds. HARD_LIMIT guards against catastrophic backtracking, which never returns:
# faulthandler dumps every thread's traceback and ends the test process.
SOFT_LIMIT = 2.0
HARD_LIMIT = 120.0


def scaled(fraction: float, minimum: int = 5) -> settings:
    """Return settings running ``fraction`` of the active profile's examples."""
    return settings(max_examples=max(minimum, int(settings.default.max_examples * fraction)))


def timed(
    function: Callable[..., Any], *args: Any, limit: float = SOFT_LIMIT, name: str = ""
) -> Any:
    """Call ``function(*args)``; fail if it is slower than ``limit`` seconds."""
    faulthandler.dump_traceback_later(HARD_LIMIT, exit=True)
    try:
        start = time.perf_counter()
        result = function(*args)
        elapsed = time.perf_counter() - start
    finally:
        faulthandler.cancel_dump_traceback_later()
    size = sum(len(a) for a in args if isinstance(a, str))
    name = name or getattr(function, "__qualname__", repr(function))
    assert elapsed < limit, f"{name} took {elapsed:.2f}s on {size} characters"
    return result


def _chars(alphabet: str, low: int, high: int) -> st.SearchStrategy[str]:
    """Return random strings: real tokens are high-entropy, unlike shrunk text."""
    return st.tuples(st.integers(low, high), st.randoms(use_true_random=False)).map(
        lambda args: "".join(args[1].choice(alphabet) for _ in range(args[0]))
    )


def _joined(*parts: st.SearchStrategy[str] | str) -> st.SearchStrategy[str]:
    return st.tuples(*(st.just(p) if isinstance(p, str) else p for p in parts)).map("".join)


# One strategy per provider format of rules.secrets.KNOWN_SECRETS.
PROVIDER_TOKENS: dict[str, st.SearchStrategy[str]] = {
    "Anthropic API key": _joined("sk-ant-", _chars(TOKEN_CHARS, 20, 60)),
    "OpenAI API key": _joined(
        "sk-", st.sampled_from(["", "proj-", "svcacct-", "admin-"]), _chars(TOKEN_CHARS, 20, 60)
    ),
    "GitHub token": _joined("gh", st.sampled_from("pousr"), "_", _chars(ALNUM, 36, 60)),
    "GitHub fine-grained token": _joined("github_pat_", _chars(ALNUM + "_", 22, 80)),
    "GitLab token": _joined("glpat-", _chars(TOKEN_CHARS, 20, 40)),
    "AWS access key ID": _joined(
        st.sampled_from(["AKIA", "ASIA", "ABIA", "ACCA"]), _chars(UPPER_ALNUM, 16, 16)
    ),
    "Google API key": _joined("AIza", _chars(TOKEN_CHARS, 35, 35)),
    "Slack token": _joined("xox", st.sampled_from("abposr"), "-", _chars(ALNUM + "-", 10, 40)),
    "Slack webhook URL": _joined(
        "https://hooks.slack.com/services/", _chars(ALNUM + "/_-", 20, 40)
    ),
    "Stripe secret key": _joined(st.sampled_from("rs"), "k_live_", _chars(ALNUM, 16, 40)),
    "Stripe test key": _joined(st.sampled_from("rs"), "k_test_", _chars(ALNUM, 16, 40)),
    "Hugging Face token": _joined("hf_", _chars(ALNUM, 30, 40)),
    "npm token": _joined("npm_", _chars(ALNUM, 36, 36)),
    "PyPI token": _joined("pypi-", _chars(TOKEN_CHARS, 50, 70)),
    "SendGrid API key": _joined(
        "SG.", _chars(TOKEN_CHARS, 16, 30), ".", _chars(TOKEN_CHARS, 16, 30)
    ),
    "Telegram bot token": _joined(
        _chars(string.digits, 8, 10), ":AA", _chars(TOKEN_CHARS, 33, 33)
    ),
    "Notion token": _joined(st.sampled_from(["secret_", "ntn_"]), _chars(ALNUM, 40, 50)),
    "Linear API key": _joined("lin_api_", _chars(ALNUM, 40, 40)),
    "Azure storage key": _joined("AccountKey=", _chars(ALNUM + "+/=", 40, 60)),
    "JSON Web Token": _joined(
        "eyJ",
        _chars(TOKEN_CHARS, 10, 30),
        ".eyJ",
        _chars(TOKEN_CHARS, 10, 30),
        ".",
        _chars(TOKEN_CHARS, 10, 30),
    ),
    "Private key": _joined(
        "-----BEGIN ",
        st.sampled_from(["", "RSA ", "EC ", "OPENSSH ", "ENCRYPTED "]),
        "PRIVATE" + " KEY-----",
        st.sampled_from(["\n", "\\n"]),
        _chars(ALNUM + "+/", 40, 120),
        st.sampled_from(["\n", "\\n"]),
        "-----END PRIVATE" + " KEY-----",
    ),
}

provider_tokens = st.sampled_from(sorted(PROVIDER_TOKENS)).flatmap(
    lambda label: st.tuples(st.just(label), PROVIDER_TOKENS[label])
)

# Text that cannot extend a token it surrounds.
SEPARATORS = st.sampled_from([" ", "\n", "\t", ", ", "; ", " (", ") ", '"', "'", " <", "> "])

# Unicode with the troublemakers over-represented: lone surrogates, combining marks,
# invisible and bidi characters, tag characters, variation selectors and controls.
SPECIAL_CHARS = st.sampled_from(
    [
        chr(cp)
        for cp in (
            0x0, 0x7, 0x1B, 0x7F, 0x85, 0xA0, 0xAD, 0x300, 0x301, 0x34F, 0x61C, 0x115F,
            0x180E, 0x200B, 0x200D, 0x200E, 0x2028, 0x202E, 0x2066, 0x2800, 0x3164,
            0xD800, 0xDBFF, 0xDC00, 0xDFFF, 0xE000, 0xFE0F, 0xFEFF, 0xFFFD, 0xFFFF,
            0x1F600, 0xE0041, 0xE007F, 0xE0100, 0x10FFFF,
        )
    ]
)  # fmt: skip
# exclude_categories=() keeps the surrogates that Hypothesis leaves out by default.
UNICODE_TEXT = st.text(alphabet=st.characters(exclude_categories=()) | SPECIAL_CHARS, max_size=200)

# Fragments that steer the rules' regular expressions; pumping them exposes
# super-linear backtracking.
REGEX_FRAGMENTS = st.sampled_from(
    [
        "a", "A", "1", "_", "-", ".", "/", ":", "=", "+", "%", "&", "?", "#", "@", "~",
        " ", "\n", "\t", " ", "\\", '"', "'", "<", ">", "{", "}", "(", ")", "|", "*",
        "${", "$", "%A%", "{{", "}}", "<!--", "-->", "-----BEGIN PRIVATE" + " KEY-----",
        "-----END ", "://", "https://", "http://a:b@", "?token=", "&key=", "=****",
        "x-", "key", "token", "api", "apikey", "private", ".pem", "ghp_", "sk-", "sk-ant-",
        "xoxb-", "eyJ", "AKIA", "AccountKey=", "SG.", "glpat-", "hf_", "AA", ":AA",
        "ignore ", "previous ", "instructions", "the ", "tool ", "tools ", "read ",
        "secrets ", "send ", "curl ", "| sh", "whether ", "you ", "user ", "do not ",
        "tell ", "<important>", "display:none", "display", "font-size", "​",
        "\U000e0041", "️", "︁", "base64", "QUFB", "id_rsa", "/.ssh/", "%2F",
        "${input:", "${env:", "--token", "TOKEN=", "-r ", "iex ", "python -c",
    ]
)  # fmt: skip


@st.composite
def pumped_text(draw: st.DrawFn, size: int = 40_000) -> str:
    """Return ``prefix + pump * n + suffix`` of about ``size`` characters."""
    fragment_lists = st.lists(REGEX_FRAGMENTS, max_size=3).map("".join)
    prefix, suffix = draw(fragment_lists), draw(fragment_lists)
    pump = "".join(draw(st.lists(REGEX_FRAGMENTS, min_size=1, max_size=4)))
    return prefix + pump * max(1, size // len(pump)) + suffix
