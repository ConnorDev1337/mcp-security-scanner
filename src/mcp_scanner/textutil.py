"""Text helpers: safe display, normalization for matching, entropy, redaction.

Everything the scanner prints comes from untrusted input, so evidence is
always passed through :func:`sanitize` first. That keeps invisible characters
visible (``\\u200b``) and stops ANSI escape sequences in a malicious tool
description from re-styling or hiding parts of the scanner's own report.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter

# Characters that render as nothing (or nearly nothing) but are not in the
# Unicode "format" category, so they need to be listed explicitly.
INVISIBLE_EXTRA = frozenset(
    {
        0x034F,  # COMBINING GRAPHEME JOINER
        0x115F,  # HANGUL CHOSEONG FILLER
        0x1160,  # HANGUL JUNGSEONG FILLER
        0x180E,  # MONGOLIAN VOWEL SEPARATOR
        0x2800,  # BRAILLE PATTERN BLANK
        0x3164,  # HANGUL FILLER
        0xFFA0,  # HALFWIDTH HANGUL FILLER
    }
)


def is_tag_char(cp: int) -> bool:
    return 0xE0000 <= cp <= 0xE007F


def is_variation_selector(cp: int) -> bool:
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF


def is_hidden_char(ch: str) -> bool:
    """True for characters that are invisible or control-like when rendered."""
    if ch in "\n\t\r":
        return False
    cp = ord(ch)
    if cp in INVISIBLE_EXTRA or is_tag_char(cp) or is_variation_selector(cp):
        return True
    return unicodedata.category(ch) in {"Cc", "Cf", "Co", "Cs", "Zl", "Zp"}


def sanitize(text: str, limit: int = 200) -> str:
    """Escape hidden/control characters and truncate, for safe display."""
    out: list[str] = []
    for ch in text:
        if ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif is_hidden_char(ch):
            cp = ord(ch)
            out.append(f"\\u{cp:04x}" if cp <= 0xFFFF else f"\\U{cp:08x}")
        else:
            out.append(ch)
    result = "".join(out)
    if len(result) > limit:
        result = result[: max(0, limit - 3)] + "..."
    return result


def snippet(text: str, start: int, end: int, context: int = 40, max_match: int = 120) -> str:
    """Return the match with some surrounding context, sanitized."""
    end = min(end, start + max_match)
    lo, hi = max(0, start - context), min(len(text), end + context)
    piece = text[lo:hi]
    prefix = "..." if lo > 0 else ""
    suffix = "..." if hi < len(text) else ""
    return sanitize(prefix + piece + suffix, limit=2 * context + max_match + 6)


_CONFUSABLES = str.maketrans(
    {
        # Cyrillic and Greek lookalikes commonly used to dodge keyword filters.
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "ԁ": "d",
        "һ": "h",
        "ӏ": "l",
        "ο": "o",
        "α": "a",
        "ν": "v",
        "τ": "t",
        "ι": "i",
        "κ": "k",
        "ρ": "p",
        "‘": "'",
        "’": "'",
        "“": '"',
        "”": '"',
    }
)
_WS = re.compile(r"\s+")


def strip_hidden(text: str) -> str:
    return "".join(ch for ch in text if not is_hidden_char(ch))


def normalize_for_matching(text: str) -> str:
    """Canonical form used by keyword rules.

    Removes invisible characters (so ``ig\\u200bnore`` still matches), applies
    NFKC (fullwidth letters fold to ASCII), maps common homoglyphs, lowercases
    and collapses whitespace.
    """
    text = unicodedata.normalize("NFKC", strip_hidden(text)).lower()
    return _WS.sub(" ", text.translate(_CONFUSABLES)).strip()


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum(c / total * math.log2(c / total) for c in counts.values())


def redact(value: str, keep: int = 4) -> str:
    """Mask a secret for display; never reveals more than ``keep`` characters."""
    value = value.strip()
    if len(value) <= keep * 3:
        return "****"
    return f"{value[:keep]}****({len(value)} chars)"


def word_parts(identifier: str) -> list[str]:
    """Split ``snake_case``, ``kebab-case``, dotted and ``camelCase`` names."""
    words: list[str] = []
    for chunk in re.split(r"[_\-.\s/:]+", identifier):
        words.extend(re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", chunk))
    return [w.lower() for w in words if w]
