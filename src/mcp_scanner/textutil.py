r"""Text helpers: safe display, normalization for matching, entropy and redaction.

All displayed evidence comes from untrusted input and goes through
:func:`sanitize`, which makes invisible characters visible (``\u200b``) and
neutralizes ANSI escape sequences that could restyle or hide parts of the report.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter

# Blank-rendering characters outside the Unicode format (Cf) category.
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
    """Return whether ``ch`` renders invisibly or acts as a control character.

    Newline, tab and carriage return are not considered hidden.
    """
    if ch in "\n\t\r":
        return False
    cp = ord(ch)
    if cp in INVISIBLE_EXTRA or is_tag_char(cp) or is_variation_selector(cp):
        return True
    return unicodedata.category(ch) in {"Cc", "Cf", "Co", "Cs", "Zl", "Zp"}


def sanitize(text: str, limit: int = 200) -> str:
    """Escape hidden and control characters and truncate to ``limit`` for display."""
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
    """Return ``text[start:end]`` with surrounding context, truncated and sanitized."""
    end = min(end, start + max_match)
    lo, hi = max(0, start - context), min(len(text), end + context)
    piece = text[lo:hi]
    prefix = "..." if lo > 0 else ""
    suffix = "..." if hi < len(text) else ""
    return sanitize(prefix + piece + suffix, limit=2 * context + max_match + 6)


_CONFUSABLES = str.maketrans(
    {
        # Cyrillic/Greek homoglyphs and typographic quotes used to dodge keyword filters.
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


# The hidden characters of ASCII text: the controls other than tab, newline and return.
_ASCII_HIDDEN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def strip_hidden(text: str) -> str:
    if text.isascii():  # Fast path: one regular expression instead of a call per character.
        return _ASCII_HIDDEN.sub("", text)
    return "".join(ch for ch in text if not is_hidden_char(ch))


def normalize_for_matching(text: str) -> str:
    r"""Return the canonical form of ``text`` matched by keyword rules.

    Removes hidden characters (so ``ig\u200bnore`` still matches), applies NFKC
    (fullwidth letters fold to ASCII), maps common homoglyphs, lowercases and
    collapses whitespace.
    """
    text = unicodedata.normalize("NFKC", strip_hidden(text)).lower()
    return _WS.sub(" ", text.translate(_CONFUSABLES)).strip()


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy of ``value`` in bits per character."""
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
    """Split a ``snake_case``, ``kebab-case``, dotted or ``camelCase`` name into words.

    Words are returned in lowercase.
    """
    words: list[str] = []
    for chunk in re.split(r"[_\-.\s/:]+", identifier):
        words.extend(re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", chunk))
    return [w.lower() for w in words if w]
