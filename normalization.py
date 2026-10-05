"""Deterministic normalization with a narrow glossary of spelling variants."""
import re
import unicodedata

_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff\u00ad]")
_SPACE = re.compile(r"[^\S\n]+")
_ALIASES = (
    (re.compile(r"(?<![a-z0-9])o[ ._-]*t[ ._-]*p(?![a-z0-9])"), "otp"),
    (re.compile(r"\b0tp\b"), "otp"),
    (re.compile(r"\bp[@a]ssw[0o]rd\b"), "password"),
    (re.compile(r"\bverificati0n\b"), "verification"),
    (re.compile(r"ร[ ._-]*ห[ ._-]*ั[ ._-]*ส[ ._-]*ผ[ ._-]*่[ ._-]*า[ ._-]*น"), "รหัสผ่าน"),
)

def normalize(content: str) -> tuple[str, list[str]]:
    changes = []
    text = unicodedata.normalize("NFKC", content).casefold()
    # NFKC decomposes Thai SARA AM; restore it so literal Thai rules still match.
    text = text.replace("\u0e4d\u0e32", "\u0e33")
    if text != content:
        changes.append("unicode_and_case")
    cleaned = _INVISIBLE.sub("", text)
    if cleaned != text:
        changes.append("invisible_characters")
    text = _SPACE.sub(" ", cleaned).strip()
    for pattern, replacement in _ALIASES:
        expanded = pattern.sub(replacement, text)
        if expanded != text and "known_spelling_variants" not in changes:
            changes.append("known_spelling_variants")
        text = expanded
    return text, changes
