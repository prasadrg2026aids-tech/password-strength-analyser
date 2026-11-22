"""Heuristics for common and predictable password patterns."""

from __future__ import annotations

import re

_SUBSTITUTIONS = str.maketrans({"@": "a", "4": "a", "0": "o", "1": "i", "!": "i", "3": "e", "$": "s", "5": "s", "7": "t"})
_KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")
_SEQUENCES = tuple(
    "".join(chr(start + offset) for offset in range(6))
    for start in range(ord("a"), ord("u") + 1)
) + tuple(
    "".join(str((start + offset) % 10) for offset in range(6))
    for start in range(10)
)


def normalize_password(password: str) -> str:
    """Normalize common leetspeak substitutions for dictionary comparison."""
    return password.lower().translate(_SUBSTITUTIONS)


def detect_patterns(password: str) -> tuple[str, ...]:
    """Return human-readable descriptions of detected predictable patterns."""
    lowered = password.lower()
    compact = re.sub(r"[^a-z0-9]", "", normalize_password(password))
    findings: list[str] = []

    if re.search(r"(.)\1{3,}", password, flags=re.IGNORECASE):
        findings.append("Contains a run of repeated characters.")
    if any(sequence in lowered for sequence in _SEQUENCES):
        findings.append("Contains an ascending alphabetic or numeric sequence.")
    if any(sequence in lowered or sequence[::-1] in lowered for row in _KEYBOARD_ROWS for sequence in (row[:6], row[2:8], row[4:10]) if len(sequence) >= 6):
        findings.append("Contains a keyboard-row pattern.")
    if re.search(r"(.{2,})\1", compact):
        findings.append("Repeats the same password segment.")
    normalized = normalize_password(password)
    if normalized != password.lower() and re.search(r"[a-z]", password.lower()):
        findings.append("Uses predictable letter-for-symbol or letter-for-number substitutions.")
    return tuple(findings)
