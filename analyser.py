"""Local password analysis and actionable feedback."""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
import string

from common_passwords import COMMON_PASSWORDS
from patterns import detect_patterns, normalize_password
from scoring import score_password


@dataclass(frozen=True)
class PasswordAnalysis:
    """A complete, presentation-ready password assessment."""

    score: int
    rating: str
    entropy_bits: float
    category_scores: dict[str, int]
    weaknesses: tuple[str, ...]
    risks: tuple[str, ...]
    recommendations: tuple[str, ...]
    checklist: dict[str, bool]


def estimate_entropy(password: str) -> float:
    """Estimate entropy from observed character classes and repetition.

    This is a rough comparison metric, not a crack-time prediction.
    """
    if not password:
        return 0.0
    pool_size = 0
    if any(char in string.ascii_lowercase for char in password):
        pool_size += 26
    if any(char in string.ascii_uppercase for char in password):
        pool_size += 26
    if any(char in string.digits for char in password):
        pool_size += 10
    if any(char in string.punctuation for char in password):
        pool_size += len(string.punctuation)
    if any(not char.isascii() for char in password):
        pool_size += 100
    if pool_size == 0:
        pool_size = len(set(password))
    entropy = len(password) * math.log2(max(pool_size, 1))
    counts = {char: password.count(char) for char in set(password)}
    if len(password) > 1:
        shannon = -sum(
            (count / len(password)) * math.log2(count / len(password))
            for count in counts.values()
        )
        entropy = min(entropy, len(password) * shannon)
    if detect_patterns(password):
        entropy *= 0.75
    return round(max(0.0, entropy), 1)


def analyze_password(password: str) -> PasswordAnalysis:
    """Analyze a password without storing or transmitting its value."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    normalized = normalize_password(password)
    base_without_suffix = normalize_password(re.sub(r"[^a-z]+$", "", password.lower()))
    common_match = (
        password.lower() in COMMON_PASSWORDS
        or normalized in COMMON_PASSWORDS
        or base_without_suffix in COMMON_PASSWORDS
    )
    predictable_suffix = bool(re.fullmatch(
        r"(?:password|admin|welcome|qwerty|letmein)\d{1,6}",
        password.lower(),
    ))
    patterns = detect_patterns(password)
    categories = {
        "uppercase": any(char in string.ascii_uppercase for char in password),
        "lowercase": any(char in string.ascii_lowercase for char in password),
        "numbers": any(char in string.digits for char in password),
        "symbols": any(char in string.punctuation for char in password),
    }

    score, category_scores = score_password(
        password,
        categories=categories,
        patterns=patterns,
        is_common=common_match or predictable_suffix,
    )
    if score <= 20:
        rating = "Very Weak"
    elif score <= 40:
        rating = "Weak"
    elif score <= 60:
        rating = "Moderate"
    elif score <= 80:
        rating = "Strong"
    else:
        rating = "Very Strong"

    weaknesses: list[str] = []
    if len(password) < 8:
        weaknesses.append("Shorter than 8 characters.")
    elif len(password) < 12:
        weaknesses.append("Under 12 characters; a longer password is safer.")
    missing = [name for name, present in categories.items() if not present]
    if missing:
        weaknesses.append("Missing character types: " + ", ".join(missing) + ".")
    if common_match or predictable_suffix:
        weaknesses.append("Matches a common password or a predictable variation.")
    for pattern in patterns:
        weaknesses.append(pattern)
    if len(set(password)) <= 2 and len(password) > 2:
        weaknesses.append("Uses only a very small set of distinct characters.")

    recommendations: list[str] = []
    if len(password) < 16:
        recommendations.append("Use at least 16 characters, or choose a long passphrase.")
    if common_match or predictable_suffix:
        recommendations.append("Replace it with a unique password unrelated to familiar words.")
    if missing:
        recommendations.append("Add variety naturally, or use a randomly generated password.")
    if patterns:
        recommendations.append("Avoid sequences, repeated runs, keyboard walks, and predictable substitutions.")
    if not recommendations:
        recommendations.append("Keep it unique to one account and store it in a password manager.")
    if len(password) < 8 or common_match or predictable_suffix:
        risks = ("This password may be guessed quickly or found in common-password lists.",)
    elif patterns or len(password) < 12:
        risks = ("Patterns and limited length can make offline guessing more effective.",)
    else:
        risks = ("Reusing this password on another service can expose otherwise unrelated accounts.",)

    checklist = {
        "At least 8 characters": len(password) >= 8,
        "At least 12 characters": len(password) >= 12,
        "Uppercase letter": categories["uppercase"],
        "Lowercase letter": categories["lowercase"],
        "Number": categories["numbers"],
        "Special character": categories["symbols"],
        "No common-password match": not (common_match or predictable_suffix),
        "No detected patterns": not patterns,
    }
    return PasswordAnalysis(
        score=score,
        rating=rating,
        entropy_bits=estimate_entropy(password),
        category_scores=category_scores,
        weaknesses=tuple(weaknesses),
        risks=risks,
        recommendations=tuple(recommendations),
        checklist=checklist,
    )
