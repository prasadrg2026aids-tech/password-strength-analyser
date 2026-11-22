"""Transparent weighted scoring for password analysis."""

from __future__ import annotations

import math
import string


def score_password(
    password: str,
    *,
    categories: dict[str, bool],
    patterns: tuple[str, ...],
    is_common: bool,
) -> tuple[int, dict[str, int]]:
    """Return a 0-100 score and its five weighted category scores."""
    length = len(password)
    length_score = min(30, round(length / 16 * 30))
    present_count = sum(categories.values())
    diversity_score = round(present_count / 4 * 25)

    unique_ratio = len(set(password)) / max(length, 1)
    pool_size = sum(
        size
        for present, size in (
            (categories.get("lowercase", False), 26),
            (categories.get("uppercase", False), 26),
            (categories.get("numbers", False), 10),
            (categories.get("symbols", False), len(string.punctuation)),
        )
        if present
    )
    estimated_bits = length * math.log2(max(pool_size, 1))
    uniqueness_score = round(min(20, estimated_bits / 80 * 20) * unique_ratio)

    pattern_score = max(0, 15 - min(15, len(patterns) * 5))
    dictionary_score = 0 if is_common else 10
    if is_common:
        length_score = min(length_score, 8)
        uniqueness_score = min(uniqueness_score, 4)
        pattern_score = min(pattern_score, 5)

    scores = {
        "length": length_score,
        "character diversity": diversity_score,
        "uniqueness": uniqueness_score,
        "pattern resistance": pattern_score,
        "dictionary resistance": dictionary_score,
    }
    score = min(100, max(0, sum(scores.values())))
    if is_common:
        if score > 20:
            scaled = {name: round(points * 20 / score) for name, points in scores.items()}
            difference = 20 - sum(scaled.values())
            scaled["length"] += difference
            scores = scaled
            score = 20
    return score, scores
