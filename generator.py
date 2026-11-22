"""Cryptographically secure password and passphrase generation."""

from __future__ import annotations

import secrets
import string

CHARACTER_SETS = {
    "uppercase": string.ascii_uppercase,
    "lowercase": string.ascii_lowercase,
    "numbers": string.digits,
    "symbols": string.punctuation,
}
AMBIGUOUS_CHARACTERS = frozenset("O0l1")
PASSPHRASE_WORDS = (
    "amber", "anchor", "apricot", "badger", "bamboo", "beacon", "birch",
    "breeze", "cactus", "candle", "canvas", "cedar", "cinder", "cobalt",
    "comet", "coral", "cricket", "daisy", "delta", "drizzle", "eagle",
    "ember", "falcon", "fern", "fjord", "forest", "fossil", "galaxy",
    "garden", "ginger", "glacier", "harbor", "hazel", "honey", "island",
    "jasmine", "jigsaw", "jungle", "kiwi", "lantern", "lavender", "lemon",
    "lilac", "maple", "marble", "meadow", "meteor", "midnight", "mint",
    "nectar", "ocean", "olive", "onyx", "orchid", "otter", "panda",
    "pebble", "pepper", "phoenix", "planet", "plum", "puzzle", "quartz",
    "rabbit", "rainbow", "raven", "ripple", "rocket", "saffron", "sailor",
    "silver", "spruce", "starlight", "summit", "tangerine", "thunder",
    "tulip", "velvet", "willow", "winter", "yonder", "zephyr",
)


def generate_password(
    length: int = 16,
    *,
    uppercase: bool = True,
    lowercase: bool = True,
    numbers: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """Generate a password meeting every selected character requirement."""
    if not isinstance(length, int) or isinstance(length, bool) or not 8 <= length <= 64:
        raise ValueError("length must be an integer from 8 to 64")
    selected = [
        CHARACTER_SETS[name]
        for name, enabled in (
            ("uppercase", uppercase),
            ("lowercase", lowercase),
            ("numbers", numbers),
            ("symbols", symbols),
        )
        if enabled
    ]
    if not selected:
        raise ValueError("select at least one character category")

    def filtered(characters: str) -> str:
        return "".join(char for char in characters if not exclude_ambiguous or char not in AMBIGUOUS_CHARACTERS)

    pools = [filtered(pool) for pool in selected]
    if any(not pool for pool in pools):
        raise ValueError("a selected category has no available characters")
    alphabet = "".join(pools)
    password = [secrets.choice(pool) for pool in pools]
    password.extend(secrets.choice(alphabet) for _ in range(length - len(password)))
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


def generate_passwords(
    count: int = 5,
    *,
    length: int = 16,
    uppercase: bool = True,
    lowercase: bool = True,
    numbers: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> list[str]:
    """Generate between one and ten independent password suggestions."""
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 10:
        raise ValueError("count must be an integer from 1 to 10")
    return [
        generate_password(
            length,
            uppercase=uppercase,
            lowercase=lowercase,
            numbers=numbers,
            symbols=symbols,
            exclude_ambiguous=exclude_ambiguous,
        )
        for _ in range(count)
    ]


def generate_passphrase(
    word_count: int = 4,
    *,
    separator: str = "-",
    capitalize: bool = False,
    add_number: bool = False,
) -> str:
    """Create a memorable passphrase from independently selected local words."""
    if not isinstance(word_count, int) or isinstance(word_count, bool) or not 3 <= word_count <= 10:
        raise ValueError("word_count must be an integer from 3 to 10")
    if not isinstance(separator, str) or len(separator) > 3:
        raise ValueError("separator must be a string of at most 3 characters")
    words = [secrets.choice(PASSPHRASE_WORDS) for _ in range(word_count)]
    if capitalize:
        words = [word.capitalize() for word in words]
    phrase = separator.join(words)
    if add_number:
        phrase += separator + str(secrets.randbelow(100))
    return phrase
