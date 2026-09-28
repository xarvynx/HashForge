"""
Cryptographically secure password generator.
Uses Python's secrets module for CSPRNG.
"""
import secrets
import string
from typing import Optional
from constants import get_charset_size
from entropy import calculate_entropy


# Character pools
LOWERCASE = string.ascii_lowercase      # 26
UPPERCASE = string.ascii_uppercase      # 26
DIGITS = string.digits                  # 10
SYMBOLS = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~"  # 32


def generate_password(
    length: int = 20,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> dict:
    """
    Generate a cryptographically secure random password.

    Args:
        length: Password length (8-128)
        use_uppercase: Include uppercase letters
        use_digits: Include digits
        use_symbols: Include symbols
        exclude_ambiguous: Exclude ambiguous chars (l, 1, I, O, 0, etc.)

    Returns:
        Dict with 'password' and 'entropy' keys
    """
    # Validate length
    length = max(8, min(128, length))

    # Build character pool
    pool = LOWERCASE
    if use_uppercase:
        pool += UPPERCASE
    if use_digits:
        pool += DIGITS
    if use_symbols:
        pool += SYMBOLS

    # Optionally remove ambiguous characters
    if exclude_ambiguous:
        ambiguous = set("l1IO0|!`~;:,./?")
        pool = "".join(c for c in pool if c not in ambiguous)

    # Ensure at least one character from each selected category
    password_chars = []

    # Always include lowercase
    password_chars.append(secrets.choice(LOWERCASE))

    if use_uppercase:
        password_chars.append(secrets.choice(UPPERCASE))
    if use_digits:
        password_chars.append(secrets.choice(DIGITS))
    if use_symbols:
        password_chars.append(secrets.choice(SYMBOLS))

    # Fill remaining length
    remaining = length - len(password_chars)
    for _ in range(remaining):
        password_chars.append(secrets.choice(pool))

    # Shuffle the characters
    secrets.SystemRandom().shuffle(password_chars)

    password = "".join(password_chars)

    # Calculate entropy
    entropy = calculate_entropy(password)

    return {
        "password": password,
        "entropy": entropy,
        "length": length,
        "composition": {
            "lowercase": True,
            "uppercase": use_uppercase,
            "digits": use_digits,
            "symbols": use_symbols,
        }
    }


def generate_passphrase(
    word_count: int = 4,
    separator: str = "-",
    capitalize: bool = False,
    include_number: bool = False,
) -> dict:
    """
    Generate a Diceware-style passphrase.

    Args:
        word_count: Number of words (3-10)
        separator: Word separator
        capitalize: Capitalize each word
        include_number: Append random number

    Returns:
        Dict with 'password' and 'entropy' keys
    """
    # Simplified wordlist (in production, use full EFF Diceware list)
    wordlist = [
        "correct", "horse", "battery", "staple", "apple", "banana",
        "orange", "grape", "melon", "peach", "pear", "plum",
        "berry", "cherry", "kiwi", "lemon", "lime", "mango",
        "nectar", "olive", "papaya", "quince", "raisin", "sugar",
        "tanger", "ugli", "vanilla", "walnut", "xigua", "yam",
        "zest", "acorn", "basil", "cocoa", "dill", "fennel",
        "ginger", "honey", "iris", "jasmine", "kale", "lavender",
        "mint", "nutmeg", "oregano", "parsley", "quinoa", "rosemary",
        "sage", "thyme", "vanilla", "wasabi", "yarrow", "zucchini",
    ]

    word_count = max(3, min(10, word_count))
    words = [secrets.choice(wordlist) for _ in range(word_count)]

    if capitalize:
        words = [w.capitalize() for w in words]

    password = separator.join(words)

    if include_number:
        password += separator + str(secrets.randbelow(10000)).zfill(4)

    entropy = calculate_entropy(password)

    return {
        "password": password,
        "entropy": entropy,
        "length": len(password),
        "composition": {
            "lowercase": True,
            "uppercase": capitalize,
            "digits": include_number,
            "symbols": bool(separator and separator not in string.ascii_letters + string.digits),
        }
    }


def generate_pin(length: int = 6) -> dict:
    """Generate a numeric PIN."""
    length = max(4, min(10, length))
    pin = "".join(str(secrets.randbelow(10)) for _ in range(length))
    entropy = calculate_entropy(pin)
    return {
        "password": pin,
        "entropy": entropy,
        "length": length,
        "composition": {
            "lowercase": False,
            "uppercase": False,
            "digits": True,
            "symbols": False,
        }
    }