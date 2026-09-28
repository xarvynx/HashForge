"""
Constants and data loading for password analysis.
Loads wordlists and common passwords at module import for O(1) lookup.
"""
from pathlib import Path
from typing import Set

# Base directory for data files
DATA_DIR = Path(__file__).parent / "data"

# Character sets for entropy calculation
LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGIT_CHARS = "0123456789"
SYMBOL_CHARS = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~"

# Keyboard layouts for walk detection (QWERTY)
KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

KEYBOARD_COLS = [
    "qaz",
    "wsx",
    "edc",
    "rfv",
    "tgb",
    "yhn",
    "ujm",
    "ik,",
    "ol.",
    "p;/",
]

# Leetspeak substitutions
LEET_MAP = {
    'a': '@4', 'b': '8', 'c': '(', 'd': '|)', 'e': '3',
    'f': '|=', 'g': '6', 'h': '#', 'i': '1!', 'j': '_|',
    'k': '|<', 'l': '1|', 'm': '|\\/|', 'n': '|\\|', 'o': '0',
    'p': '|*', 'q': '9', 'r': '|2', 's': '$5', 't': '7+',
    'u': '|_|', 'v': '\\/', 'w': '\\/\\/', 'x': '><', 'y': '`/', 'z': '2'
}

# Common years to detect
COMMON_YEARS = {str(y) for y in range(1900, 2030)}

# Load common passwords (exact match = critical severity)
_COMMON_PASSWORDS: Set[str] = set()
_COMMON_PASSWORDS_LOADED = False

# Load dictionary words (substring match = high severity)
_DICTIONARY_WORDS: Set[str] = set()
_DICTIONARY_WORDS_LOADED = False


def load_common_passwords() -> Set[str]:
    """Load top 10k common passwords from file."""
    global _COMMON_PASSWORDS, _COMMON_PASSWORDS_LOADED
    if _COMMON_PASSWORDS_LOADED:
        return _COMMON_PASSWORDS

    filepath = DATA_DIR / "common_passwords.txt"
    if filepath.exists():
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            _COMMON_PASSWORDS = {line.strip() for line in f if line.strip()}
    else:
        # Fallback minimal list
        _COMMON_PASSWORDS = {
            "password", "123456", "123456789", "12345678", "12345",
            "1234567890", "qwerty", "abc123", "111111", "1234567",
            "password123", "admin", "letmein", "welcome", "monkey",
        }

    _COMMON_PASSWORDS_LOADED = True
    return _COMMON_PASSWORDS


def load_dictionary_words() -> Set[str]:
    """Load dictionary words for substring detection."""
    global _DICTIONARY_WORDS, _DICTIONARY_WORDS_LOADED
    if _DICTIONARY_WORDS_LOADED:
        return _DICTIONARY_WORDS

    filepath = DATA_DIR / "dictionary_words.txt"
    if filepath.exists():
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            _DICTIONARY_WORDS = {line.strip().lower() for line in f if line.strip()}
    else:
        _DICTIONARY_WORDS = set()

    _DICTIONARY_WORDS_LOADED = True
    return _DICTIONARY_WORDS


# Initialize on import
load_common_passwords()
load_dictionary_words()


# Exported constants
COMMON_PASSWORDS = _COMMON_PASSWORDS
DICTIONARY_WORDS = _DICTIONARY_WORDS


def get_charset_size(password: str) -> int:
    """Calculate the character pool size based on password composition."""
    has_lower = any(c in LOWERCASE_CHARS for c in password)
    has_upper = any(c in UPPERCASE_CHARS for c in password)
    has_digit = any(c in DIGIT_CHARS for c in password)
    has_symbol = any(c in SYMBOL_CHARS for c in password)

    size = 0
    if has_lower:
        size += len(LOWERCASE_CHARS)
    if has_upper:
        size += len(UPPERCASE_CHARS)
    if has_digit:
        size += len(DIGIT_CHARS)
    if has_symbol:
        size += len(SYMBOL_CHARS)

    return max(size, 1)  # At least 1 to avoid log(0)


def get_composition(password: str) -> dict:
    """Get character composition breakdown."""
    return {
        "length": len(password),
        "lowercase": any(c in LOWERCASE_CHARS for c in password),
        "uppercase": any(c in UPPERCASE_CHARS for c in password),
        "digits": any(c in DIGIT_CHARS for c in password),
        "symbols": any(c in SYMBOL_CHARS for c in password),
    }