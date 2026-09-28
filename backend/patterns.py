"""
Pattern detection module for password analysis.
Detects dictionary words, keyboard walks, sequences, repeating patterns, leetspeak, dates, etc.
Optimized with Trie for O(L) dictionary lookup instead of O(N*L) linear scan.
"""
import re
from dataclasses import dataclass
from typing import List, Optional, Set, Dict
from constants import (
    COMMON_PASSWORDS,
    DICTIONARY_WORDS,
    KEYBOARD_ROWS,
    KEYBOARD_COLS,
    LEET_MAP,
    COMMON_YEARS,
)


@dataclass
class PatternMatch:
    """Represents a detected pattern in a password."""
    pattern_type: str      # e.g., "dictionary_word", "keyboard_walk", "sequence"
    severity: str          # "critical", "high", "medium", "low"
    message: str           # Human-readable description
    matched_text: str = "" # The actual matched substring
    position: int = -1     # Start position in password


# ==================== PRECOMPUTED DATA STRUCTURES ====================

# Trie for O(L) dictionary word detection (built once at module load)
class _TrieNode:
    __slots__ = ('children', 'word', 'is_end')
    def __init__(self):
        self.children: Dict[str, '_TrieNode'] = {}
        self.word: Optional[str] = None
        self.is_end: bool = False

_DICTIONARY_TRIE: Optional[_TrieNode] = None
_TRIE_BUILT = False

# Precomputed keyboard walk sequences (built once)
_KEYBOARD_SEQUENCES: Optional[Set[str]] = None

# Precompiled leetspeak regex patterns
_LEET_PATTERNS_COMPILED: Optional[List[tuple[re.Pattern, str]]] = None

# Sorted years for consistent iteration
_SORTED_YEARS: Optional[List[str]] = None


def _build_dictionary_trie() -> _TrieNode:
    """Build Trie from dictionary words for O(L) substring search."""
    root = _TrieNode()
    for word in DICTIONARY_WORDS:
        if len(word) < 4:
            continue
        node = root
        for char in word:
            if char not in node.children:
                node.children[char] = _TrieNode()
            node = node.children[char]
        node.is_end = True
        node.word = word
    return root


def _build_keyboard_sequences() -> Set[str]:
    """Precompute all keyboard walk sequences (length 3+)."""
    sequences = set()
    min_length = 3

    # Horizontal rows (forward and reverse)
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - min_length + 1):
            seq = row[i:i + min_length]
            sequences.add(seq)
            sequences.add(seq[::-1])

    # Vertical columns (forward and reverse)
    for col in KEYBOARD_COLS:
        for i in range(len(col) - min_length + 1):
            seq = col[i:i + min_length]
            sequences.add(seq)
            sequences.add(seq[::-1])

    return sequences


def _build_leetspeak_patterns() -> List[tuple[re.Pattern, str]]:
    """Precompile leetspeak regex patterns."""
    leet_patterns = {
        r'[4@]': 'a', r'8': 'b', r'[\(<{]': 'c', r'[\)\]}]': 'd', r'3': 'e',
        r'[=|]': 'f', r'6': 'g', r'#': 'h', r'[1!|]': 'i', r'_\|': 'j',
        r'\|<': 'k', r'1\|': 'l', r'0': 'o', r'\$': 's', r'7': 't',
        r'\+': 't', r'\|_\|': 'u', r'\\/': 'v', r'\\/\\/': 'w', r'><': 'x',
    }
    return [(re.compile(pattern), char) for pattern, char in leet_patterns.items()]


def _init_pattern_data():
    """Initialize all precomputed data structures (called once at module load)."""
    global _DICTIONARY_TRIE, _TRIE_BUILT, _KEYBOARD_SEQUENCES
    global _LEET_PATTERNS_COMPILED, _SORTED_YEARS

    if _TRIE_BUILT:
        return

    _DICTIONARY_TRIE = _build_dictionary_trie()
    _KEYBOARD_SEQUENCES = _build_keyboard_sequences()
    _LEET_PATTERNS_COMPILED = _build_leetspeak_patterns()
    _SORTED_YEARS = sorted(COMMON_YEARS, key=lambda y: (len(y), y), reverse=True)  # Longer first
    _TRIE_BUILT = True


# Initialize on import
_init_pattern_data()


# ==================== PATTERN DETECTION FUNCTIONS ====================

def detect_patterns(password: str) -> List[PatternMatch]:
    """
    Run all pattern detectors on the password.
    Returns list of PatternMatch objects sorted by severity.
    """
    if not password:
        return []

    patterns = []
    lower = password.lower()

    # 1. Critical: Exact common password match (O(1) set lookup)
    if password in COMMON_PASSWORDS:
        patterns.append(PatternMatch(
            pattern_type="common_password",
            severity="critical",
            message="Password appears in top 10k breached passwords list",
            matched_text=password,
            position=0,
        ))

    # 2. High: Dictionary word detection (O(L) Trie search)
    dict_matches = _detect_dictionary_words(lower)
    patterns.extend(dict_matches)

    # 3. High: Keyboard walks (precomputed set lookup)
    kb_matches = _detect_keyboard_walks(lower)
    patterns.extend(kb_matches)

    # 4. Medium: Sequences (abc, 123, etc.)
    seq_matches = _detect_sequences(lower)
    patterns.extend(seq_matches)

    # 5. Medium: Repeating characters/patterns
    rep_matches = _detect_repeating_patterns(lower)
    patterns.extend(rep_matches)

    # 6. Medium: Leetspeak substitutions (precompiled regex)
    leet_matches = _detect_leetspeak(lower)
    patterns.extend(leet_matches)

    # 7. Low: Years/Dates (sorted iteration)
    year_matches = _detect_years(lower)
    patterns.extend(year_matches)

    # Sort by severity priority
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    patterns.sort(key=lambda p: severity_order.get(p.severity, 4))

    return patterns


def _detect_dictionary_words(lower: str) -> List[PatternMatch]:
    """
    Detect dictionary words as substrings using Trie.
    O(L^2) worst case but typically O(L) for early exits.
    """
    matches = []
    n = len(lower)

    # Search for dictionary words starting at each position
    for i in range(n - 3):  # Need at least 4 chars
        node = _DICTIONARY_TRIE
        for j in range(i, n):
            char = lower[j]
            if char not in node.children:
                break
            node = node.children[char]
            if node.is_end:
                # Found a dictionary word
                word = node.word
                matches.append(PatternMatch(
                    pattern_type="dictionary_word",
                    severity="high",
                    message=f"Contains dictionary word: '{word}'",
                    matched_text=word,
                    position=i,
                ))
                return matches  # Only report first found

    return matches


def _detect_keyboard_walks(lower: str) -> List[PatternMatch]:
    """Detect keyboard walks using precomputed sequence set."""
    matches = []

    for seq in _KEYBOARD_SEQUENCES:
        if seq in lower:
            pos = lower.index(seq)
            matches.append(PatternMatch(
                pattern_type="keyboard_walk",
                severity="high",
                message=f"Contains keyboard pattern: '{seq}'",
                matched_text=seq,
                position=pos,
            ))
            break  # Only report first keyboard walk

    return matches


def _detect_sequences(lower: str) -> List[PatternMatch]:
    """Detect character sequences (abc, 123, etc.)."""
    matches = []
    min_length = 3

    # Alphabetic sequences
    for i in range(len(lower) - min_length + 1):
        substr = lower[i:i + min_length]
        if _is_alphabetic_sequence(substr):
            matches.append(PatternMatch(
                pattern_type="alphabetic_sequence",
                severity="medium",
                message=f"Contains alphabetic sequence: '{substr}'",
                matched_text=substr,
                position=i,
            ))
            break

    # Numeric sequences
    for i in range(len(lower) - min_length + 1):
        substr = lower[i:i + min_length]
        if _is_numeric_sequence(substr):
            matches.append(PatternMatch(
                pattern_type="numeric_sequence",
                severity="medium",
                message=f"Contains numeric sequence: '{substr}'",
                matched_text=substr,
                position=i,
            ))
            break

    return matches


def _is_alphabetic_sequence(s: str) -> bool:
    """Check if string is consecutive alphabetic characters."""
    if len(s) < 3:
        return False
    for i in range(len(s) - 1):
        if not (s[i].isalpha() and s[i+1].isalpha()):
            return False
        if ord(s[i+1]) - ord(s[i]) != 1:
            return False
    return True


def _is_numeric_sequence(s: str) -> bool:
    """Check if string is consecutive numeric characters."""
    if len(s) < 3:
        return False
    for i in range(len(s) - 1):
        if not (s[i].isdigit() and s[i+1].isdigit()):
            return False
        if int(s[i+1]) - int(s[i]) != 1:
            return False
    return True


def _detect_repeating_patterns(lower: str) -> List[PatternMatch]:
    """Detect repeating characters or patterns."""
    matches = []

    # Repeating single character (aaa, 111)
    for i in range(len(lower) - 2):
        if lower[i] == lower[i+1] == lower[i+2]:
            matches.append(PatternMatch(
                pattern_type="repeating_character",
                severity="medium",
                message=f"Contains repeating character: '{lower[i] * 3}'",
                matched_text=lower[i] * 3,
                position=i,
            ))
            break

    # Repeating pattern (ababab, 123123)
    for pattern_len in range(2, 5):
        for i in range(len(lower) - pattern_len * 2 + 1):
            pattern = lower[i:i + pattern_len]
            if lower[i + pattern_len:i + pattern_len * 2] == pattern:
                matches.append(PatternMatch(
                    pattern_type="repeating_pattern",
                    severity="medium",
                    message=f"Contains repeating pattern: '{pattern}'",
                    matched_text=pattern * 2,
                    position=i,
                ))
                return matches  # Return first found

    return matches


def _detect_leetspeak(lower: str) -> List[PatternMatch]:
    """Detect common leetspeak substitutions using precompiled regex."""
    matches = []

    # Only count as leetspeak if BOTH the substitution symbol AND the letter it replaces
    # are present in the password (e.g., both 'a' and '@' or 'e' and '3')
    leet_count = 0
    for pattern, char in _LEET_PATTERNS_COMPILED:
        if pattern.search(lower) and char in lower:
            leet_count += 1

    if leet_count >= 2:
        matches.append(PatternMatch(
            pattern_type="leetspeak",
            severity="medium",
            message=f"Contains leetspeak substitutions ({leet_count} detected)",
            matched_text="",
            position=-1,
        ))

    return matches


def _detect_years(lower: str) -> List[PatternMatch]:
    """Detect common years (1900-2029) using sorted list."""
    matches = []
    for year in _SORTED_YEARS:
        if year in lower:
            pos = lower.index(year)
            matches.append(PatternMatch(
                pattern_type="year",
                severity="low",
                message=f"Contains year: '{year}'",
                matched_text=year,
                position=pos,
            ))
            break  # Only report first year
    return matches


def calculate_pattern_penalty(patterns: List[PatternMatch]) -> float:
    """
    Calculate score penalty based on detected patterns.
    Returns penalty value (0-25) to subtract from score.
    """
    severity_weights = {
        "critical": 25,
        "high": 15,
        "medium": 8,
        "low": 3,
    }

    total_penalty = 0
    for pattern in patterns:
        weight = severity_weights.get(pattern.severity, 0)
        total_penalty += weight

    # Cap at 25 (max pattern penalty per README)
    return min(total_penalty, 25.0)