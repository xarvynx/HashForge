"""
Main password analyzer - orchestrates all analysis modules.
Combines entropy, patterns, breach check into final score.
"""
from dataclasses import dataclass
from typing import List, Optional
from constants import get_composition
from entropy import calculate_entropy, estimate_crack_time
from patterns import detect_patterns, calculate_pattern_penalty, PatternMatch
from breach_check import check_breach


@dataclass
class AnalysisResult:
    """Complete password analysis result."""
    score: int
    strength: str
    entropy: float
    crack_time: dict
    feedback: dict
    breached: bool
    composition: dict
    patterns: List[PatternMatch]


# Strength thresholds
STRENGTH_THRESHOLDS = [
    (81, "Very Strong"),
    (61, "Strong"),
    (41, "Fair"),
    (21, "Weak"),
    (0, "Very Weak"),
]


def analyze_password(password: str, check_breach_api: bool = True) -> AnalysisResult:
    """
    Perform complete password analysis.

    Args:
        password: The password to analyze
        check_breach_api: Whether to call HIBP API (can be disabled for testing)

    Returns:
        AnalysisResult with all metrics
    """
    if not password:
        return _empty_result()

    # 1. Character composition
    composition = get_composition(password)

    # 2. Entropy calculation
    entropy = calculate_entropy(password)

    # 3. Pattern detection
    patterns = detect_patterns(password)

    # 4. Breach check
    breached = False
    if check_breach_api:
        breached = check_breach(password)

    # 5. Calculate score
    score = _calculate_score(
        entropy=entropy,
        composition=composition,
        patterns=patterns,
        breached=breached,
        length=len(password),
    )

    # 6. Determine strength label
    strength = _get_strength_label(score)

    # 7. Crack time estimation
    crack_time = estimate_crack_time(entropy)

    # 8. Generate feedback
    feedback = _generate_feedback(patterns, breached, composition, entropy)

    return AnalysisResult(
        score=score,
        strength=strength,
        entropy=entropy,
        crack_time=crack_time,
        feedback=feedback,
        breached=breached,
        composition=composition,
        patterns=patterns,
    )


def _calculate_score(
    entropy: float,
    composition: dict,
    patterns: List[PatternMatch],
    breached: bool,
    length: int,
) -> int:
    """
    Calculate overall score (0-100) using weighted formula from README:

    | Factor | Weight | Description |
    |--------|--------|-------------|
    | Length | 30% | Longer passwords score higher |
    | Entropy | 30% | Bits of randomness |
    | Character Variety | 20% | Mix of character types |
    | Pattern Penalty | -25% | Deductions for weak patterns |
    | Breach Penalty | -50% | Massive penalty if breached |
    """
    # Length score (0-30): max at 20+ chars
    length_score = min(30, (length / 20) * 30)

    # Entropy score (0-30): max at 80+ bits
    entropy_score = min(30, (entropy / 80) * 30)

    # Character variety score (0-20)
    variety_score = 0
    if composition["lowercase"]:
        variety_score += 5
    if composition["uppercase"]:
        variety_score += 5
    if composition["digits"]:
        variety_score += 5
    if composition["symbols"]:
        variety_score += 5

    # Base score (max 80)
    base_score = length_score + entropy_score + variety_score

    # Pattern penalty (max -25)
    pattern_penalty = calculate_pattern_penalty(patterns)

    # Breach penalty (-50 if breached)
    breach_penalty = 50 if breached else 0

    # Final score
    final_score = base_score - pattern_penalty - breach_penalty

    # Clamp to 0-100
    return max(0, min(100, int(round(final_score))))


def _get_strength_label(score: int) -> str:
    """Get strength label from score."""
    for threshold, label in STRENGTH_THRESHOLDS:
        if score >= threshold:
            return label
    return "Very Weak"


def _generate_feedback(
    patterns: List[PatternMatch],
    breached: bool,
    composition: dict,
    entropy: float,
) -> dict:
    """Generate actionable feedback for the user."""
    warnings = []
    suggestions = []

    # Breach warning (highest priority)
    if breached:
        warnings.append("This password has been found in data breaches. Change it immediately.")
        suggestions.append("Use a completely different, unique password.")

    # Pattern-based warnings
    for pattern in patterns:
        if pattern.severity in ("critical", "high"):
            warnings.append(pattern.message)
        if pattern.pattern_type == "dictionary_word":
            suggestions.append("Avoid dictionary words or common phrases.")
        elif pattern.pattern_type == "keyboard_walk":
            suggestions.append("Avoid keyboard patterns (e.g., 'qwerty', 'asdf').")
        elif pattern.pattern_type in ("alphabetic_sequence", "numeric_sequence"):
            suggestions.append("Avoid sequential characters (e.g., 'abc', '123').")
        elif pattern.pattern_type == "repeating_character":
            suggestions.append("Avoid repeating the same character multiple times.")
        elif pattern.pattern_type == "repeating_pattern":
            suggestions.append("Avoid repeating patterns (e.g., 'ababab').")
        elif pattern.pattern_type == "leetspeak":
            suggestions.append("Leetspeak substitutions (e.g., 'p@ssw0rd') are well-known to attackers.")
        elif pattern.pattern_type == "year":
            suggestions.append("Avoid using years or dates in passwords.")

    # Composition-based suggestions
    if not composition["uppercase"]:
        suggestions.append("Add uppercase letters.")
    if not composition["digits"]:
        suggestions.append("Add numbers.")
    if not composition["symbols"]:
        suggestions.append("Add special symbols (!@#$%^&*).")
    if composition["length"] < 12:
        suggestions.append("Use at least 12 characters (longer is better).")
    if composition["length"] < 16:
        suggestions.append("Consider using 16+ characters for stronger protection.")

    # Entropy-based suggestions
    if entropy < 40:
        suggestions.append("Increase randomness - use a password manager to generate secure passwords.")
    elif entropy < 60:
        suggestions.append("Good entropy, but could be stronger with more length or variety.")

    # Deduplicate suggestions
    suggestions = list(dict.fromkeys(suggestions))

    # Limit to top 5 suggestions
    suggestions = suggestions[:5]

    result = {"suggestions": suggestions}
    if warnings:
        result["warning"] = warnings[0]  # Primary warning

    return result


def _empty_result() -> AnalysisResult:
    """Return empty result for invalid input."""
    return AnalysisResult(
        score=0,
        strength="Very Weak",
        entropy=0.0,
        crack_time={
            "online_throttled": "instant",
            "offline_slow_hash": "instant",
            "offline_fast_hash": "instant",
            "gpu_cluster": "instant",
        },
        feedback={
            "warning": "Please enter a password",
            "suggestions": ["Enter a password to analyze"],
        },
        breached=False,
        composition={
            "length": 0,
            "lowercase": False,
            "uppercase": False,
            "digits": False,
            "symbols": False,
        },
        patterns=[],
    )


# Convenience function for API
def analyze_password_dict(password: str, check_breach_api: bool = True) -> dict:
    """Return analysis as dictionary for JSON serialization."""
    result = analyze_password(password, check_breach_api)
    return {
        "score": result.score,
        "strength": result.strength,
        "entropy": result.entropy,
        "crack_time": result.crack_time,
        "feedback": result.feedback,
        "breached": result.breached,
        "composition": result.composition,
    }