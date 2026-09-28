"""
Entropy calculation module for password strength analysis.
Implements Shannon entropy: E = L * log2(R) where L=length, R=charset size.
"""
import math
from constants import get_charset_size, get_composition


def calculate_entropy(password: str) -> float:
    """
    Calculate Shannon entropy in bits.
    Formula: E = L * log2(R)
    where L = password length, R = character pool size.
    """
    if not password:
        return 0.0

    length = len(password)
    charset_size = get_charset_size(password)

    # Shannon entropy
    entropy = length * math.log2(charset_size)
    return round(entropy, 1)


def calculate_entropy_detailed(password: str) -> dict:
    """Calculate entropy with detailed breakdown."""
    composition = get_composition(password)
    charset_size = get_charset_size(password)
    entropy = calculate_entropy(password)

    # Character type contributions
    contributions = {}
    if composition["lowercase"]:
        contributions["lowercase"] = math.log2(26)
    if composition["uppercase"]:
        contributions["uppercase"] = math.log2(26)
    if composition["digits"]:
        contributions["digits"] = math.log2(10)
    if composition["symbols"]:
        contributions["symbols"] = math.log2(32)  # Approximate symbol count

    return {
        "entropy": entropy,
        "length": composition["length"],
        "charset_size": charset_size,
        "composition": composition,
        "per_char_entropy": round(entropy / composition["length"], 2) if composition["length"] > 0 else 0,
        "contributions": contributions,
    }


def estimate_crack_time(entropy: float) -> dict:
    """
    Estimate crack times for different attack scenarios.
    Based on entropy bits and guessing rates.
    """
    if entropy <= 0:
        return {
            "online_throttled": "instant",
            "offline_slow_hash": "instant",
            "offline_fast_hash": "instant",
            "gpu_cluster": "instant",
        }

    # Guessing rates (guesses per second)
    rates = {
        "online_throttled": 100,          # 100 guesses/sec (rate limited)
        "offline_slow_hash": 10_000,      # 10K guesses/sec (bcrypt/scrypt)
        "offline_fast_hash": 1_000_000_000,  # 1B guesses/sec (MD5/SHA1)
        "gpu_cluster": 10_000_000_000,    # 10B guesses/sec (GPU cluster)
    }

    # Total possible combinations = 2^entropy
    combinations = 2 ** entropy

    # Average time = combinations / (2 * rate)  (average case, not worst case)
    results = {}
    for scenario, rate in rates.items():
        avg_seconds = combinations / (2 * rate)
        results[scenario] = _format_time(avg_seconds)

    return results


def _format_time(seconds: float) -> str:
    """Format seconds into human-readable time string."""
    if seconds < 1:
        return "instant"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    elif seconds < 31536000:
        return f"{seconds / 86400:.1f} days"
    elif seconds < 315360000:
        return f"{seconds / 31536000:.1f} years"
    elif seconds < 3153600000:
        return f"{seconds / 315360000:.1f} decades"
    elif seconds < 31536000000:
        return f"{seconds / 3153600000:.1f} centuries"
    else:
        return "millennia+"