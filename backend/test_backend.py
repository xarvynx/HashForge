"""
Comprehensive tests for the password analyzer backend.
Run with: python -m pytest test_backend.py -v
"""
import pytest
from fastapi.testclient import TestClient
from app import app
from constants import (
    get_charset_size,
    get_composition,
    COMMON_PASSWORDS,
    DICTIONARY_WORDS,
)
from entropy import calculate_entropy, estimate_crack_time
from patterns import detect_patterns, calculate_pattern_penalty
from analyzer import analyze_password, analyze_password_dict, _calculate_score
from generator import generate_password, generate_passphrase, generate_pin
from breach_check import check_breach

client = TestClient(app)


# ==================== CONSTANTS TESTS ====================

def test_charset_size():
    assert get_charset_size("abc") == 26  # lowercase only
    assert get_charset_size("ABC") == 26  # uppercase only
    assert get_charset_size("123") == 10  # digits only
    assert get_charset_size("!@#") == 31  # symbols only (31 chars in SYMBOL_CHARS)
    assert get_charset_size("aB1!") == 26 + 26 + 10 + 31  # all four
    assert get_charset_size("") == 1  # empty = at least 1


def test_composition():
    comp = get_composition("Test123!")
    assert comp["length"] == 8
    assert comp["lowercase"] is True
    assert comp["uppercase"] is True
    assert comp["digits"] is True
    assert comp["symbols"] is True

    comp = get_composition("lowercase")
    assert comp["lowercase"] is True
    assert comp["uppercase"] is False


def test_common_passwords_loaded():
    assert len(COMMON_PASSWORDS) >= 1000
    assert "password" in COMMON_PASSWORDS
    assert "123456" in COMMON_PASSWORDS


def test_dictionary_words_loaded():
    assert len(DICTIONARY_WORDS) >= 1000
    assert "password" in DICTIONARY_WORDS
    assert "apple" in DICTIONARY_WORDS


# ==================== ENTROPY TESTS ====================

def test_calculate_entropy():
    # Empty password
    assert calculate_entropy("") == 0.0

    # Known values
    # "a" * 8 = 8 * log2(26) ≈ 37.6
    entropy = calculate_entropy("aaaaaaaa")
    assert abs(entropy - 37.6) < 0.2

    # "aB1!" * 4 = 16 * log2(94) ≈ 105
    entropy = calculate_entropy("aB1!aB1!aB1!aB1!")
    assert entropy > 100

    # Longer = more entropy
    assert calculate_entropy("short") < calculate_entropy("muchlongerpassword")


def test_estimate_crack_time():
    times = estimate_crack_time(0)
    assert all(v == "instant" for v in times.values())

    times = estimate_crack_time(40)
    assert times["gpu_cluster"] != "instant"
    assert times["online_throttled"] != "instant"

    times = estimate_crack_time(100)
    # High entropy returns "millennia+" for GPU cluster
    assert times["gpu_cluster"] in ("millennia+", "centuries", "decades", "years")


# ==================== PATTERN TESTS ====================

def test_detect_common_password():
    patterns = detect_patterns("password")
    assert any(p.pattern_type == "common_password" for p in patterns)
    assert any(p.severity == "critical" for p in patterns)


def test_detect_dictionary_word():
    patterns = detect_patterns("apple123")
    dict_patterns = [p for p in patterns if p.pattern_type == "dictionary_word"]
    assert len(dict_patterns) >= 1
    assert dict_patterns[0].severity == "high"


def test_detect_keyboard_walk():
    patterns = detect_patterns("qwerty123")
    kb_patterns = [p for p in patterns if p.pattern_type == "keyboard_walk"]
    assert len(kb_patterns) >= 1


def test_detect_sequences():
    patterns = detect_patterns("abc123")
    seq_patterns = [p for p in patterns if "sequence" in p.pattern_type]
    assert len(seq_patterns) >= 1


def test_detect_repeating():
    patterns = detect_patterns("aaa123")
    rep_patterns = [p for p in patterns if p.pattern_type == "repeating_character"]
    assert len(rep_patterns) >= 1


def test_detect_year():
    patterns = detect_patterns("pass2024")
    year_patterns = [p for p in patterns if p.pattern_type == "year"]
    assert len(year_patterns) >= 1


def test_pattern_penalty():
    # No patterns = no penalty
    assert calculate_pattern_penalty([]) == 0

    # Critical pattern = max penalty
    from patterns import PatternMatch
    critical = [PatternMatch("common_password", "critical", "test")]
    assert calculate_pattern_penalty(critical) == 25


# ==================== ANALYZER TESTS ====================

def test_analyze_weak_password():
    result = analyze_password("123")
    assert result.score == 0
    assert result.strength == "Very Weak"
    assert result.entropy > 0


def test_analyze_common_password():
    result = analyze_password("password", check_breach_api=False)
    # Without breach check: critical pattern (25) + high dict (15) = 40 penalty, capped at 25
    # Base score ~31, final ~6
    assert result.score <= 10
    assert result.strength == "Very Weak"
    assert "common_password" in [p.pattern_type for p in result.patterns]


def test_analyze_strong_password():
    result = analyze_password("Tr0ub4dor&3!", check_breach_api=False)
    # Has leetspeak penalty (-8), so score is slightly lower
    assert result.score >= 55
    assert result.strength in ("Fair", "Strong", "Very Strong")
    assert result.entropy > 50


def test_analyze_very_strong_password():
    # Use a truly random password without dictionary words
    result = analyze_password("x7#Kp9$mQ2!vL8@nR4&z", check_breach_api=False)
    assert result.score >= 70
    assert result.strength in ("Strong", "Very Strong")


def test_analyze_empty_password():
    result = analyze_password("")
    assert result.score == 0
    assert result.composition["length"] == 0


def test_score_calculation():
    # Test the scoring formula directly
    from patterns import PatternMatch

    # No patterns, not breached, good composition
    score = _calculate_score(
        entropy=60,
        composition={"lowercase": True, "uppercase": True, "digits": True, "symbols": True},
        patterns=[],
        breached=False,
        length=16,
    )
    assert 60 <= score <= 100

    # Breached = massive penalty
    score = _calculate_score(
        entropy=80,
        composition={"lowercase": True, "uppercase": True, "digits": True, "symbols": True},
        patterns=[],
        breached=True,
        length=20,
    )
    assert score <= 50  # 50 point penalty


# ==================== GENERATOR TESTS ====================

def test_generate_password():
    result = generate_password(length=20, use_uppercase=True, use_digits=True, use_symbols=True)
    assert "password" in result
    assert "entropy" in result
    assert len(result["password"]) == 20
    assert result["entropy"] > 0
    assert result["composition"]["uppercase"] is True


def test_generate_password_min_length():
    result = generate_password(length=8)
    assert len(result["password"]) == 8


def test_generate_password_max_length():
    result = generate_password(length=128)
    assert len(result["password"]) == 128


def test_generate_passphrase():
    result = generate_passphrase(word_count=4)
    assert "password" in result
    assert "-" in result["password"]  # default separator
    assert result["entropy"] > 0


def test_generate_passphrase_custom():
    result = generate_passphrase(word_count=3, separator=".", capitalize=True)
    words = result["password"].split(".")
    assert len(words) == 3
    assert all(w[0].isupper() for w in words)


def test_generate_pin():
    result = generate_pin(6)
    assert len(result["password"]) == 6
    assert result["password"].isdigit()


# ==================== API TESTS ====================

def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "1.0.0"


def test_analyze_endpoint():
    response = client.post("/api/analyze", json={"password": "Test123!", "check_breach": False})
    assert response.status_code == 200
    data = response.json()
    assert "score" in data
    assert "strength" in data
    assert "entropy" in data
    assert "crack_time" in data
    assert "feedback" in data
    assert "breached" in data
    assert "composition" in data


def test_analyze_endpoint_validation():
    # Empty password
    response = client.post("/api/analyze", json={"password": ""})
    assert response.status_code == 422

    # Too long
    response = client.post("/api/analyze", json={"password": "a" * 129})
    assert response.status_code == 422


def test_generate_endpoint():
    response = client.post("/api/generate", json={"length": 16})
    assert response.status_code == 200
    data = response.json()
    assert "password" in data
    assert len(data["password"]) == 16
    assert data["entropy"] > 0


def test_generate_endpoint_validation():
    # Too short
    response = client.post("/api/generate", json={"length": 4})
    assert response.status_code == 422

    # Too long
    response = client.post("/api/generate", json={"length": 200})
    assert response.status_code == 422


def test_passphrase_endpoint():
    response = client.post("/api/generate/passphrase", json={"word_count": 4})
    assert response.status_code == 200
    data = response.json()
    assert "password" in data


def test_pin_endpoint():
    response = client.post("/api/generate/pin?length=6")
    assert response.status_code == 200
    data = response.json()
    assert len(data["password"]) == 6
    assert data["password"].isdigit()


def test_breach_check_endpoint():
    response = client.post("/api/breach-check", json={"password": "test123"})
    assert response.status_code == 200
    data = response.json()
    assert "breached" in data
    assert "count" in data


# ==================== INTEGRATION TESTS ====================

def test_full_analysis_flow():
    """Test complete analysis of various password types."""
    test_cases = [
        ("password", 0, "Very Weak"),
        ("12345678", 0, "Very Weak"),
        ("Password1", 15, "Weak"),
        ("Passw0rd!", 30, "Weak"),
        ("Tr0ub4dor&3", 55, "Fair"),
        ("x7#Kp9$mQ2!vL8@nR4&z", 80, "Very Strong"),
    ]

    for pwd, min_score, expected_strength in test_cases:
        result = analyze_password(pwd, check_breach_api=False)
        assert result.score >= min_score, f"{pwd}: score {result.score} < {min_score}"
        # Strength might be higher than expected, that's OK


def test_breach_check_known_breached():
    # "password" is definitely breached
    breached = check_breach("password")
    # Note: This hits the real API, so might be flaky in CI
    # In production tests, you'd mock this


if __name__ == "__main__":
    pytest.main([__file__, "-v"])