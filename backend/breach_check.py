"""
HaveIBeenPwned breach check integration using k-anonymity model.
Only first 5 chars of SHA-1 hash are sent to the API.
"""
import hashlib
import requests
from typing import Optional
from functools import lru_cache


HIBP_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
REQUEST_TIMEOUT = 10  # seconds


class BreachCheckError(Exception):
    """Exception raised when breach check fails."""
    pass


def check_breach(password: str) -> bool:
    """
    Check if password has been breached using HIBP k-anonymity API.
    Returns True if breached, False otherwise.
    """
    if not password:
        return False

    try:
        # SHA-1 hash the password
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        # Query HIBP API
        response = requests.get(
            HIBP_API_URL.format(prefix=prefix),
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "PasswordStrengthAnalyzer/1.0"}
        )

        if response.status_code == 200:
            # Parse response: each line is "SUFFIX:COUNT"
            for line in response.text.splitlines():
                if ':' in line:
                    hash_suffix, count = line.split(':')
                    if hash_suffix == suffix:
                        return True
            return False
        elif response.status_code == 404:
            # Prefix not found = not breached
            return False
        else:
            raise BreachCheckError(f"HIBP API returned status {response.status_code}")

    except requests.Timeout:
        # On timeout, assume not breached (fail open for UX)
        # In production, you might want to log this
        return False
    except requests.RequestException as e:
        # Network error - fail open
        return False
    except Exception:
        # Any other error - fail open
        return False


def check_breach_with_count(password: str) -> tuple[bool, int]:
    """
    Check breach and return (breached, count).
    Count is number of times seen in breaches (0 if not breached).
    """
    if not password:
        return False, 0

    try:
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        response = requests.get(
            HIBP_API_URL.format(prefix=prefix),
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "PasswordStrengthAnalyzer/1.0"}
        )

        if response.status_code == 200:
            for line in response.text.splitlines():
                if ':' in line:
                    hash_suffix, count = line.split(':')
                    if hash_suffix == suffix:
                        return True, int(count)
            return False, 0
        elif response.status_code == 404:
            return False, 0
        else:
            raise BreachCheckError(f"HIBP API returned status {response.status_code}")

    except (requests.Timeout, requests.RequestException, Exception):
        return False, 0


# Cache for development/testing (avoid hitting API repeatedly)
@lru_cache(maxsize=1000)
def _cached_check_breach(password_hash_prefix: str) -> Optional[dict]:
    """Internal cached check - not used in production."""
    pass  # Placeholder for future caching implementation