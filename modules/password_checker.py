"""
Password Strength Analysis Module
Scores password strength using composition rules, entropy estimation,
and a curated list of breached/common passwords. Also estimates a
rough offline brute-force crack time for educational purposes.
"""

import math
import re
from typing import Dict, List

SPECIAL = r"""[!@#$%^&*()_+\-=\[\]{};:'",.<>?/\\|`~]"""

# A larger, still-small sample of the most breached passwords worldwide
# (source pattern: annual "most common passwords" lists). Educational only —
# not a substitute for checking against a real breach corpus (e.g. HIBP).
COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456", "12345678",
    "123456789", "1234567890", "12345", "1234567", "qwerty",
    "qwerty123", "qwertyuiop", "admin", "admin123", "letmein",
    "welcome", "welcome1", "iloveyou", "abc123", "abcd1234",
    "monkey", "dragon", "master", "login", "princess",
    "sunshine", "football", "baseball", "trustno1", "superman",
    "shadow", "michael", "mustang", "starwars", "freedom",
    "whatever", "batman", "hunter2", "passw0rd", "p@ssw0rd",
    "changeme", "default", "guest", "test123", "000000",
    "111111", "123123", "654321", "121212", "1q2w3e4r",
}

# Keyboard-walk patterns beyond simple numeric/alpha sequences
KEYBOARD_WALKS = [
    "qwerty", "asdf", "zxcv", "qazwsx", "1qaz", "2wsx",
    "qweasd", "wasd",
]


def _shannon_entropy_bits(password: str) -> float:
    """Estimate entropy in bits using the character pool actually used."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(SPECIAL, password):
        pool += 32
    if re.search(r"[^\x00-\x7F]", password):  # non-ASCII / unicode
        pool += 100
    pool = max(pool, 1)
    return len(password) * math.log2(pool)


def check_password_strength(password: str) -> Dict:
    """
    Analyze password strength using composition, pattern, and entropy checks.

    Args:
        password: The password to analyze.

    Returns:
        Dict with score, max_score, strength label, percentage, feedback,
        entropy_bits, crack_time estimate, and a details breakdown.
    """
    if not isinstance(password, str):
        password = str(password)

    score = 0
    feedback: List[str] = []

    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(SPECIAL, password))
    has_space = " " in password
    repeated = bool(re.search(r"(.)\1{2,}", password))
    sequential = bool(re.search(
        r"(0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|3210"
        r"|abcd|bcde|cdef|defg|efgh|fghi|ghij)",
        password.lower()
    ))
    keyboard_walk = any(walk in password.lower() for walk in KEYBOARD_WALKS)
    common = password.lower() in COMMON_PASSWORDS
    # Common password with trivial suffix (password1!, admin2024, etc.)
    stripped = re.sub(r"[\d!@#$%^&*]+$", "", password.lower())
    common_variant = (not common) and stripped in COMMON_PASSWORDS and stripped != ""

    # ---- Composition scoring ----
    if length >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters; 12-16+ is much stronger.")

    if length >= 12:
        score += 1
    else:
        feedback.append("Consider a password or passphrase of 12+ characters.")

    if length >= 16:
        score += 1

    if has_lower:
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    if has_upper:
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    if has_digit:
        score += 1
    else:
        feedback.append("Add numbers.")

    if has_special:
        score += 1
    else:
        feedback.append("Add special characters (e.g. ! @ # $ %).")

    # ---- Penalties ----
    if repeated:
        score = max(0, score - 1)
        feedback.append("Avoid repeating the same character three or more times.")

    if sequential:
        score = max(0, score - 1)
        feedback.append("Avoid obvious sequences such as 1234 or abcd.")

    if keyboard_walk:
        score = max(0, score - 1)
        feedback.append("Avoid keyboard patterns such as qwerty or asdf.")

    if common:
        score = 0
        feedback.insert(0, "This is one of the most commonly used passwords in the world. Change it immediately.")
    elif common_variant:
        score = max(0, score - 3)
        feedback.insert(0, "This looks like a common password with a predictable number or symbol added. Attackers try these variants first.")

    score = max(0, min(score, 8))
    percentage = round((score / 8) * 100, 1)

    if score <= 1:
        strength = "Very Weak"
    elif score <= 3:
        strength = "Weak"
    elif score <= 4:
        strength = "Fair"
    elif score <= 5:
        strength = "Strong"
    elif score <= 6:
        strength = "Very Strong"
    else:
        strength = "Excellent"

    if has_space and not feedback:
        feedback.append("Good password structure. Passphrases with spaces are fine and often strong.")

    if not feedback:
        feedback.append("Good password structure. Do not reuse it on other accounts.")

    entropy_bits = round(_shannon_entropy_bits(password), 1) if password else 0.0
    crack = estimate_crack_time(password)

    return {
        "score": score,
        "max_score": 8,
        "strength": strength,
        "percentage": percentage,
        "feedback": feedback,
        "entropy_bits": entropy_bits,
        "crack_time": crack,
        "details": {
            "length": length,
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_numbers": has_digit,
            "has_special_chars": has_special,
            "has_repeated_chars": repeated,
            "has_sequence": sequential,
            "has_keyboard_walk": keyboard_walk,
            "is_common": common,
            "is_common_variant": common_variant,
        },
    }


def estimate_crack_time(password: str) -> Dict:
    """
    Rough educational estimate of offline brute-force crack time.
    Uses a conservative modern GPU-cracking rate as an illustrative
    baseline. This is NOT a precise prediction — real-world crack time
    depends heavily on the hashing algorithm, salting, attacker
    hardware, and whether the password is guessable via a wordlist
    rather than brute force.
    """
    if not password:
        return {
            "estimated_time": "Instant",
            "character_set_size": 0,
            "password_length": 0,
            "model": "Educational estimate only",
        }

    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(SPECIAL, password):
        pool += 32
    if re.search(r"[^\x00-\x7F]", password):
        pool += 100

    pool = max(pool, 10)
    combinations = pool ** len(password)

    # Illustrative offline attack rate against a slow, properly-salted hash
    # (e.g. bcrypt-class). A fast unsalted hash could be many orders of
    # magnitude faster to attack; this deliberately picks a defensible,
    # conservative middle estimate for educational purposes.
    guesses_per_second = 10_000_000_000  # 10 billion/sec, illustrative GPU rate
    seconds = combinations / (2 * guesses_per_second)

    readable = _seconds_to_readable(seconds)

    return {
        "estimated_time": readable,
        "character_set_size": pool,
        "password_length": len(password),
        "model": "Educational brute-force estimate at ~10B guesses/second (illustrative only)",
    }


def _seconds_to_readable(seconds: float) -> str:
    if seconds < 1:
        return "Less than 1 second"
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    if seconds < 31_536_000:
        return f"{seconds / 86400:.1f} days"
    if seconds < 3_153_600_000:
        return f"{seconds / 31_536_000:.1f} years"
    if seconds < 3_153_600_000_000:
        return f"{seconds / 3_153_600_000:.0f} thousand years"
    return "Centuries or more"


def get_password_tips() -> List[str]:
    """Return general password hygiene tips."""
    return [
        "Use a unique password for every account",
        "Prefer a long passphrase (4+ random words) over a short complex string",
        "Use a password manager to generate and store passwords",
        "Enable two-factor authentication wherever it's offered",
        "Never reuse a password that has appeared in a data breach",
        "Avoid using personal info (names, birthdays) in passwords",
      ]
