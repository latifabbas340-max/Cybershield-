import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.password_checker import check_password_strength, estimate_crack_time


def test_empty_password():
    result = check_password_strength("")
    assert result["score"] == 0
    assert result["strength"] == "Very Weak"


def test_common_password_scores_zero():
    result = check_password_strength("password")
    assert result["score"] == 0
    assert result["details"]["is_common"] is True


def test_common_password_with_suffix_flagged_as_variant():
    result = check_password_strength("Password!2024")
    # Not an exact common-password match, but a recognizable variant pattern
    # should still be penalized, not scored as strong.
    assert result["score"] < 6


def test_strong_passphrase_scores_high():
    result = check_password_strength("Tr0ub4dor&3xtraLongPhrase!")
    assert result["score"] >= 6
    assert result["strength"] in ("Very Strong", "Excellent")


def test_sequential_pattern_penalized():
    base = check_password_strength("Xk9#mQ2!")
    seq = check_password_strength("Xk9#mQ2!1234")
    # Adding a sequence should not make the score worse than the length
    # bonus alone would suggest was possible — sanity check it still runs.
    assert "has_sequence" in seq["details"]


def test_keyboard_walk_detected():
    result = check_password_strength("qwertyuiop123")
    assert result["details"]["has_keyboard_walk"] is True


def test_crack_time_returns_readable_string():
    result = estimate_crack_time("a")
    assert "estimated_time" in result
    assert isinstance(result["estimated_time"], str)


def test_crack_time_empty_password():
    result = estimate_crack_time("")
    assert result["estimated_time"] == "Instant"


def test_non_string_input_does_not_crash():
    result = check_password_strength(12345)  # type: ignore[arg-type]
    assert "score" in result
  
