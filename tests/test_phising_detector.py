import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.phishing_detector import check_domain_reputation, detect_phishing


def test_clean_https_url_is_low_risk():
    result = detect_phishing("https://www.example.com")
    assert result["risk_score"] == 0
    assert "Low Risk" in result["risk_level"]


def test_ip_address_url_is_flagged():
    result = detect_phishing("http://192.168.1.100/login")
    assert result["risk_score"] >= 3
    assert any("IP address" in i for i in result["indicators"])


def test_typosquat_detected():
    result = detect_phishing("http://paypa1-secure.com/verify")
    assert any("mimic" in i for i in result["indicators"])


def test_punycode_domain_flagged():
    result = detect_phishing("https://xn--pple-43d.com/account")
    assert any("punycode" in i.lower() for i in result["indicators"])


def test_at_symbol_obfuscation_flagged():
    result = detect_phishing("https://example.com@malicious.test/login")
    assert any("@" in i for i in result["indicators"])


def test_empty_url_handled_gracefully():
    result = detect_phishing("")
    assert result["risk_level"] == "Invalid"


def test_oversized_url_rejected_without_crash():
    huge_url = "https://example.com/" + ("a" * 3000)
    result = detect_phishing(huge_url)
    assert result["risk_score"] > 0


def test_url_without_scheme_still_analyzed():
    result = detect_phishing("example.com/verify-account-now")
    assert "risk_score" in result


def test_domain_reputation_shortener():
    result = check_domain_reputation("bit.ly")
    assert result["reputation_score"] < 100
  
