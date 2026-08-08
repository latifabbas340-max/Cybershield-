"""
Phishing URL Detector Module
Applies weighted heuristics to flag common phishing indicators in a URL.
This is a rule-based educational detector, not a real-time reputation
or threat-intelligence service.
"""

import re
from typing import Dict, List
from urllib.parse import urlparse

MAX_URL_LENGTH = 2048  # sane upper bound before we refuse to process input

SUSPICIOUS_KEYWORDS = [
    "verify", "confirm", "update", "urgent", "secure", "account",
    "suspended", "locked", "action-required", "action_required",
    "immediate", "unusual-activity", "unusual_activity", "reactivate",
    "validate", "authenticate", "signin", "sign-in", "webscr",
    "billing", "invoice", "payment-declined", "limited-access",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
]

# Typosquat fragments for a short list of heavily-impersonated brands.
# Educational heuristic only — real typosquat detection needs edit-distance
# comparison against a domain allowlist, not substring matching.
BRAND_TYPOSQUATS = {
    "paypal": ["paypa1", "paypai", "paypal-secure", "paypal-verify", "pay-pal"],
    "amazon": ["amazo", "amaz0n", "amazon-secure", "amazon-verify", "amazon-support"],
    "apple": ["apple-id", "apple-secure", "appleid-verify", "icloud-verify"],
    "google": ["goog1e", "googl3", "google-secure", "accounts-google", "gogle"],
    "microsoft": ["micros0ft", "micro-soft", "outlook-secure", "office365-verify"],
    "netflix": ["netfl1x", "netflix-billing", "netflix-account"],
    "bank of america": ["bankofamerica-secure", "boa-verify"],
    "chase": ["chase-secure", "chase-verify", "chaseonline-secure"],
}

STANDARD_PORTS = {80, 443, 8080, 8443}

# Characters that are legitimately common in URLs; anything outside this
# (plus a small unreserved allowance) is flagged as an obfuscation attempt.
_URL_SAFE_CHARS = re.compile(r"^[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%\u00a1-\uffff]*$")


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        # No scheme provided; assume http since that's the riskier default
        # and lets us still flag it as non-HTTPS.
        url = "http://" + url
    return url


def detect_phishing(raw_url: str) -> Dict:
    """
    Analyze a URL for common phishing indicators using weighted heuristics.

    Args:
        raw_url: The URL to analyze (scheme optional).

    Returns:
        Dict with url, risk_level, risk_score, indicators, recommendation,
        and a details breakdown.
    """
    if not isinstance(raw_url, str) or not raw_url.strip():
        return {
            "url": raw_url,
            "risk_level": "Invalid",
            "risk_score": 0,
            "indicators": ["No URL provided"],
            "recommendation": "Enter a URL to analyze.",
            "details": {},
        }

    if len(raw_url) > MAX_URL_LENGTH:
        return {
            "url": raw_url[:100] + "...",
            "risk_level": "Very High Risk \U0001f6d1",
            "risk_score": 10,
            "indicators": ["URL exceeds a reasonable length limit and could not be safely analyzed"],
            "recommendation": "Do not visit this link. Extremely long URLs are a common obfuscation technique.",
            "details": {"url_length": len(raw_url)},
        }

    url = _normalize_url(raw_url)
    url_lower = url.lower()
    indicators: List[str] = []
    risk_score = 0

    try:
        parsed = urlparse(url)
    except ValueError:
        return {
            "url": raw_url,
            "risk_level": "Invalid",
            "risk_score": 0,
            "indicators": ["URL could not be parsed"],
            "recommendation": "Check the URL format and try again.",
            "details": {},
        }

    domain = parsed.hostname or ""

    # ---- CHECK 1: Suspicious keywords (weight 1, counted once) ----
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if matched_keywords:
        shown = ", ".join(f"'{k}'" for k in matched_keywords[:3])
        indicators.append(f"Contains suspicious keyword(s): {shown}")
        risk_score += 1

    # ---- CHECK 2: IP address instead of domain (weight 3) ----
    if domain and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        indicators.append("Uses a raw IP address instead of a domain name")
        risk_score += 3
    elif domain and ":" in domain and re.match(r"^[0-9a-fA-F:]+$", domain):
        indicators.append("Uses a raw IPv6 address instead of a domain name")
        risk_score += 3

    # ---- CHECK 3: Not HTTPS (weight 1) ----
    if parsed.scheme == "http":
        indicators.append("Uses HTTP instead of secure HTTPS")
        risk_score += 1

    # ---- CHECK 4: Unusual/obfuscated characters (weight 1) ----
    if not _URL_SAFE_CHARS.match(url):
        indicators.append("Contains unusual or non-standard characters")
        risk_score += 1

    # ---- CHECK 5: Excessive length (weight 1) ----
    if len(url) > 100:
        indicators.append("URL is unusually long, which is often used to hide malicious content")
        risk_score += 1

    # ---- CHECK 6: Excessive subdomains (weight 2) ----
    if domain:
        # Strip a trailing public-suffix-style ending for a rough subdomain count
        label_count = domain.count(".")
        if label_count >= 4:
            indicators.append("URL has an unusually high number of subdomains (possible subdomain spoofing)")
            risk_score += 2
        elif label_count == 3:
            indicators.append("URL has multiple subdomains")
            risk_score += 1

    # ---- CHECK 7: Punycode / IDN homograph spoofing (weight 3) ----
    if "xn--" in domain:
        indicators.append("Possible internationalized domain spoofing (punycode/IDN attack)")
        risk_score += 3

    # ---- CHECK 8: Non-standard port (weight 1) ----
    if parsed.port and parsed.port not in STANDARD_PORTS:
        indicators.append(f"Uses a non-standard port ({parsed.port})")
        risk_score += 1

    # ---- CHECK 9: Brand typosquatting (weight 3) ----
    for brand, typos in BRAND_TYPOSQUATS.items():
        if any(typo in url_lower for typo in typos):
            indicators.append(f"Domain appears to mimic '{brand}' (possible typosquatting)")
            risk_score += 3
            break

    # ---- CHECK 10: Excessive query parameters (weight 1) ----
    if parsed.query:
        param_count = len([p for p in parsed.query.split("&") if p])
        if param_count > 6:
            indicators.append("URL has an excessive number of query parameters")
            risk_score += 1

    # ---- CHECK 11: '@' in URL before the host (weight 3, classic obfuscation) ----
    if "@" in (parsed.netloc or ""):
        indicators.append("Contains '@' before the host, a technique used to disguise the real destination")
        risk_score += 3

    # ---- CHECK 12: Known URL shortener (weight 1, informational) ----
    if domain and any(domain == s or domain.endswith("." + s) for s in URL_SHORTENERS):
        indicators.append("Uses a URL shortening service, which can hide the true destination")
        risk_score += 1

    # ---- CHECK 13: Hyphens in domain (weight 1, common in fake domains) ----
    if domain and domain.count("-") >= 3:
        indicators.append("Domain contains an unusually high number of hyphens")
        risk_score += 1

    risk_score = min(risk_score, 10)

    if risk_score == 0:
        risk_level = "Low Risk \u2705"
        recommendation = "This link shows no common phishing indicators. Still verify the sender before entering credentials."
    elif risk_score <= 2:
        risk_level = "Medium Risk \u26a0\ufe0f"
        recommendation = "Be cautious with this link. Verify the source before clicking."
    elif risk_score <= 5:
        risk_level = "High Risk \U0001f534"
        recommendation = "This link appears suspicious. Do not enter credentials or personal information."
    else:
        risk_level = "Very High Risk \U0001f6d1"
        recommendation = "This link shows strong phishing characteristics. Do not click it."

    return {
        "url": raw_url,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "indicators": indicators if indicators else ["No obvious phishing indicators detected"],
        "recommendation": recommendation,
        "details": {
            "domain": domain,
            "scheme": parsed.scheme,
            "uses_ip_address": any("IP address" in i for i in indicators),
            "uses_http": parsed.scheme == "http",
            "url_length": len(raw_url),
            "matched_keywords": matched_keywords,
        },
    }


def check_domain_reputation(domain: str) -> Dict:
    """
    Lightweight, pattern-based domain reputation check.
    Not a substitute for a real reputation/threat-intel feed.
    """
    if not isinstance(domain, str) or not domain.strip():
        return {"domain": domain, "reputation_score": 0, "is_safe": False, "warnings": ["No domain provided"]}

    domain = domain.strip().lower()
    reputation_score = 100
    warnings: List[str] = []

    if any(domain == s or domain.endswith("." + s) for s in URL_SHORTENERS):
        reputation_score -= 25
        warnings.append("Domain is a known URL shortener; true destination is hidden")

    if "xn--" in domain:
        reputation_score -= 30
        warnings.append("Domain uses punycode encoding, sometimes used for homograph attacks")

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        reputation_score -= 40
        warnings.append("Domain is a raw IP address")

    reputation_score = max(0, reputation_score)

    return {
        "domain": domain,
        "reputation_score": reputation_score,
        "is_safe": reputation_score > 50,
        "warnings": warnings,
    }


def get_phishing_prevention_tips() -> List[str]:
    """Return phishing prevention tips."""
    return [
        "Hover over links to see the actual URL before clicking",
        "Look for HTTPS and a valid certificate in the browser",
        "Verify sender email address carefully, not just the display name",
        "Be suspicious of urgent requests for personal or financial information",
        "Never click links in unexpected emails or texts",
        "Type important URLs directly into the browser instead of clicking",
        "Check the spelling of domain names carefully",
        "Verify unusual requests through an official contact method",
        "Use two-factor authentication for important accounts",
        "When in doubt, contact the organization directly using a known number",
]
  
