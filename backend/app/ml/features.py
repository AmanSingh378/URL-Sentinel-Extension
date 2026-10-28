"""Extract lexical URL features without visiting the submitted URL."""

import ipaddress
import math
from collections import Counter
from urllib.parse import urlsplit


FEATURE_NAMES = [
    "hostname_length",
    "num_dots",
    "num_hyphens",
    "num_ats",
    "num_question_marks",
    "num_equal",
    "num_underscores",
    "num_digits",
    "digit_ratio",
    "num_subdomains",
    "has_ip",
    "http_token_in_host",
    "has_at_symbol",
    "has_punycode",
    "has_port",
    "hostname_entropy",
    "num_percent_symbols",
    "has_suspicious_word",
]

SUSPICIOUS_WORDS = (
    "login", "verify", "verification", "secure", "account",
    "update", "password", "signin", "confirm", "wallet",
    "free", "bonus", "banking", "support",
)


def _entropy(value: str) -> float:
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def extract_url_features(url: str) -> dict[str, float]:
    """Return numeric URL features without making a network request."""

    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower()

    # Normalize www for the selected lexical features.
    feature_hostname = hostname.removeprefix("www.")
    feature_labels = [
        part for part in feature_hostname.split(".") if part
    ]

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    lower_url = url.lower()

    # Digits in a hostname can be a useful lexical signal.
    # Digits in paths and query strings often occur in normal IDs.
    digit_count = sum(character.isdigit() for character in feature_hostname)

    try:
        has_port = int(parsed.port is not None)
    except ValueError:
        has_port = 1

    # Treat an empty path and a single root slash as equivalent.
    path = parsed.path.rstrip("/") or ""
    path_slash_count = path.count("/")

    normalized_length = (
        len(url)
        - (4 if hostname.startswith("www.") else 0)
        - (
            1
            if parsed.path == "/"
            and not parsed.query
            and not parsed.fragment
            else 0
        )
    )

    features = {
        "url_length": normalized_length,
        "hostname_length": len(feature_hostname),
        "path_length": len(path),
        "query_length": len(parsed.query),
        "num_dots": feature_hostname.count("."),
        "num_hyphens": feature_hostname.count("-"),
        "num_ats": url.count("@"),
        "num_question_marks": url.count("?"),
        "num_equal": url.count("="),
        "num_underscores": url.count("_"),
        "num_slashes": path_slash_count,
        "num_digits": digit_count,
        "digit_ratio": digit_count / max(len(feature_hostname), 1),
        "num_subdomains": max(len(feature_labels) - 2, 0),
        "has_ip": has_ip,
        "http_token_in_host": int("http" in feature_hostname),
        "has_at_symbol": int("@" in url),
        "has_punycode": int("xn--" in hostname),
        "has_port": has_port,
        "hostname_entropy": _entropy(feature_hostname),
        "num_percent_symbols": url.count("%"),
        "has_suspicious_word": int(
            any(word in lower_url for word in SUSPICIOUS_WORDS)
        ),
    }

    # Return all calculated features for diagnostics and tests.
    # Training and inference still select the saved 18 FEATURE_NAMES
    # in their original order, preserving model compatibility.
    return {
        name: float(value)
        for name, value in features.items()
    }
