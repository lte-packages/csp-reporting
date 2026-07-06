"""
CSP Violation Filters

Filters CSP violations to separate legitimate issues from network security tools,
browser extensions, and malware.
"""
import re

from django.conf import settings

# Known corporate/ISP network security solutions
KNOWN_NETWORK_FILTERS = [
    "opendns.com",
    "umbrella.com",
    "zscaler.com",
    "zscaler.net",
    "websense.com",
    "forcepoint.com",
    "bluecoat.com",
    "symantec.com",
    "sky.com/error",
    "bt.com/error",
]

# Patterns indicating browser extensions or malware
SUSPICIOUS_PATTERNS = [
    r"^https?://\d+\.\d+\.\d+\.\d+:\d+",  # IP with port
    r"^chrome-extension://",
    r"^moz-extension://",
    r"^safari-extension://",
    r"^ms-browser-extension://",
    r"^https?://localhost:\d{4,5}",
    r"^https?://127\.0\.0\.1:\d{4,5}",
]


def categorize_violation(blocked_uri, document_uri=None):
    """
    Categorize a CSP violation based on its blocked URI.

    Args:
        blocked_uri: The blocked URI from the CSP report
        document_uri: The document URI from the CSP report (optional)

    Returns:
        str: Category of the violation
            'network_filter': Known corporate/ISP security tools (safe to ignore)
            'suspicious': Possible malware or browser extensions
            'legitimate': Actual violation from application
            'unknown': Needs manual review
    """
    if not blocked_uri or blocked_uri in ("inline", "eval", "data"):
        return "legitimate"

    blocked_uri_lower = blocked_uri.lower()

    # Get custom network filters from settings
    custom_filters = getattr(settings, "CSP_REPORT_CUSTOM_FILTERS", [])
    all_filters = KNOWN_NETWORK_FILTERS + custom_filters

    # Check for network filters
    if any(filter_domain in blocked_uri_lower for filter_domain in all_filters):
        return "network_filter"

    # Get custom suspicious patterns from settings
    custom_patterns = getattr(settings, "CSP_REPORT_CUSTOM_SUSPICIOUS_PATTERNS", [])
    all_patterns = SUSPICIOUS_PATTERNS + custom_patterns

    # Check for suspicious patterns
    if any(re.match(pattern, blocked_uri) for pattern in all_patterns):
        return "suspicious"

    # Add your own domain checks here if needed
    # if document_uri and 'yourdomain.com' in blocked_uri:
    #     return 'legitimate'

    return "unknown"


def should_ignore_violation(blocked_uri, document_uri=None):
    """
    Determine if a CSP violation should be ignored based on its category.

    Args:
        blocked_uri: The blocked URI from the CSP report
        document_uri: The document URI from the CSP report (optional)

    Returns:
        bool: True if should ignore, False otherwise
    """
    category = categorize_violation(blocked_uri, document_uri)
    # Only ignore network filters by default
    # Applications can override this behavior via settings
    return category == "network_filter"
