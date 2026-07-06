"""
Signals for CSP reporting

Provides Django signals to allow applications to hook into CSP violation processing.
"""
from django.dispatch import Signal

# Signal sent when a CSP violation is received and validated
# Provides:
#   - violation: dict of sanitized CSP report data
#   - category: str ('legitimate', 'network_filter', 'suspicious', 'unknown')
#   - report: CSPReport instance (or None if ignored)
#   - ignored: bool (True if violation was filtered, False otherwise)
csp_violation = Signal()
