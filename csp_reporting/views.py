import json
import logging
import time
from urllib.parse import urlparse

from django.conf import settings
from django.core.cache import cache
from django.core.signing import Signer
from django.http import HttpResponseBadRequest, HttpResponseForbidden, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .models import CSPReport

logger = logging.getLogger(__name__)

# Default maximum size for CSP report (in bytes) - 100KB should be more than enough
DEFAULT_MAX_REPORT_SIZE = 100 * 1024

# Rate limiting defaults
DEFAULT_RATE_LIMIT_REQUESTS = 100  # requests
DEFAULT_RATE_LIMIT_WINDOW = 3600  # seconds (1 hour)

# Expected CSP report fields according to the spec
CSP_REPORT_FIELDS = {
    "document-uri",
    "referrer",
    "blocked-uri",
    "effective-directive",
    "violated-directive",
    "original-policy",
    "disposition",
    "status-code",
    "line-number",
    "column-number",
    "source-file",
    "script-sample",
}


def validate_origin(request):
    """
    Validate that the origin or referrer matches one of the allowed origins.
    Firefox sends Origin header, Edge sends both Origin and Referer.
    Returns True if valid, False otherwise.
    """
    # Try Origin header first (sent by Firefox and Edge)
    origin = request.META.get("HTTP_ORIGIN", "")

    # Fall back to Referer header if Origin is not present
    referer = request.META.get("HTTP_REFERER", "")

    if not origin and not referer:
        logger.warning("CSP report received without origin or referer header")
        return False

    # Get allowed origins from settings, fallback to request origin
    allowed_origins = getattr(settings, "CSP_REPORT_ALLOWED_ORIGINS", None)

    if allowed_origins is None:
        # If not configured, allow reports from the same origin as the request
        request_host = request.get_host()
        allowed_origins = [
            f"https://{request_host}",
            f"http://{request_host}",
        ]

    # Use Origin header if available, otherwise extract origin from Referer
    if origin:
        request_origin = origin.rstrip("/")
    else:
        request_origin = f"{urlparse(referer).scheme}://{urlparse(referer).netloc}"

    for allowed_origin in allowed_origins:
        if request_origin == allowed_origin.rstrip("/"):
            return True

    logger.warning(f"CSP report from unauthorized origin: {request_origin}")
    return False


def get_client_ip(request):
    """
    Get the client IP address from the request.
    Handles X-Forwarded-For header for proxied requests.
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        # Take the first IP in the chain
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


def get_cache_key(request):
    # Get client identifier (IP address) and create a privacy-preserving hash
    client_ip = get_client_ip(request)

    # Use Django's Signer to create a consistent, one-way hash of the IP
    # This prevents storing raw IP addresses in cache while maintaining rate limiting
    signer = Signer(salt="csp_report_rate_limit")
    ip_hash = signer.signature(client_ip)
    return f"csp_report_rate_limit:{ip_hash}"


def check_rate_limit(request):
    """
    Check if the request exceeds the rate limit.
    Returns (is_allowed: bool, retry_after: int or None).
    """
    # Check if rate limiting is enabled
    rate_limit_enabled = getattr(
        settings,
        "CSP_REPORT_RATE_LIMIT_ENABLED",
        True,
    )
    if not rate_limit_enabled:
        return True, None

    # Get rate limit settings
    max_requests = getattr(
        settings,
        "CSP_REPORT_RATE_LIMIT_REQUESTS",
        DEFAULT_RATE_LIMIT_REQUESTS,
    )
    window_seconds = getattr(
        settings,
        "CSP_REPORT_RATE_LIMIT_WINDOW",
        DEFAULT_RATE_LIMIT_WINDOW,
    )

    cache_key = get_cache_key(request)

    # Get current request data from cache
    current_data = cache.get(cache_key)
    current_time = int(time.time())

    if current_data is None:
        # First request from this IP
        cache.set(
            cache_key,
            {"count": 1, "window_start": current_time},
            timeout=window_seconds,
        )
        return True, None

    # Check if we're still in the same window
    time_elapsed = current_time - current_data["window_start"]

    if time_elapsed > window_seconds:
        # Window has expired, start a new one
        cache.set(
            cache_key,
            {"count": 1, "window_start": current_time},
            timeout=window_seconds,
        )
        return True, None

    # We're in the same window, check the count
    if current_data["count"] >= max_requests:
        # Rate limit exceeded
        retry_after = window_seconds - time_elapsed
        logger.warning(
            f"Rate limit exceeded for client: "
            f"{current_data['count']} requests in {time_elapsed}s"
        )
        return False, retry_after

    # Increment the counter
    current_data["count"] += 1
    cache.set(cache_key, current_data, timeout=window_seconds)

    return True, None


def validate_csp_report_structure(report):
    """
    Validate that the report looks like a legitimate CSP report.
    Returns True if valid, False otherwise.
    """
    if not isinstance(report, dict):
        return False

    # Check that we have at least some of the expected CSP fields
    report_keys = set(report.keys())
    # common_fields = report_keys.intersection(CSP_REPORT_FIELDS)

    # At minimum, we should have document-uri and violated-directive
    required_fields = {"document-uri", "violated-directive"}
    if not required_fields.issubset(report_keys):
        logger.warning(f"CSP report missing required fields. Found: {report_keys}")
        return False

    # Check for suspicious extra fields that shouldn't be in a CSP report
    unknown_fields = report_keys - CSP_REPORT_FIELDS
    if len(unknown_fields) > 3:  # Allow a few unknown fields for future spec changes
        logger.warning(f"CSP report has too many unknown fields: {unknown_fields}")
        return False

    return True


def sanitize_string_field(value, max_length=2048):
    """
    Sanitize a string field from the CSP report.
    Limits length and ensures it's a string.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    return value[:max_length]


def sanitize_csp_report(report):
    """
    Sanitize the CSP report data to prevent injection attacks
    and ensure data integrity.
    """
    sanitized = {}

    for key in CSP_REPORT_FIELDS:
        if key in report:
            value = report[key]
            # Sanitize string fields
            if isinstance(value, str):
                sanitized[key] = sanitize_string_field(value)
            # Allow integers for line-number, column-number, status-code
            elif isinstance(value, int) and key in [
                "line-number",
                "column-number",
                "status-code",
            ]:
                sanitized[key] = value
            # For any other type, convert to string and sanitize
            else:
                sanitized[key] = sanitize_string_field(
                    str(value) if value is not None else None
                )

    return sanitized


@csrf_exempt
def csp_report_view(request):
    if request.method == "POST":
        # Check rate limit first (before doing any expensive operations)
        is_allowed, retry_after = check_rate_limit(request)
        if not is_allowed:
            response = JsonResponse(
                {"error": "Rate limit exceeded", "retry_after": retry_after},
                status=429,
            )
            response["Retry-After"] = str(retry_after)
            return response

        # Check request size
        max_report_size = getattr(
            settings, "CSP_REPORT_MAX_SIZE", DEFAULT_MAX_REPORT_SIZE
        )
        content_length = request.META.get("CONTENT_LENGTH")
        if content_length and int(content_length) > max_report_size:
            logger.warning(f"CSP report too large: {content_length} bytes")
            return HttpResponseBadRequest("Report too large")

        # Validate origin
        if not validate_origin(request):
            return HttpResponseForbidden("Invalid origin")

        try:
            # Parse JSON
            data = json.loads(request.body.decode("utf-8"))

            # CSP reports are usually under 'csp-report' key
            report = data.get("csp-report", data)

            # Validate report structure
            if not validate_csp_report_structure(report):
                logger.warning(f"Invalid CSP report structure: {list(report.keys())}")
                return HttpResponseBadRequest("Invalid CSP report structure")

            # Sanitize the report
            sanitized_report = sanitize_csp_report(report)

            # Create the report with sanitized data
            CSPReport.objects.create(
                raw_report=sanitized_report,
                blocked_uri=sanitized_report.get("blocked-uri"),
                document_uri=sanitized_report.get("document-uri"),
                violated_directive=sanitized_report.get("violated-directive"),
            )

            return JsonResponse({"status": "ok"}, status=201)

        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON in CSP report: {e}")
            return HttpResponseBadRequest("Invalid JSON")
        except Exception as e:
            logger.error(f"Error processing CSP report: {e}", exc_info=True)
            return HttpResponseBadRequest("Error processing report")

    return HttpResponseBadRequest("Only POST allowed.")
