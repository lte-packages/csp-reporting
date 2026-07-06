# CSP Reporting

This is intended as a companion package for [Django CSP](https://pypi.org/project/django-csp/)

The reporting functionality was removed from that package, and it probably makes
sense to collect these reports on a dedicated monitoring server rather than
taking up bandwidth on production servers for storing this info.

But if you choose to then you can install this package and use it to store
the reports.

## Installation

This package is not published to pypi so install from github:

```
pip install git+https://github.com/lte-packages/csp-reporting.git@0.2.2
```

Then add to your installed apps in your settings:

```
INSTALLED_APPS = [
    'csp',
    'csp_reporting',
]

```

Add to your urls.py:

```
urlpatterns = [
    ...
    path("csp/", include("csp_reporting.urls")),
    ...
]
```

## Middleware

This package also provides custom versions of the middleware provided by the
Django CSP package (https://django-csp.readthedocs.io/en/latest/nonce.html#middleware)
using the version in this package bypasses CSP for logged in staff users.

This can be useful when using Django CMS where the scripts break as it doesn't
support CSP.

```
MIDDLEWARE = [
    ...
    'csp_reporting.middleware.CSPMiddleware,
    ...
]
```

## Security Configuration

The CSP reporting endpoint includes several security measures to validate and sanitize incoming reports:

### Origin Validation

By default, the endpoint validates that reports come from the same origin as your application. You can configure allowed origins in your settings:

```python
# settings.py
CSP_REPORT_ALLOWED_ORIGINS = [
    'https://yourdomain.com',
    'https://www.yourdomain.com',
]
```

If not configured, the endpoint will only accept reports from the same host as the request.

### Report Size Limit

To prevent abuse, reports are limited to 100KB by default. You can customize this:

```python
# settings.py
CSP_REPORT_MAX_SIZE = 50 * 1024  # 50KB
```

### Report Validation

The endpoint validates that incoming data:
- Contains required CSP report fields (`document-uri` and `violated-directive`)
- Follows the CSP report specification structure
- Doesn't contain excessive unknown fields (which could indicate malicious payloads)

### Input Sanitization

All report data is sanitized before being stored:
- String fields are limited to 2048 characters
- Only expected CSP report fields are stored
- Data types are validated and normalized

### Rate Limiting

To prevent server overload, the endpoint includes rate limiting by IP address. By default, it allows 100 requests per hour per IP address.

You can configure rate limiting in your settings:

```python
# settings.py

# Enable or disable rate limiting (enabled by default)
CSP_REPORT_RATE_LIMIT_ENABLED = True

# Maximum number of requests allowed per window
CSP_REPORT_RATE_LIMIT_REQUESTS = 100  # default: 100

# Time window in seconds
CSP_REPORT_RATE_LIMIT_WINDOW = 3600  # default: 3600 (1 hour)
```

When rate limit is exceeded, the endpoint returns a `429 Too Many Requests` status with a `Retry-After` header indicating when the client can retry.

**Note:** Rate limiting requires Django's cache framework to be configured. If you haven't configured caching, add this to your settings:

```python
# settings.py
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
}
```

For production, consider using Redis or Memcached for better performance across multiple server instances.

## CSP Violation Filtering and Categorization

This package includes built-in filtering to separate legitimate CSP violations from noise caused by network security tools, browser extensions, and malware.

### Automatic Categorization

All CSP violations are automatically categorized on-the-fly using a model property. No database migration or additional storage is required - the category is computed dynamically based on the blocked URI.

Categories:

- **legitimate**: Real violations from your application (inline scripts, eval, data URIs, etc.)
- **network_filter**: Violations caused by corporate/ISP security tools (OpenDNS, Zscaler, etc.)
- **suspicious**: Potential malware or browser extensions (IP addresses with ports, extension URIs)
- **unknown**: Violations that need manual review

### Configuration

You can configure the filtering behavior in your settings:

```python
# settings.py

# Enable/disable automatic filtering (default: True)
CSP_REPORT_FILTER_ENABLED = True

# Automatically ignore network filter violations (don't save to DB)
# This can significantly reduce database noise (default: True)
CSP_REPORT_IGNORE_NETWORK_FILTERS = True

# Custom network filter domains (extends built-in list)
CSP_REPORT_CUSTOM_FILTERS = [
    "your-corporate-proxy.com",
    "your-vpn-provider.com",
]

# Custom suspicious patterns (extends built-in list)
CSP_REPORT_CUSTOM_SUSPICIOUS_PATTERNS = [
    r"^https?://your-pattern",
]
```

### Querying by Category

Since categorization is computed on-the-fly, you can access the category as a property. The Django admin includes a custom filter that translates category logic into efficient database queries.

```python
from csp_reporting.models import CSPReport

# Access category for a single report
report = CSPReport.objects.first()
print(report.category)  # 'legitimate', 'network_filter', 'suspicious', or 'unknown'

# Filter in Python (for smaller datasets)
reports = CSPReport.objects.all()
legitimate = [r for r in reports if r.category == 'legitimate']
suspicious = [r for r in reports if r.category == 'suspicious']

# For large datasets, consider filtering by blocked_uri patterns directly
network_filters = CSPReport.objects.filter(
    blocked_uri__icontains='zscaler'
) | CSPReport.objects.filter(
    blocked_uri__icontains='opendns'
)
```

**Django Admin:** The category field is displayed in the list view and is available as a filter option, which uses efficient database queries under the hood.

### Multi-Domain Support

If you're using a single Django instance as the CSP reporting endpoint for multiple domains, the admin interface includes a **Domain Filter** that dynamically extracts domains from the `document_uri` field. This allows you to easily:

- View reports from a specific domain
- Monitor CSP violations across different sites
- Analyze patterns per domain

The filter automatically discovers domains from your reports and displays up to 50 most common domains to choose from.

### Django Signals

The package emits a Django signal for each CSP violation, allowing you to add custom processing:

```python
# your_app/handlers.py
from django.dispatch import receiver
from csp_reporting.signals import csp_violation

@receiver(csp_violation)
def handle_csp_violation(sender, violation, category, report, ignored=False, **kwargs):
    """
    Custom processing for CSP violations

    Args:
        violation (dict): Sanitized CSP report data
        category (str): 'legitimate', 'network_filter', 'suspicious', 'unknown'
        report (CSPReport): CSPReport instance (or None if ignored)
        ignored (bool): True if violation was filtered, False otherwise
    """
    if category == 'suspicious':
        # Alert security team
        send_security_alert(violation)
    elif category == 'legitimate' and not ignored:
        # Log to monitoring system
        log_to_monitoring(violation)
```

Don't forget to connect your signal handler in your app's `apps.py`:

```python
# your_app/apps.py
from django.apps import AppConfig

class YourAppConfig(AppConfig):
    name = 'your_app'

    def ready(self):
        import your_app.handlers  # noqa
```

## License

MIT
