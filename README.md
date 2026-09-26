# CSP Reporting

This is intended as a companion package for [Django CSP](https://pypi.org/project/django-csp/)

The reporting functionality was removed from that package, and it probably makes
sense to collect these reports on a dedicated monitoring server rather than
taking up bandwidth on production servers for storing this info.

But if you choose to then you can install this package and use it to store
the reports. This could be as part of a centralized monitoring and alerting
system or simply as part of your existing Django project.

## Installation

This package is not published to PyPI so install from GitHub:

```bash
pip install git+https://github.com/lte-packages/csp-reporting.git@main
```

Then add to your installed apps in your settings:

```python
INSTALLED_APPS = [
    'csp',
    'csp_reporting',
]
```

Add to your urls.py:

```python
from django.urls import path, include

urlpatterns = [
    ...
    path("csp/", include("csp_reporting.urls")),
    ...
]
```

## Middleware

This package provides custom versions of the middleware from the [Django CSP package](https://django-csp.readthedocs.io/en/latest/nonce.html#middleware) with an additional feature: these implementations bypass CSP for logged-in staff users.

This is useful when using Django CMS where scripts break due to CSP restrictions, allowing staff users to edit content without CSP constraints.

### CSPMiddleware

Basic CSP middleware with staff exemption:

```python
MIDDLEWARE = [
    ...
    'csp_reporting.middleware.CSPMiddleware',
    ...
]
```

### RateLimitedCSPMiddleware

CSP middleware with built-in rate limiting and staff exemption:

```python
MIDDLEWARE = [
    ...
    'csp_reporting.middleware.RateLimitedCSPMiddleware',
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
    "https://yourdomain.com",
    "https://www.yourdomain.com",
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
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}
```

For production, consider using Redis or Memcached for better performance across multiple server instances.

## Contributing

To contribute to this project, please see [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

MIT
