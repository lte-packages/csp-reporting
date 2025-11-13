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

## License

MIT
