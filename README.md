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

## License

MIT
