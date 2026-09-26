"""
Pytest configuration for Django project.

Configures Django settings and provides fixtures for pytest.
Use: pytest tests/
"""

import sys
from pathlib import Path

import django
from django.conf import settings

# Add project root to path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


def pytest_configure():
    """Configure Django settings for pytest."""
    if not settings.configured:
        settings.configure(
            DEBUG=True,
            DATABASES={
                "default": {
                    "ENGINE": "django.db.backends.sqlite3",
                    "NAME": ":memory:",
                }
            },
            INSTALLED_APPS=[
                "django.contrib.auth",
                "django.contrib.contenttypes",
                "django.contrib.sessions",
                "django.contrib.messages",
                "csp_reporting",
            ],
            MIDDLEWARE=[
                "django.middleware.security.SecurityMiddleware",
                "django.contrib.sessions.middleware.SessionMiddleware",
                "django.middleware.common.CommonMiddleware",
                "django.middleware.csrf.CsrfViewMiddleware",
                "django.contrib.auth.middleware.AuthenticationMiddleware",
                "django.contrib.messages.middleware.MessageMiddleware",
            ],
            SECRET_KEY="test-secret-key-for-testing-only",
            USE_TZ=True,
            ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"],
            # CSP Reporting settings
            CSP_REPORT_ALLOWED_ORIGINS=["http://testserver", "https://testserver"],
            CSP_REPORT_MAX_SIZE=5000,
            CSP_REPORT_RATE_LIMIT_ENABLED=False,
            CSP_REPORT_RATE_LIMIT_REQUESTS=10,
            CSP_REPORT_RATE_LIMIT_WINDOW=3600,
            CACHES={
                "default": {
                    "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                    "LOCATION": "unique-snowflake",
                }
            },
            LOGGING={
                "version": 1,
                "disable_existing_loggers": False,
                "handlers": {
                    "console": {
                        "class": "logging.StreamHandler",
                    },
                },
                "root": {
                    "handlers": ["console"],
                    "level": "WARNING",
                },
            },
        )
        django.setup()
