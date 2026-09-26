# Code Review: CSP Reporting Package

## Overview
This is a well-structured Django package for handling Content Security Policy (CSP) reports with good security practices and configuration options. Below are detailed suggestions for improvement across several dimensions.

---

## 1. Code Quality & Architecture

### 1.1 **Import Organization** ✅ Good
- Imports are well-organized and follow PEP 8 standards
- Suggestion: Add type hints to improve IDE support and catch potential bugs early

### 1.2 **Type Annotations** ⚠️ **HIGH PRIORITY**
**Current State:** No type hints used throughout the codebase
**Recommendation:** Add type hints to:
- Function signatures in `views.py`
- Model fields with property methods
- Cache operations in rate limiting logic

**Example improvements:**
```python
# views.py
def validate_origin(request: HttpRequest) -> bool:
    """Validate that the origin or referrer matches allowed origins."""
    ...

def check_rate_limit(request: HttpRequest) -> tuple[bool, int | None]:
    """Check if request exceeds rate limit."""
    ...

def sanitize_csp_report(report: dict) -> dict:
    """Sanitize the CSP report data."""
    ...
```

### 1.3 **Magic Numbers** ⚠️ **MEDIUM PRIORITY**
**Current State:** Several magic numbers scattered in code
**Found:**
- `3` in `validate_csp_report_structure` (allowed unknown fields)
- `2048` in `sanitize_string_field` (max field length)
- `100` and `3600` as rate limit defaults
- `100 * 1024` for max report size (100KB)

**Recommendation:** Create constants at module level:
```python
# At the top of views.py
MAX_UNKNOWN_CSP_FIELDS = 3
MAX_STRING_FIELD_LENGTH = 2048
```

### 1.4 **Code Duplication** ⚠️ **LOW PRIORITY**
**Found:** `search_fields` in `admin.py` has `"document_uri"` listed twice
```python
search_fields = (
    "blocked_uri",
    "document_uri",
    "document_uri",  # <-- Duplicate
    "violated_directive",
    "id",
)
```

---

## 2. Security Review

### 2.1 **Current Security Strengths** ✅
- Origin validation implemented correctly (checks both Origin and Referer headers)
- Rate limiting with privacy-preserving IP hashing using Django Signer
- Input sanitization with length limits
- Report size validation
- CSRF exemption properly documented
- Secure error handling (no sensitive data leakage)

### 2.2 **Potential Security Improvements**

#### 2.2.1 **Cache Key Timeout** ⚠️ **MEDIUM PRIORITY**
**Issue:** In `get_cache_key()`, the IP hash uses `Signer.signature()` which includes a timestamp
**Recommendation:** Document this behavior or use a consistent salt without timestamp component

#### 2.2.2 **Logging Sensitivity** ✅ Good
- Rate limit warnings log request count but not raw IP addresses (good privacy practice)
- Consider: Add optional verbose logging flag for debugging

#### 2.2.3 **Missing HTTPS Check** ⚠️ **LOW PRIORITY**
**Suggestion:** Consider warning in logs if CSP reports received over HTTP in production:
```python
if not request.is_secure() and not DEBUG:
    logger.warning("CSP report received over HTTP (not HTTPS)")
```

---

## 3. Testing

### 3.1 **Current Test Coverage** ⚠️ **INCOMPLETE**
**Found Tests:**
- ✅ Origin validation tests
- ✅ Report structure validation tests
- ✅ Sanitization tests
- ❌ Missing: Rate limiting tests
- ❌ Missing: View response tests (actual CSPReport creation)
- ❌ Missing: Malformed JSON handling
- ❌ Missing: Large payload rejection
- ❌ Missing: Middleware tests

### 3.2 **Recommended Test Additions**
```python
# Missing tests to add:
- test_rate_limit_allows_within_threshold
- test_rate_limit_blocks_exceeding_threshold
- test_csp_report_view_creates_report_correctly
- test_csp_report_view_with_oversized_payload
- test_malformed_json_response
- test_middleware_bypasses_csp_for_staff
- test_middleware_applies_csp_for_regular_users
- test_cache_key_privacy
```

### 3.3 **Test Configuration** ⚠️ **MEDIUM PRIORITY**
**Suggestion:** Create a `conftest.py` fixture at package level for common test setup:
```python
# csp_reporting/conftest.py
import pytest
from django.test import RequestFactory

@pytest.fixture
def factory():
    return RequestFactory()

@pytest.fixture
def valid_csp_report():
    return {
        "csp-report": {
            "document-uri": "https://example.com/page",
            "violated-directive": "script-src 'self'",
            "blocked-uri": "https://evil.com/malicious.js",
        }
    }
```

---

## 4. Documentation

### 4.1 **README.md** ⚠️ **MEDIUM PRIORITY**
**Current Issues:**
1. Installation URL references version `@0.2.2` but `pyproject.toml` shows `0.3.6`
   - **Fix:** Update to current version or use `@latest` or just branch name
2. "Rate Limiting" section appears incomplete (text cuts off)
3. Missing: Middleware configuration example for `RateLimitedCSPMiddleware`
4. Missing: Rate limiting configuration documentation
5. Missing: Troubleshooting section

### 4.2 **Docstrings** ⚠️ **MEDIUM PRIORITY**
**Current State:** Most functions have docstrings, but inconsistent format
**Recommendation:** Use Google-style docstrings consistently:
```python
def validate_origin(request):
    """Validate that the origin or referrer matches one of the allowed origins.

    Firefox sends Origin header, Edge sends both Origin and Referer.

    Args:
        request: Django HttpRequest object

    Returns:
        bool: True if origin is valid, False otherwise

    Raises:
        None

    Examples:
        >>> is_valid = validate_origin(request)
    """
```

### 4.3 **Code Comments** ✅ Good
- Complex logic in `validate_origin()` is well-commented
- Rate limiting algorithm is clear
- Sanitization strategy is documented

---

## 5. Development & Deployment

### 5.1 **Makefile** ✅ Good
- Standard targets present
- Help documentation included
- Consistent with Python best practices

**Suggestion:** Add:
```makefile
build: ## Build the package for distribution
	$(PYTHON) -m pip install build
	$(PYTHON) -m build

publish: build ## Publish package to PyPI (requires credentials)
	$(PYTHON) -m twine upload dist/*

coverage: ## Run tests with coverage report
	$(PYTHON) -m pytest csp_reporting/tests.py --cov=csp_reporting --cov-report=html
	@echo "Coverage report: htmlcov/index.html"
```

### 5.2 **Pre-commit Configuration** ⚠️ **MEDIUM PRIORITY**
**Recommendation:** Add `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.1.0
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
        args: ['--maxkb=100']

  - repo: https://github.com/asottile/setup-cfg-fmt
    rev: v2.2.1
    hooks:
      - id: setup-cfg-fmt
```

### 5.3 **GitHub Actions** ⚠️ **HIGH PRIORITY**
**Missing:** CI/CD pipeline for automated testing
**Recommendation:** Create `.github/workflows/ci.yml`:
```yaml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.10', '3.11', '3.12']
        django-version: ['4.2', '5.0']

    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install dependencies
        run: |
          pip install --upgrade pip
          pip install -e ".[dev]"
          pip install Django==${{ matrix.django-version }}
      - name: Lint with ruff
        run: make lint
      - name: Format check
        run: python -m ruff format --check .
      - name: Run tests
        run: make test
```

---

## 6. Configuration & Settings

### 6.1 **Settings Documentation** ✅ Good
- `CSP_REPORT_ALLOWED_ORIGINS` documented in README
- `CSP_REPORT_MAX_SIZE` documented
- Rate limiting settings documented

### 6.2 **Missing Settings** ⚠️ **LOW PRIORITY**
**Suggestion:** Document optional logging configuration:
```python
# In README.md
CSP_REPORT_DEBUG_LOGGING = False  # Enable verbose logging
CSP_REPORT_STORE_RAW = True       # Store raw report (always true, but document intent)
CSP_REPORT_LOG_SUPPRESSED_REPORTS = False  # Log rate-limited/rejected reports
```

---

## 7. Model Improvements

### 7.1 **CSPReport Model** ✅ Good Structure
**Current strengths:**
- Proper use of `auto_now_add` for timestamps
- Reasonable field choices with null/blank handling

**Suggestions:**
```python
class CSPReport(models.Model):
    # Add helpful improvements:
    received_at = models.DateTimeField(auto_now_add=True, db_index=True)  # Index for queries
    raw_report = models.JSONField()
    blocked_uri = models.TextField(blank=True, null=True, db_index=True)  # Index for filtering
    document_uri = models.TextField(blank=True, null=True)
    violated_directive = models.TextField(blank=True, null=True, db_index=True)

    # Add new fields:
    ip_hash = models.CharField(max_length=64, blank=True)  # For analytics
    user_agent = models.TextField(blank=True)  # Useful for debugging

    class Meta:
        verbose_name = "CSP Report"
        verbose_name_plural = "Reports"
        ordering = ["-received_at"]
        # Add index for common query patterns:
        indexes = [
            models.Index(fields=["-received_at"]),
            models.Index(fields=["violated_directive", "-received_at"]),
        ]
```

---

## 8. Error Handling

### 8.1 **Exception Handling** ✅ Good
- Proper logging of errors with `exc_info=True`
- Graceful response codes (400, 403, 429)
- No sensitive data in error messages

### 8.2 **Suggestion:** Add specific exception types
```python
class CSPReportError(Exception):
    """Base exception for CSP reporting."""
    pass

class InvalidCSPReport(CSPReportError):
    """Raised when CSP report validation fails."""
    pass

class RateLimitExceeded(CSPReportError):
    """Raised when rate limit is exceeded."""
    pass
```

---

## 9. Performance Considerations

### 9.1 **Database Queries** ⚠️ **MEDIUM PRIORITY**
**Suggestion:** Add model manager for common queries:
```python
class CSPReportManager(models.Manager):
    def recent_violations(self, hours=24):
        from datetime import timedelta
        from django.utils import timezone
        cutoff = timezone.now() - timedelta(hours=hours)
        return self.filter(received_at__gte=cutoff)

    def by_directive(self, directive):
        return self.filter(violated_directive__icontains=directive)

class CSPReport(models.Model):
    # ...
    objects = CSPReportManager()
```

### 9.2 **Caching Strategy** ✅ Good
- Rate limiting uses cache efficiently
- Consider: Document cache backend requirements (Redis recommended for production)

### 9.3 **Query Optimization** ✅ Good
- Admin uses `list_filter` and `search_fields` appropriately
- Consider: Add `select_related` or `prefetch_related` if adding FK relationships

---

## 10. Package Metadata & Publishing

### 10.1 **pyproject.toml** ⚠️ **MEDIUM PRIORITY**
**Improvements:**
```toml
[project]
name = "csp-reporting"
version = "0.3.6"
description = "Reporting package for django-csp."
readme = "README.md"
requires-python = ">=3.10"
license-files = ["LICENSE"]

# Add:
authors = [
    { name="horrocksm", email="mikeh_74_@outlook.com" }
]
keywords = ["django", "csp", "security", "reporting"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Environment :: Web Environment",
    "Framework :: Django",
    "Framework :: Django :: 4.2",
    "Framework :: Django :: 5.0",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Programming Language :: Python",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security",
    "Topic :: Internet :: WWW/HTTP",
]

# Add repository info:
[project.urls]
Homepage = "https://github.com/lte-packages/csp-reporting"
Repository = "https://github.com/lte-packages/csp-reporting.git"
Issues = "https://github.com/lte-packages/csp-reporting/issues"
Changelog = "https://github.com/lte-packages/csp-reporting/releases"

# Add optional testing dependencies:
[project.optional-dependencies]
dev = [
    "ruff>=0.1.0",
    "pytest>=7.0",
    "pytest-django>=4.5",
    "pytest-cov>=4.0",
    "pre-commit>=3.0",
    "build>=0.10.0",
]
```

### 10.2 **Missing Files** ⚠️ **MEDIUM PRIORITY**
- ✅ README.md - Present
- ✅ LICENSE - Present
- ✅ CONTRIBUTING.md - Present
- ❌ CHANGELOG.md - Missing
- ❌ .gitignore - Consider verifying completeness

---

## Summary of Priority Improvements

### 🔴 HIGH PRIORITY
1. Add type hints throughout codebase
2. Add GitHub Actions CI/CD pipeline
3. Complete test coverage (rate limiting, views, middleware)
4. Update README installation URL to match current version

### 🟡 MEDIUM PRIORITY
1. Add constants for magic numbers
2. Add database indexes to model
3. Add `.pre-commit-config.yaml`
4. Complete missing tests
5. Update pyproject.toml with classifiers and URLs
6. Create CHANGELOG.md
7. Fix duplicate in admin search_fields
8. Add performance optimization (model manager)

### 🟢 LOW PRIORITY
1. Add HTTPS check warning for development
2. Create custom exception classes
3. Enhance error logging verbosity control
4. Add coverage target to Makefile

---

## Estimated Time to Implement

- High Priority: ~4-6 hours
- Medium Priority: ~6-8 hours
- Low Priority: ~2-3 hours
- **Total: ~12-17 hours**

---

## Next Steps

1. Start with type hints (enables better IDE support immediately)
2. Add missing tests (improves code confidence)
3. Set up CI/CD (catches issues before merge)
4. Update documentation (helps users)
5. Optimize database queries (improves performance)

---

**Overall Assessment:** This is a well-built security-focused package with good fundamentals. The main gaps are in testing coverage, type hints, and CI/CD automation rather than fundamental architectural issues.
