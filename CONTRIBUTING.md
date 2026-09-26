# Contributing to CSP Reporting

Thank you for your interest in contributing to CSP Reporting! This guide will help you get started with development.

## Requirements

Before you begin, ensure you have the following:

- **Python 3.10 or higher** - This project requires Python 3.10+
- **Django 4.2 to 5.x** - Compatible with Django 4.2 through 5.x versions
- **django-csp 4.0+** - The CSP package this reporting tool is designed for

The project uses `pip` for dependency management and a virtual environment for isolation.

## Project Structure

CSP Reporting is organized as a Django application with the following key components:

```
csp_reporting/
├── models.py           # Database models for storing CSP reports
├── views.py            # View handlers for the CSP reporting endpoint
├── urls.py             # URL routing for the CSP report receiver
├── middleware.py       # Custom CSP middleware (bypasses CSP for staff users)
├── admin.py            # Django admin interface for reports
├── apps.py             # Django app configuration
├── migrations/         # Database schema migrations
└── tests.py            # Test suite
```

**Key Models:**
- `CSPReport` - Stores Content Security Policy violation reports received from browsers

**Key Views:**
- CSP report receiver endpoint - Accepts and validates CSP violation reports from browsers

**Middleware:**
- `CSPMiddleware` - Custom implementation that disables CSP for authenticated staff users (useful for Django CMS compatibility)

## Development Setup

This project uses a standard virtual environment at `.venv`. To set up your development environment and install development dependencies:

```bash
# Install development dependencies
make install-dev
```

All development tasks (linting, formatting, testing) use this `.venv` path by default.

## Development Commands

The project includes a Makefile with common development tasks:

```bash
# Run linting checks
make lint

# Format code
make format

# Run tests
make test

# Run pre-commit hooks on changed files
make pre-commit

# Run pre-commit hooks on all files
make pre-commit-all

# Clean up build artifacts
make clean

# Build the package
make build
```

## Code Quality

This project uses:
- **ruff** for linting and formatting
- **pytest** for testing
- **pre-commit** hooks to maintain code quality

Before submitting a pull request, ensure all checks pass:

```bash
make lint
make format
make test
make pre-commit-all
```

## Running Tests

Run the test suite with:

```bash
make test
```

Tests are located in `csp_reporting/tests.py`.

## Code Style & Naming Conventions

This project follows these style conventions, enforced by ruff:

### General Style
- **Line length:** 88 characters maximum
- **Python version:** Code must be compatible with Python 3.10+

### Naming Conventions (PEP 8)
- **Classes:** `PascalCase` (e.g., `CSPReport`, `ReportSerializer`)
- **Functions/methods:** `snake_case` (e.g., `validate_report`, `get_report_count`)
- **Constants:** `UPPER_SNAKE_CASE` (e.g., `MAX_REPORT_SIZE`, `RATE_LIMIT_WINDOW`)
- **Private methods:** Leading underscore (e.g., `_validate_origin`)

### Import Ordering
Imports are automatically sorted by ruff's isort rule:
1. Standard library imports
2. Third-party imports (Django, django-csp)
3. Local application imports

### Security Rules
This project enforces security checks via bandit (ruff's `S` rules):
- No hardcoded passwords in code (OK in test files)
- Careful use of `eval()` and `exec()`
- Proper input validation and sanitization

### Exceptions
- **Tests:** Assert statements and hardcoded test data are permitted in test files
- **Management commands:** Print statements are allowed
- **Migrations:** Non-lowercase variable names are allowed

Run `make format` to automatically fix most style issues:

```bash
make format
```

## Submitting Changes

1. Fork the repository
2. Create a feature branch for your changes
3. Ensure all code quality checks pass locally
4. Submit a pull request with a clear description of your changes

## Questions or Issues?

If you have questions about contributing, please open an issue on the repository.
