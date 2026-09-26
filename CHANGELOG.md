# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Type hints throughout the codebase for improved IDE support and type safety
- Database indexes on frequently queried fields (`received_at`, `violated_directive`, `blocked_uri`)
- `CSPReportManager` with utility methods for common queries (`recent_violations()`, `by_directive()`)
- Comprehensive test suite including rate limiting tests with different IP addresses
- GitHub Actions CI/CD pipeline for automated testing across Python 3.10-3.12 and Django 4.2-5.0
- Added `coverage` target to Makefile for test coverage reports
- Added `build` target to Makefile for package distribution
- Project URLs to pyproject.toml (Homepage, Repository, Issues, Changelog)
- Classifiers to pyproject.toml for better package discovery
- Enhanced docstrings following Google-style format
- Development dependency `pytest-django` and `pytest-cov` for improved testing

### Changed
- Updated installation instructions in README to use `@main` instead of `@0.2.2`
- Improved Middleware documentation with separate sections for `CSPMiddleware` and `RateLimitedCSPMiddleware`
- Refactored magic numbers into named constants: `DEFAULT_MAX_REPORT_SIZE`, `MAX_STRING_FIELD_LENGTH`, `MAX_UNKNOWN_CSP_FIELDS`
- Enhanced `.pre-commit-config.yaml` with proper configuration size limits
- Improved code formatting and removed code duplication in admin

### Fixed
- Fixed duplicate `document_uri` entry in admin `search_fields`
- Corrected import statements in middleware to avoid circular imports
- Ensured all type hints are Python 3.10+ compatible

### Security
- No security changes in this release

## [0.3.6] - 2024-Q3

### Added
- Rate limiting functionality for CSP report endpoints
- Origin validation with configurable allowed origins
- Report size limit validation (100KB default)
- Input sanitization for CSP reports
- Django admin interface with report filtering and search
- Comprehensive security tests

### Changed
- Improved error handling and logging
- Enhanced report validation to prevent malicious payloads

### Security
- Added origin validation to prevent unauthorized reports
- Implemented rate limiting to prevent abuse
- Added input sanitization to prevent injection attacks

## [0.2.2] - Earlier

### Notes
Earlier versions had basic CSP report collection without the security hardening present in 0.3.6+.
