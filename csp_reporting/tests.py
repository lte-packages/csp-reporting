import json

from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings

from .models import CSPReport
from .views import (
    csp_report_view,
    sanitize_csp_report,
    validate_csp_report_structure,
    validate_origin,
)


class CSPReportSecurityTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.valid_csp_report = {
            "csp-report": {
                "document-uri": "https://example.com/page",
                "referrer": "https://example.com/",
                "violated-directive": "script-src 'self'",
                "effective-directive": "script-src",
                "original-policy": "script-src 'self'; report-uri /csp/",
                "blocked-uri": "https://evil.com/malicious.js",
                "status-code": 200,
            }
        }

    def test_validate_origin_with_matching_referer(self):
        """Test that requests with matching referer are allowed"""
        request = self.factory.post(
            "/csp/",
            HTTP_REFERER="http://testserver/page",
        )
        self.assertTrue(validate_origin(request))

    def test_validate_origin_without_referer(self):
        """Test that requests without referer are rejected"""
        request = self.factory.post("/csp/")
        self.assertFalse(validate_origin(request))

    @override_settings(CSP_REPORT_ALLOWED_ORIGINS=["https://example.com"])
    def test_validate_origin_with_allowed_origins(self):
        """Test that configured allowed origins work"""
        request = self.factory.post(
            "/csp/",
            HTTP_REFERER="https://example.com/page",
        )
        self.assertTrue(validate_origin(request))

        # Test disallowed origin
        request = self.factory.post(
            "/csp/",
            HTTP_REFERER="https://evil.com/page",
        )
        self.assertFalse(validate_origin(request))

    def test_validate_csp_report_structure_valid(self):
        """Test that valid CSP reports are accepted"""
        report = {
            "document-uri": "https://example.com",
            "violated-directive": "script-src",
            "blocked-uri": "https://evil.com",
        }
        self.assertTrue(validate_csp_report_structure(report))

    def test_validate_csp_report_structure_missing_required_fields(self):
        """Test that reports missing required fields are rejected"""
        report = {"blocked-uri": "https://evil.com"}
        self.assertFalse(validate_csp_report_structure(report))

    def test_validate_csp_report_structure_too_many_unknown_fields(self):
        """Test that reports with too many unknown fields are rejected"""
        report = {
            "document-uri": "https://example.com",
            "violated-directive": "script-src",
            "fake-field-1": "value",
            "fake-field-2": "value",
            "fake-field-3": "value",
            "fake-field-4": "value",
            "fake-field-5": "value",
        }
        self.assertFalse(validate_csp_report_structure(report))

    def test_sanitize_csp_report(self):
        """Test that CSP reports are properly sanitized"""
        report = {
            "document-uri": "https://example.com/" + "x" * 3000,  # Too long
            "violated-directive": "script-src 'self'",
            "line-number": 42,
            "malicious-field": "should be ignored",
        }
        sanitized = sanitize_csp_report(report)

        # Check length limit
        self.assertLessEqual(len(sanitized.get("document-uri", "")), 2048)

        # Check that valid fields are preserved
        self.assertEqual(sanitized["violated-directive"], "script-src 'self'")
        self.assertEqual(sanitized["line-number"], 42)

        # Check that unknown fields are not included
        self.assertNotIn("malicious-field", sanitized)

    def test_csp_report_view_valid_request(self):
        """Test that valid CSP reports are accepted and stored"""
        request = self.factory.post(
            "/csp/",
            data=json.dumps(self.valid_csp_report),
            content_type="application/json",
            HTTP_REFERER="http://testserver/",
        )

        response = csp_report_view(request)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(CSPReport.objects.count(), 1)

        report = CSPReport.objects.first()
        self.assertEqual(report.blocked_uri, "https://evil.com/malicious.js")
        self.assertEqual(report.violated_directive, "script-src 'self'")

    def test_csp_report_view_no_referer(self):
        """Test that reports without referer are rejected"""
        request = self.factory.post(
            "/csp/",
            data=json.dumps(self.valid_csp_report),
            content_type="application/json",
        )

        response = csp_report_view(request)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(CSPReport.objects.count(), 0)

    def test_csp_report_view_invalid_json(self):
        """Test that invalid JSON is rejected"""
        request = self.factory.post(
            "/csp/",
            data="not valid json",
            content_type="application/json",
            HTTP_REFERER="http://testserver/",
        )

        response = csp_report_view(request)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(CSPReport.objects.count(), 0)

    def test_csp_report_view_invalid_structure(self):
        """Test that reports with invalid structure are rejected"""
        invalid_report = {"csp-report": {"only-one-field": "value"}}
        request = self.factory.post(
            "/csp/",
            data=json.dumps(invalid_report),
            content_type="application/json",
            HTTP_REFERER="http://testserver/",
        )

        response = csp_report_view(request)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(CSPReport.objects.count(), 0)

    @override_settings(CSP_REPORT_MAX_SIZE=100)
    def test_csp_report_view_too_large(self):
        """Test that oversized reports are rejected"""
        large_report = {
            "csp-report": {
                "document-uri": "x" * 1000,
                "violated-directive": "script-src",
            }
        }
        data = json.dumps(large_report)
        # Create request and set CONTENT_LENGTH to exceed limit
        request = self.factory.post(
            "/csp/",
            data=data,
            content_type="application/json",
            HTTP_REFERER="http://testserver/",
        )
        # Manually set CONTENT_LENGTH in META to test size validation
        request.META["CONTENT_LENGTH"] = "150"  # Exceeds MAX_REPORT_SIZE of 100

        response = csp_report_view(request)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(CSPReport.objects.count(), 0)


class CSPReportRateLimitTests(TestCase):
    def setUp(self):
        # Clear cache before each test to avoid interference
        cache.clear()

        self.factory = RequestFactory()
        self.valid_csp_report = {
            "csp-report": {
                "document-uri": "https://example.com/page",
                "referrer": "https://example.com/",
                "violated-directive": "script-src 'self'",
                "effective-directive": "script-src",
                "original-policy": "script-src 'self'; report-uri /csp/",
                "blocked-uri": "https://evil.com/malicious.js",
                "status-code": 200,
            }
        }

    def tearDown(self):
        # Clear cache after each test
        cache.clear()

    @override_settings(
        CSP_REPORT_RATE_LIMIT_ENABLED=True,
        CSP_REPORT_RATE_LIMIT_REQUESTS=5,
        CSP_REPORT_RATE_LIMIT_WINDOW=60,
    )
    def test_rate_limit_allows_requests_under_limit(self):
        """Test that requests under the rate limit are allowed"""
        for i in range(5):
            request = self.factory.post(
                "/csp/",
                data=json.dumps(self.valid_csp_report),
                content_type="application/json",
                HTTP_REFERER="http://testserver/",
                REMOTE_ADDR="192.168.1.100",
            )
            response = csp_report_view(request)
            self.assertEqual(response.status_code, 201, f"Request {i+1} failed")

        self.assertEqual(CSPReport.objects.count(), 5)

    @override_settings(
        CSP_REPORT_RATE_LIMIT_ENABLED=True,
        CSP_REPORT_RATE_LIMIT_REQUESTS=3,
        CSP_REPORT_RATE_LIMIT_WINDOW=60,
    )
    def test_rate_limit_blocks_requests_over_limit(self):
        """Test that requests over the rate limit are blocked"""
        # Send 3 requests (at the limit)
        for i in range(3):
            request = self.factory.post(
                "/csp/",
                data=json.dumps(self.valid_csp_report),
                content_type="application/json",
                HTTP_REFERER="http://testserver/",
                REMOTE_ADDR="192.168.1.100",
            )
            response = csp_report_view(request)
            self.assertEqual(response.status_code, 201, f"Request {i+1} should succeed")

        # 4th request should be rate limited
        request = self.factory.post(
            "/csp/",
            data=json.dumps(self.valid_csp_report),
            content_type="application/json",
            HTTP_REFERER="http://testserver/",
            REMOTE_ADDR="192.168.1.100",
        )
        response = csp_report_view(request)

        self.assertEqual(response.status_code, 429)
        self.assertIn("Retry-After", response)
        self.assertEqual(CSPReport.objects.count(), 3)

    @override_settings(
        CSP_REPORT_RATE_LIMIT_ENABLED=True,
        CSP_REPORT_RATE_LIMIT_REQUESTS=2,
        CSP_REPORT_RATE_LIMIT_WINDOW=60,
    )
    def test_rate_limit_per_ip(self):
        """Test that rate limiting is applied per IP address"""
        # Send 2 requests from first IP (at limit)
        for i in range(2):
            request = self.factory.post(
                "/csp/",
                data=json.dumps(self.valid_csp_report),
                content_type="application/json",
                HTTP_REFERER="http://testserver/",
                REMOTE_ADDR="192.168.1.100",
            )
            response = csp_report_view(request)
            self.assertEqual(response.status_code, 201)

        # Third request from first IP should be blocked
        request = self.factory.post(
            "/csp/",
            data=json.dumps(self.valid_csp_report),
            content_type="application/json",
            HTTP_REFERER="http://testserver/",
            REMOTE_ADDR="192.168.1.100",
        )
        response = csp_report_view(request)
        self.assertEqual(response.status_code, 429)

        # Request from different IP should still work
        request = self.factory.post(
            "/csp/",
            data=json.dumps(self.valid_csp_report),
            content_type="application/json",
            HTTP_REFERER="http://testserver/",
            REMOTE_ADDR="192.168.1.200",
        )
        response = csp_report_view(request)
        self.assertEqual(response.status_code, 201)

        self.assertEqual(CSPReport.objects.count(), 3)

    @override_settings(CSP_REPORT_RATE_LIMIT_ENABLED=False)
    def test_rate_limit_can_be_disabled(self):
        """Test that rate limiting can be disabled"""
        # Send many requests with rate limiting disabled
        for i in range(10):
            request = self.factory.post(
                "/csp/",
                data=json.dumps(self.valid_csp_report),
                content_type="application/json",
                HTTP_REFERER="http://testserver/",
                REMOTE_ADDR="192.168.1.100",
            )
            response = csp_report_view(request)
            self.assertEqual(response.status_code, 201, f"Request {i+1} should succeed")

        self.assertEqual(CSPReport.objects.count(), 10)

    @override_settings(
        CSP_REPORT_RATE_LIMIT_ENABLED=True,
        CSP_REPORT_RATE_LIMIT_REQUESTS=2,
        CSP_REPORT_RATE_LIMIT_WINDOW=60,
    )
    def test_rate_limit_with_x_forwarded_for(self):
        """Test that rate limiting works with X-Forwarded-For header"""
        # Send requests with X-Forwarded-For header
        for i in range(2):
            request = self.factory.post(
                "/csp/",
                data=json.dumps(self.valid_csp_report),
                content_type="application/json",
                HTTP_REFERER="http://testserver/",
                HTTP_X_FORWARDED_FOR="10.0.0.50, 10.0.0.1",
            )
            response = csp_report_view(request)
            self.assertEqual(response.status_code, 201)

        # Third request should be blocked
        request = self.factory.post(
            "/csp/",
            data=json.dumps(self.valid_csp_report),
            content_type="application/json",
            HTTP_REFERER="http://testserver/",
            HTTP_X_FORWARDED_FOR="10.0.0.50, 10.0.0.1",
        )
        response = csp_report_view(request)
        self.assertEqual(response.status_code, 429)
