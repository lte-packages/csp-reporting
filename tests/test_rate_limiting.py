import json

from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings

from csp_reporting.models import CSPReport
from csp_reporting.views import csp_report_view


class CSPReportRateLimitTests(TestCase):
    """Tests for CSP report rate limiting."""

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
            self.assertEqual(response.status_code, 201, f"Request {i + 1} failed")

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
            self.assertEqual(
                response.status_code, 201, f"Request {i + 1} should succeed"
            )

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
            self.assertEqual(
                response.status_code, 201, f"Request {i + 1} should succeed"
            )

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
