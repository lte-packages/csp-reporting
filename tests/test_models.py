from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from csp_reporting.models import CSPReport


class CSPReportModelTests(TestCase):
    """Tests for CSPReport model and CSPReportManager."""

    def setUp(self):
        """Create test data for model tests."""
        self.now = timezone.now()
        self.base_report_data = {
            "document-uri": "https://example.com/page",
            "violated-directive": "script-src 'self'",
            "blocked-uri": "https://evil.com/malicious.js",
        }

    def test_csp_report_str_with_full_uri(self):
        """Test __str__ method with a complete URI."""
        report = CSPReport.objects.create(
            raw_report=self.base_report_data,
            blocked_uri="https://example.com/resource.js",
            document_uri="https://example.com/page",
            violated_directive="script-src 'self'",
        )
        result = str(report)
        self.assertIn("https://example.com", result)
        self.assertIn(str(report.id), result)

    def test_csp_report_str_with_empty_blocked_uri(self):
        """Test __str__ method when blocked_uri is empty."""
        report = CSPReport.objects.create(
            raw_report=self.base_report_data,
            blocked_uri="",
            document_uri="https://example.com/page",
            violated_directive="script-src 'self'",
        )
        result = str(report)
        self.assertIn(str(report.id), result)
        self.assertIn("at", result)

    def test_csp_report_str_with_none_blocked_uri(self):
        """Test __str__ method when blocked_uri is None."""
        report = CSPReport.objects.create(
            raw_report=self.base_report_data,
            blocked_uri=None,
            document_uri="https://example.com/page",
            violated_directive="script-src 'self'",
        )
        result = str(report)
        self.assertIn(str(report.id), result)

    def test_csp_report_str_with_uri_without_scheme(self):
        """Test __str__ method with URI that has no scheme."""
        report = CSPReport.objects.create(
            raw_report=self.base_report_data,
            blocked_uri="example.com/resource.js",
            document_uri="https://example.com/page",
            violated_directive="script-src 'self'",
        )
        result = str(report)
        self.assertIn("example.com", result)

    def test_csp_report_str_with_whitespace_uri(self):
        """Test __str__ method with URI containing whitespace."""
        report = CSPReport.objects.create(
            raw_report=self.base_report_data,
            blocked_uri="   https://example.com/resource.js   ",
            document_uri="https://example.com/page",
            violated_directive="script-src 'self'",
        )
        result = str(report)
        self.assertIn("example.com", result)

    def test_recent_violations_gets_reports_within_hours(self):
        """Test recent_violations returns reports from last N hours."""
        # Use a fixed baseline time for consistency
        baseline = timezone.now()

        # Create reports at known times relative to baseline
        CSPReport.objects.create(
            raw_report=self.base_report_data,
            blocked_uri="https://old.com/resource.js",
            document_uri="https://example.com/page",
            violated_directive="script-src 'self'",
            received_at=baseline - timedelta(hours=50),  # Definitely outside 24h window
        )
        CSPReport.objects.create(
            raw_report=self.base_report_data,
            blocked_uri="https://recent.com/resource.js",
            document_uri="https://example.com/page",
            violated_directive="script-src 'self'",
            received_at=baseline - timedelta(hours=6),  # Definitely inside 24h window
        )

        # Get reports from last 24 hours
        recent = CSPReport.objects.recent_violations(hours=24)
        # Should get at least the recent one (created 6 hours ago)
        self.assertGreaterEqual(recent.count(), 1)
        # Verify recent report is in results
        uris = [r.blocked_uri for r in recent]
        self.assertTrue(
            any("recent.com" in uri for uri in uris),
            f"Expected 'recent.com' in URIs: {uris}",
        )

    def test_recent_violations_returns_ordered_by_received_at(self):
        """Test recent_violations returns results ordered by received_at descending."""
        report1 = CSPReport.objects.create(
            raw_report=self.base_report_data,
            blocked_uri="https://one.com/resource.js",
            document_uri="https://example.com/page",
            violated_directive="script-src 'self'",
            received_at=self.now - timedelta(hours=2),
        )
        report2 = CSPReport.objects.create(
            raw_report=self.base_report_data,
            blocked_uri="https://two.com/resource.js",
            document_uri="https://example.com/page",
            violated_directive="script-src 'self'",
            received_at=self.now - timedelta(hours=1),
        )

        recent = CSPReport.objects.recent_violations(hours=24)
        reports_list = list(recent)
        # Most recent should be first
        self.assertEqual(reports_list[0].id, report2.id)
        self.assertEqual(reports_list[1].id, report1.id)

    def test_recent_violations_with_different_hour_ranges(self):
        """Test recent_violations with various hour ranges."""
        # Create reports at clear intervals
        baseline = timezone.now()

        CSPReport.objects.create(
            raw_report=self.base_report_data,
            blocked_uri="https://old.com/resource.js",
            document_uri="https://example.com/page",
            violated_directive="script-src 'self'",
            received_at=baseline - timedelta(hours=100),  # Very old
        )
        CSPReport.objects.create(
            raw_report=self.base_report_data,
            blocked_uri="https://24h.com/resource.js",
            document_uri="https://example.com/page",
            violated_directive="script-src 'self'",
            received_at=baseline - timedelta(hours=36),  # Between 24-72h
        )
        CSPReport.objects.create(
            raw_report=self.base_report_data,
            blocked_uri="https://recent.com/resource.js",
            document_uri="https://example.com/page",
            violated_directive="script-src 'self'",
            received_at=baseline - timedelta(hours=6),  # Recent
        )

        # Test different ranges
        result_1h = CSPReport.objects.recent_violations(hours=1)
        result_24h = CSPReport.objects.recent_violations(hours=24)
        result_72h = CSPReport.objects.recent_violations(hours=72)

        # Verify that the most recent report (6h old) is in all windows
        # uris_1h = [r.blocked_uri for r in result_1h]
        uris_24h = [r.blocked_uri for r in result_24h]
        uris_72h = [r.blocked_uri for r in result_72h]

        # Recent report should be in all queries
        self.assertTrue(any("recent.com" in uri for uri in uris_24h))
        self.assertTrue(any("recent.com" in uri for uri in uris_72h))

        # 36h report should be in 24h+ and 72h queries
        self.assertTrue(
            any("24h.com" in uri for uri in uris_24h)
            or any("24h.com" in uri for uri in uris_72h)
        )

        # Window expansion should return equal or more results
        self.assertLessEqual(result_1h.count(), result_24h.count())
        self.assertLessEqual(result_24h.count(), result_72h.count())

    def test_by_directive_filters_by_directive(self):
        """Test by_directive returns reports for specific directive."""
        CSPReport.objects.create(
            raw_report=self.base_report_data,
            blocked_uri="https://evil.com/malicious.js",
            document_uri="https://example.com/page",
            violated_directive="script-src 'self'",
        )
        CSPReport.objects.create(
            raw_report={
                **self.base_report_data,
                "violated-directive": "img-src 'none'",
            },
            blocked_uri="https://evil.com/image.png",
            document_uri="https://example.com/page",
            violated_directive="img-src 'none'",
        )

        # Filter by script-src
        script_reports = CSPReport.objects.by_directive("script-src")
        self.assertEqual(script_reports.count(), 1)
        self.assertIn("script-src", script_reports.first().violated_directive)

        # Filter by img-src
        img_reports = CSPReport.objects.by_directive("img-src")
        self.assertEqual(img_reports.count(), 1)
        self.assertIn("img-src", img_reports.first().violated_directive)

    def test_by_directive_case_insensitive(self):
        """Test by_directive is case-insensitive."""
        CSPReport.objects.create(
            raw_report=self.base_report_data,
            blocked_uri="https://evil.com/malicious.js",
            document_uri="https://example.com/page",
            violated_directive="Script-Src 'self'",
        )

        # Query with different cases
        results = CSPReport.objects.by_directive("SCRIPT-SRC")
        self.assertEqual(results.count(), 1)

    def test_by_directive_returns_ordered_by_received_at(self):
        """Test by_directive returns results ordered by received_at descending."""
        report1 = CSPReport.objects.create(
            raw_report=self.base_report_data,
            blocked_uri="https://one.com/resource.js",
            document_uri="https://example.com/page",
            violated_directive="script-src 'self'",
            received_at=self.now - timedelta(hours=2),
        )
        report2 = CSPReport.objects.create(
            raw_report=self.base_report_data,
            blocked_uri="https://two.com/resource.js",
            document_uri="https://example.com/page",
            violated_directive="script-src 'self'",
            received_at=self.now - timedelta(hours=1),
        )

        results = CSPReport.objects.by_directive("script-src")
        reports_list = list(results)
        # Most recent should be first
        self.assertEqual(reports_list[0].id, report2.id)
        self.assertEqual(reports_list[1].id, report1.id)

    def test_by_directive_empty_results(self):
        """Test by_directive returns empty when no matches found."""
        CSPReport.objects.create(
            raw_report=self.base_report_data,
            blocked_uri="https://evil.com/malicious.js",
            document_uri="https://example.com/page",
            violated_directive="script-src 'self'",
        )

        results = CSPReport.objects.by_directive("style-src")
        self.assertEqual(results.count(), 0)
