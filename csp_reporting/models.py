from datetime import timedelta
from urllib.parse import urlparse

from django.db import models
from django.utils import timezone


class CSPReportManager(models.Manager):
    """Custom manager for CSPReport model with common queries."""

    def recent_violations(self, hours: int = 24) -> models.QuerySet:
        """Get CSP reports from the last N hours.

        Args:
            hours: Number of hours to look back

        Returns:
            QuerySet: Filtered reports
        """
        cutoff = timezone.now() - timedelta(hours=hours)
        return self.filter(received_at__gte=cutoff).order_by("-received_at")

    def by_directive(self, directive: str) -> models.QuerySet:
        """Get CSP reports for a specific violated directive.

        Args:
            directive: The CSP directive (e.g., 'script-src')

        Returns:
            QuerySet: Filtered reports
        """
        return self.filter(violated_directive__icontains=directive).order_by(
            "-received_at"
        )


class CSPReport(models.Model):
    """Model for storing Content Security Policy violation reports."""

    received_at = models.DateTimeField(auto_now_add=True, db_index=True)
    raw_report = models.JSONField()
    blocked_uri = models.TextField(blank=True, null=True, db_index=True)
    document_uri = models.TextField(blank=True, null=True)
    violated_directive = models.TextField(blank=True, null=True, db_index=True)

    objects = CSPReportManager()

    class Meta:
        verbose_name = "CSP Report"
        verbose_name_plural = "Reports"
        ordering = ["-received_at"]  # noqa: RUF012
        indexes = [  # noqa: RUF012
            models.Index(fields=["-received_at"]),
            models.Index(fields=["violated_directive", "-received_at"]),
            models.Index(fields=["blocked_uri", "-received_at"]),
        ]

    def __str__(self) -> str:
        """Return a human-readable string representation of the report."""
        uri = (self.blocked_uri or "").strip()
        if not uri:
            return f"({self.id}) at {self.received_at}"
        parsed = urlparse(uri)
        scheme = parsed.scheme
        netloc = parsed.netloc
        if not netloc:
            parsed = urlparse("//" + uri)
            netloc = parsed.netloc
        host = f"{scheme}://{netloc}" if scheme else netloc
        host = host or uri
        return f"{host} ({self.id}) at {self.received_at}"
