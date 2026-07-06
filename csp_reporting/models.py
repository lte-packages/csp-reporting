from urllib.parse import urlparse

from django.db import models


class CSPReport(models.Model):
    received_at = models.DateTimeField(auto_now_add=True)
    raw_report = models.JSONField()
    blocked_uri = models.TextField(
        blank=True,
        null=True,
    )
    document_uri = models.TextField(
        blank=True,
        null=True,
    )
    violated_directive = models.TextField(
        blank=True,
        null=True,
    )

    class Meta:
        verbose_name = "CSP Report"
        verbose_name_plural = "Reports"

    def __str__(self):
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

    @property
    def category(self):
        """
        Dynamically categorize the CSP violation based on its blocked URI.

        Returns:
            str: Category of the violation
                'network_filter': Known corporate/ISP security tools
                'suspicious': Possible malware or browser extensions
                'legitimate': Actual violation from application
                'unknown': Needs manual review
        """
        from .filters import categorize_violation

        return categorize_violation(self.blocked_uri, self.document_uri)
