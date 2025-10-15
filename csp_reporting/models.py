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

    def __str__(self):
        return f"{self.blocked_uri} ({self.id}) at {self.received_at}"
