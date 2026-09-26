from django.contrib import admin
from django.utils.html import format_html

from .models import CSPReport


@admin.register(CSPReport)
class CSPReportAdmin(admin.ModelAdmin):
    """Admin interface for CSP Report model."""

    def blocked_uri_short(self, obj: CSPReport) -> str:
        """Return a truncated version of blocked_uri with full text on hover.

        Args:
            obj: CSPReport instance

        Returns:
            str: HTML formatted truncated URI
        """
        value = obj.blocked_uri or ""
        truncated = (value[:40] + "…") if len(value) > 40 else value
        return format_html('<span title="{}">{}</span>', value, truncated)

    blocked_uri_short.admin_order_field = "blocked_uri"  # type: ignore
    blocked_uri_short.short_description = "Blocked URI"  # type: ignore

    list_display = (
        "blocked_uri_short",
        "violated_directive",
        "document_uri",
        "received_at",
    )
    list_filter = ("violated_directive", "received_at")
    readonly_fields = (
        "received_at",
        "raw_report",
        "blocked_uri",
        "document_uri",
        "violated_directive",
    )
    search_fields = (
        "blocked_uri",
        "document_uri",
        "violated_directive",
        "id",
    )
    ordering = ("-received_at",)
