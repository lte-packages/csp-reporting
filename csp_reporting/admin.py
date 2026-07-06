import logging
from urllib.parse import urlparse

from django.contrib import admin
from django.db.models import Q
from django.utils.html import format_html

from .filters import KNOWN_NETWORK_FILTERS
from .models import CSPReport

logger = logging.getLogger(__name__)


class DomainFilter(admin.SimpleListFilter):
    """Custom admin filter for document domain (extracted from document_uri)."""

    title = "document domain"
    parameter_name = "domain"

    def lookups(self, request, model_admin):
        """
        Dynamically generate filter options from unique domains in the database.
        Returns up to 50 most common domains to avoid performance issues.
        """
        # Get all unique document URIs (excluding null/empty)
        document_uris = (
            CSPReport.objects.exclude(document_uri__isnull=True)
            .exclude(document_uri="")
            .values_list("document_uri", flat=True)
            .distinct()[:500]  # Limit to avoid memory issues
        )

        # Extract domains
        domains = set()
        for uri in document_uris:
            try:
                parsed = urlparse(uri)
                domain = parsed.netloc or parsed.path.split("/")[0]
                if domain:
                    domains.add(domain)
                    if len(domains) >= 50:  # Limit displayed options
                        break
            except Exception as e:
                logger.debug(f"Failed to parse document_uri: {uri} - {e}")
                continue

        # Sort alphabetically
        return sorted([(domain, domain) for domain in domains])

    def queryset(self, request, queryset):
        """Filter the queryset to match the selected domain."""
        if self.value():
            # Filter for URIs that contain the domain
            # Using icontains to catch http://, https://, and variations
            return queryset.filter(document_uri__icontains=self.value())
        return queryset


class CategoryFilter(admin.SimpleListFilter):
    """Custom admin filter for dynamically computed category field."""

    title = "category"
    parameter_name = "category"

    def lookups(self, request, model_admin):
        """Define the filter options."""
        return [
            ("legitimate", "Legitimate"),
            ("network_filter", "Network Filter"),
            ("suspicious", "Suspicious"),
            ("unknown", "Unknown"),
        ]

    def queryset(self, request, queryset):
        """Filter the queryset based on category logic."""
        if self.value() == "legitimate":
            # Legitimate: empty, null, or special keywords
            return queryset.filter(
                Q(blocked_uri__isnull=True)
                | Q(blocked_uri="")
                | Q(blocked_uri="inline")
                | Q(blocked_uri="eval")
                | Q(blocked_uri="data")
            )

        elif self.value() == "network_filter":
            # Network filters: contains any known filter domain
            q = Q()
            for domain in KNOWN_NETWORK_FILTERS:
                q |= Q(blocked_uri__icontains=domain)
            return queryset.filter(q)

        elif self.value() == "suspicious":
            # Suspicious: matches regex patterns
            # Note: This uses database-level regex which may vary by DB backend
            q = Q()

            # IP with port pattern
            q |= Q(
                blocked_uri__iregex=r"^https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+"
            )

            # Extension patterns
            q |= Q(blocked_uri__istartswith="chrome-extension://")
            q |= Q(blocked_uri__istartswith="moz-extension://")
            q |= Q(blocked_uri__istartswith="safari-extension://")
            q |= Q(blocked_uri__istartswith="ms-browser-extension://")

            # Localhost patterns
            q |= Q(blocked_uri__iregex=r"^https?://localhost:[0-9]{4,5}")
            q |= Q(blocked_uri__iregex=r"^https?://127\.0\.0\.1:[0-9]{4,5}")

            return queryset.filter(q)

        elif self.value() == "unknown":
            # Unknown: everything that doesn't match other categories
            # Exclude legitimate
            legitimate_q = (
                Q(blocked_uri__isnull=True)
                | Q(blocked_uri="")
                | Q(blocked_uri="inline")
                | Q(blocked_uri="eval")
                | Q(blocked_uri="data")
            )

            # Exclude network filters
            network_q = Q()
            for domain in KNOWN_NETWORK_FILTERS:
                network_q |= Q(blocked_uri__icontains=domain)

            # Exclude suspicious
            suspicious_q = Q()
            suspicious_q |= Q(
                blocked_uri__iregex=r"^https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+"
            )
            suspicious_q |= Q(blocked_uri__istartswith="chrome-extension://")
            suspicious_q |= Q(blocked_uri__istartswith="moz-extension://")
            suspicious_q |= Q(blocked_uri__istartswith="safari-extension://")
            suspicious_q |= Q(blocked_uri__istartswith="ms-browser-extension://")
            suspicious_q |= Q(blocked_uri__iregex=r"^https?://localhost:[0-9]{4,5}")
            suspicious_q |= Q(blocked_uri__iregex=r"^https?://127\.0\.0\.1:[0-9]{4,5}")

            return (
                queryset.exclude(legitimate_q).exclude(network_q).exclude(suspicious_q)
            )

        return queryset


@admin.register(CSPReport)
class CSPReportAdmin(admin.ModelAdmin):
    def blocked_uri_short(self, obj):
        value = obj.blocked_uri or ""
        truncated = (value[:40] + "…") if len(value) > 40 else value
        return format_html('<span title="{}">{}</span>', value, truncated)

    blocked_uri_short.admin_order_field = "blocked_uri"
    blocked_uri_short.short_description = "Blocked URI"

    list_display = (
        "blocked_uri_short",
        "violated_directive",
        "category",
        "document_uri",
        "received_at",
    )
    list_filter = (DomainFilter, CategoryFilter, "violated_directive", "received_at")
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
        "document_uri",
        "violated_directive",
        "id",
    )
    ordering = ("-received_at",)
