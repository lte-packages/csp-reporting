from csp.contrib.rate_limiting import (
    RateLimitedCSPMiddleware as _RateLimitedCSPMiddleware,
)
from csp.middleware import CSPMiddleware as _CSPMiddleware
from django.http import HttpRequest, HttpResponse


class CSPMiddleware(_CSPMiddleware):
    """Custom CSP middleware that bypasses CSP for logged in staff users.

    This is useful when using Django CMS where scripts break due to CSP,
    allowing staff users to edit content without CSP restrictions.
    """

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Process the request and response.

        Args:
            request: Django HttpRequest object

        Returns:
            HttpResponse: The response from the middleware or app
        """
        user = getattr(request, "user", None)
        if user and user.is_authenticated and user.is_staff:
            # Bypass CSP processing entirely for staff users
            return self.get_response(request)
        # Otherwise, apply CSP as normal
        return super().__call__(request)


class RateLimitedCSPMiddleware(_RateLimitedCSPMiddleware):
    """Custom Rate-Limited CSP middleware that bypasses CSP for staff users.

    Combines rate limiting with staff user exemption for better control
    over CSP policies in development environments.
    """

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Process the request and response.

        Args:
            request: Django HttpRequest object

        Returns:
            HttpResponse: The response from the middleware or app
        """
        user = getattr(request, "user", None)
        if user and user.is_authenticated and user.is_staff:
            # Bypass CSP processing entirely for staff users
            return self.get_response(request)
        # Otherwise, apply CSP as normal
        return super().__call__(request)
