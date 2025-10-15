from csp.contrib.rate_limiting import RateLimitedCSPMiddleware
from csp.middleware import CSPMiddleware


class CustomCSPMiddleware(CSPMiddleware):
    def __call__(self, request):
        user = getattr(request, "user", None)
        if user and user.is_authenticated and user.is_staff:
            # Bypass CSP processing entirely for staff users
            return self.get_response(request)
        # Otherwise, apply CSP as normal
        return super().__call__(request)


class CustomRateLimitedCSPMiddleware(RateLimitedCSPMiddleware):
    def __call__(self, request):
        user = getattr(request, "user", None)
        if user and user.is_authenticated and user.is_staff:
            # Bypass CSP processing entirely for staff users
            return self.get_response(request)
        # Otherwise, apply CSP as normal
        return super().__call__(request)
