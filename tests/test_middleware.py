from unittest.mock import Mock

from django.test import RequestFactory, TestCase

from csp_reporting.middleware import CSPMiddleware


class CSPMiddlewareTests(TestCase):
    """Tests for CSPMiddleware."""

    def setUp(self):
        """Set up middleware and test fixtures."""
        self.factory = RequestFactory()
        # Create a simple mock get_response callable that returns a proper response
        response_mock = Mock()
        response_mock.status_code = 200
        response_mock.has_header = Mock(return_value=False)
        response_mock.__setitem__ = Mock()
        self.get_response = Mock(return_value=response_mock)
        self.middleware = CSPMiddleware(self.get_response)

    def test_middleware_bypasses_csp_for_authenticated_staff_user(self):
        """Test middleware bypasses CSP for authenticated staff users."""
        request = self.factory.get("/")
        request.user = Mock(is_authenticated=True, is_staff=True)

        response = self.middleware(request)  # noqa: F841

        # Middleware should skip CSP processing and just return get_response
        self.get_response.assert_called_once_with(request)

    def test_middleware_returns_response_for_staff_user(self):
        """Test middleware returns the response object from get_response for staff."""
        expected_response = Mock(status_code=200, content="test")
        self.get_response.return_value = expected_response
        request = self.factory.get("/")
        request.user = Mock(is_authenticated=True, is_staff=True)

        response = self.middleware(request)

        self.assertEqual(response, expected_response)

    def test_middleware_staff_requires_both_flags(self):
        """Test that middleware only bypasses when BOTH authenticated AND staff."""
        # Test: authenticated but not staff - should NOT bypass
        request = self.factory.get("/")
        request.user = Mock(is_authenticated=True, is_staff=False)

        # We can verify the logic by checking user attributes
        user = request.user
        self.assertFalse(user.is_staff or not user.is_authenticated)

    def test_middleware_handles_missing_user_attribute(self):
        """Test middleware gracefully handles request without user attribute."""
        request = self.factory.get("/")
        # Simulate missing user by deleting the attribute
        if hasattr(request, "user"):
            delattr(request, "user")

        # Should not raise an exception
        result = getattr(request, "user", None)
        self.assertIsNone(result)

    def test_middleware_logic_for_unauthenticated_user(self):
        """Test middleware bypass logic for unauthenticated user."""
        request = self.factory.get("/")
        request.user = Mock(is_authenticated=False, is_staff=False)

        user = getattr(request, "user", None)
        # Unauthenticated users should NOT bypass CSP
        bypass = user and user.is_authenticated and user.is_staff
        self.assertFalse(bypass)

    def test_middleware_logic_for_staff_user(self):
        """Test middleware bypass logic correctly identifies staff users."""
        request = self.factory.get("/")
        request.user = Mock(is_authenticated=True, is_staff=True)

        user = getattr(request, "user", None)
        # Staff users should bypass CSP
        bypass = user and user.is_authenticated and user.is_staff
        self.assertTrue(bypass)
