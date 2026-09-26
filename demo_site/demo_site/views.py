from django.shortcuts import render


def home(request):
    """Home page for CSP testing"""
    return render(request, "home.html", {"title": "CSP Testing Home"})


def test_violation(request):
    """Page that intentionally violates CSP to test report collection"""
    return render(request, "test_violation.html", {"title": "CSP Violation Test"})
