from django.urls import path

from .views import csp_report_view

urlpatterns = [
    path("report/", csp_report_view, name="csp_report"),
]
