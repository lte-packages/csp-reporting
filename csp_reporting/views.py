import json

from django.http import HttpResponseBadRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .models import CSPReport


@csrf_exempt
def csp_report_view(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body.decode("utf-8"))
            # CSP reports are usually under 'csp-report' key
            report = data.get("csp-report", data)
            CSPReport.objects.create(
                raw_report=report,
                blocked_uri=report.get("blocked-uri"),
                document_uri=report.get("document-uri"),
                violated_directive=report.get("violated-directive"),
            )
            return JsonResponse({"status": "ok"}, status=201)
        except Exception as e:
            return HttpResponseBadRequest(f"Invalid CSP report: {e}")
    return HttpResponseBadRequest("Only POST allowed.")
