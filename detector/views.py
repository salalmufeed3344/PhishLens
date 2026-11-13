"""PhishLens views: one-page checker, metrics page, legal pages, JSON API."""

from __future__ import annotations

import json

from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from . import annotate as annotate_api
from . import model as model_api

# Example links shown on the home page. The phishing example is a
# look-alike domain that does not need to exist — the app never fetches it.
EXAMPLE_PHISHING = "http://paypal-secure-login.com/verify/account/update?session=8839201"
EXAMPLE_LEGIT = "https://www.wikipedia.org/wiki/Phishing"


def _teaser_metrics() -> dict | None:
    """Formatted holdout metrics for the home-page teaser, read from the
    same metrics.json that /metrics renders — so the home numbers can
    never go stale on a retrain. Returns None when no metrics exist."""
    model = model_api.get_metrics().get("model") or {}
    try:
        return {
            "accuracy": f"{float(model['test_accuracy']) * 100:.1f}%",
            "precision": f"{float(model['test_precision']) * 100:.1f}%",
            "recall": f"{float(model['test_recall']) * 100:.1f}%",
            "roc_auc": f"{float(model['test_roc_auc']):.3f}",
        }
    except (KeyError, TypeError, ValueError):
        return None


def home(request):
    return render(request, "detector/home.html", {
        "example_phishing": EXAMPLE_PHISHING,
        "example_legit": EXAMPLE_LEGIT,
        "teaser_metrics": _teaser_metrics(),
    })


@require_http_methods(["POST"])
def check(request):
    url = request.POST.get("url", "")
    try:
        result = model_api.check_url(url)
    except Exception:
        # Never show a bare 500 for a failed analysis: keep the user's
        # URL and invite a retry.
        return render(request, "detector/home.html", {
            "error": "Something went wrong while analysing this link. "
                     "Please try again.",
            "submitted_url": url,
            "example_phishing": EXAMPLE_PHISHING,
            "example_legit": EXAMPLE_LEGIT,
            "teaser_metrics": _teaser_metrics(),
        })
    if result.get("error"):
        return render(request, "detector/home.html", {
            "error": result["error"],
            "submitted_url": url,
            "example_phishing": EXAMPLE_PHISHING,
            "example_legit": EXAMPLE_LEGIT,
            "teaser_metrics": _teaser_metrics(),
        })
    # Exhibit annotation: circle each finding on the address itself.
    # It must never break the result page — fall back to no annotation.
    try:
        result["annotation"] = annotate_api.annotate_url(
            result["url"], result.get("tricks"), result["rule_triggered"]
        )
    except Exception:
        result["annotation"] = None
    return render(request, "detector/result.html", {"result": result})


def metrics(request):
    metrics = model_api.get_metrics()
    return render(request, "detector/metrics.html", {"metrics": metrics})


def legal_page(request, page):
    """One view for the four plain legal pages: privacy, cookies,
    terms, about. The page name comes from the URL pattern only."""
    return render(request, f"detector/{page}.html")


@csrf_exempt
@require_http_methods(["POST"])
def api_check(request):
    """POST /api/check — JSON in, JSON out.

    Accepts {"url": "..."} (JSON body) or form-encoded url=...
    Returns the same analysis as the web UI, or {"error": ...} with 400.
    """
    try:
        if request.content_type and "application/json" in request.content_type:
            payload = json.loads(request.body.decode("utf-8") or "{}")
            url = payload.get("url", "")
        else:
            url = request.POST.get("url", "")
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JsonResponse({"error": "Request body was not valid JSON."}, status=400)

    try:
        result = model_api.check_url(url)
    except Exception:
        return JsonResponse(
            {"error": "Something went wrong while analysing this link. "
                      "Please try again."},
            status=500,
        )
    if result.get("error"):
        return JsonResponse({"error": result["error"]}, status=400)

    public = {
        "url": result["url"],
        "host": result["host"],
        "registered_domain": result["registered_domain"],
        "verdict": result["final_level"],
        "score": result["final_score"],
        "rule_score": result["rule_score"],
        "rule_level": result["rule_level"],
        "model_probability": result["model_probability"],
        "model_level": result["model_level"],
        "model_available": result["model_available"],
        "rules_triggered": result["rule_triggered"],
        "shap_reasons": result["shap_reasons"],
        "advice": result["advice"],
    }
    return JsonResponse(public)
