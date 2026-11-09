"""PhishLens detector URL configuration."""

from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("check", views.check, name="check"),
    path("metrics", views.metrics, name="metrics"),
    path("privacy", views.legal_page, {"page": "privacy"}, name="privacy"),
    path("cookies", views.legal_page, {"page": "cookies"}, name="cookies"),
    path("terms", views.legal_page, {"page": "terms"}, name="terms"),
    path("about", views.legal_page, {"page": "about"}, name="about"),
    path("api/check", views.api_check, name="api_check"),
]
