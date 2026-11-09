"""PhishLens detector URL configuration."""

from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("check", views.check, name="check"),
    path("metrics", views.metrics, name="metrics"),
    path("api/check", views.api_check, name="api_check"),
]
