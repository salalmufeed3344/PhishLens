"""End-to-end tests for the checker views and JSON API."""

import json

import pytest
from django.test import Client
from django.urls import reverse

pytestmark = pytest.mark.django_db


@pytest.fixture
def client():
    return Client()


def test_home_page_loads(client):
    resp = client.get(reverse("home"))
    assert resp.status_code == 200
    assert b"PhishLens" in resp.content
    assert b"Check link" in resp.content


def test_metrics_page_loads(client):
    resp = client.get(reverse("metrics"))
    assert resp.status_code == 200
    assert b"metrics" in resp.content.lower()


def test_check_legit_url_returns_low(client):
    resp = client.post(reverse("check"), {"url": "https://www.google.com/search?q=hello"})
    assert resp.status_code == 200
    assert b"Low risk" in resp.content


def test_check_phishing_lookalike_returns_high_or_medium(client):
    resp = client.post(
        reverse("check"),
        {"url": "http://paypal-secure-login.com/verify/account/update?session=8839201"},
    )
    assert resp.status_code == 200
    assert b"risk" in resp.content.lower()
    assert b"High risk" in resp.content or b"Medium risk" in resp.content


def test_check_ip_host_url_flags_ip_rule(client):
    resp = client.post(reverse("check"), {"url": "http://185.23.41.9/login.php"})
    assert resp.status_code == 200
    assert b"IP address as host" in resp.content


def test_check_empty_url_shows_error(client):
    resp = client.post(reverse("check"), {"url": ""})
    assert resp.status_code == 200
    assert b"Please paste a URL first" in resp.content


def test_check_garbage_url_shows_error(client):
    resp = client.post(reverse("check"), {"url": "not a url at all!!!"})
    assert resp.status_code == 200
    assert b"not a valid host name" in resp.content


def test_check_get_not_allowed(client):
    resp = client.get(reverse("check"))
    assert resp.status_code == 405


def test_api_check_returns_json(client):
    resp = client.post(
        reverse("api_check"),
        data=json.dumps({"url": "https://www.google.com/"}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "Low"
    assert data["score"] <= 25
    assert "rules_triggered" in data
    assert "advice" in data


def test_api_check_phishing_lookalike(client):
    resp = client.post(
        reverse("api_check"),
        data=json.dumps({"url": "http://paypal-secure-login.com/verify/account"}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] in ("Medium", "High")
    assert len(data["rules_triggered"]) >= 2


def test_api_check_bad_input_returns_400(client):
    resp = client.post(
        reverse("api_check"),
        data=json.dumps({"url": ""}),
        content_type="application/json",
    )
    assert resp.status_code == 400
    assert "error" in resp.json()


def test_api_check_invalid_json_returns_400(client):
    resp = client.post(
        reverse("api_check"),
        data="{not json",
        content_type="application/json",
    )
    assert resp.status_code == 400


def test_submitted_url_is_never_rendered_as_link(client):
    resp = client.post(
        reverse("check"),
        {"url": "http://evil.example.com/login"},
    )
    assert resp.status_code == 200
    # The URL text may appear, but never as a clickable hyperlink.
    assert b'href="http://evil.example.com' not in resp.content
    assert b"href='http://evil.example.com" not in resp.content


# --- Required end-to-end cases: deep tricks must score High, the real
# thing must score Low. These exercise the full check (rules + model).

def test_check_homoglyph_brand_login_scores_high(client):
    # Cyrillic 'a' (U+0430) in place of Latin 'a' — built from the code
    # point, never typed literally.
    url = "https://p" + chr(0x0430) + "ypal.com/login"
    resp = client.post(reverse("check"), {"url": url})
    assert resp.status_code == 200
    assert b"High risk" in resp.content
    assert b"look-alike" in resp.content


def test_check_real_paypal_scores_low(client):
    resp = client.post(reverse("check"), {"url": "https://www.paypal.com/signin"})
    assert resp.status_code == 200
    assert b"Low risk" in resp.content


def test_check_at_trick_scores_high(client):
    resp = client.post(
        reverse("check"),
        {"url": "http://google.com@evil-login.example.com/verify"},
    )
    assert resp.status_code == 200
    assert b"High risk" in resp.content
    assert b"@' trick" in resp.content or b"decoy" in resp.content


def test_check_typosquat_scores_high(client):
    resp = client.post(reverse("check"), {"url": "https://paypaI.com/login"})
    assert resp.status_code == 200
    assert b"High risk" in resp.content
    assert b"Typosquat" in resp.content


def test_check_zip_domain_scores_high(client):
    resp = client.post(reverse("check"), {"url": "https://invoice.zip/login"})
    assert resp.status_code == 200
    assert b"High risk" in resp.content
    assert b"File-extension" in resp.content


def test_check_bidi_character_scores_high(client):
    url = "https://verify-account.com/" + chr(0x202E) + "login"
    resp = client.post(reverse("check"), {"url": url})
    assert resp.status_code == 200
    assert b"High risk" in resp.content
    assert b"Invisible characters" in resp.content


def test_check_open_redirect_scores_high_or_medium(client):
    resp = client.post(
        reverse("check"),
        {"url": "https://www.google.com/url?q=https://evil-login.example.com/verify"},
    )
    assert resp.status_code == 200
    assert b"High risk" in resp.content or b"Medium risk" in resp.content
    assert b"Open redirect" in resp.content


def test_check_free_hosting_login_scores_high_or_medium(client):
    resp = client.post(
        reverse("check"),
        {"url": "https://paypal-login.firebaseapp.com/verify"},
    )
    assert resp.status_code == 200
    assert b"High risk" in resp.content or b"Medium risk" in resp.content
    assert b"free hosting" in resp.content


def test_result_page_states_https_does_not_mean_safe(client):
    resp = client.post(reverse("check"), {"url": "https://www.google.com/"})
    assert resp.status_code == 200
    assert b"HTTPS does not mean safe" in resp.content
