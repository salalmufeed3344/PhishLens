"""Unit tests for feature extraction (detector/features.py)."""

import pytest

from detector import features


def test_ip_host_flagged():
    f = features.extract_features("http://185.23.41.9/login.php")
    assert f["is_ip_host"] == 1
    assert f["_meta"]["is_ip_host"] is True


def test_normal_https_site_is_clean():
    f = features.extract_features("https://www.google.com/search?q=hello")
    assert f["is_ip_host"] == 0
    assert f["is_http"] == 0
    assert f["has_at"] == 0
    assert f["is_punycode"] == 0
    assert f["is_shortener"] == 0
    assert f["brand_in_subdomain"] == 0
    assert f["brand_lookalike_domain"] == 0
    assert f["sensitive_keyword_count"] == 0


def test_at_symbol_detected():
    f = features.extract_features("https://www.google.com@evil.example.com/login")
    assert f["has_at"] == 1


def test_punycode_detected():
    f = features.extract_features("https://xn--pple-43d.com/login")
    assert f["is_punycode"] == 1


def test_shortener_detected():
    f = features.extract_features("https://bit.ly/3xYzAbC")
    assert f["is_shortener"] == 1
    f2 = features.extract_features("https://www.example.com/page")
    assert f2["is_shortener"] == 0


def test_brand_in_subdomain():
    f = features.extract_features("https://secure-paypal.login.verify.example.com/x")
    assert f["brand_in_subdomain"] == 1
    assert "paypal" in f["_meta"]["brands_in_subdomain"]


def test_brand_lookalike_domain():
    f = features.extract_features("http://paypal-secure-login.com/verify")
    assert f["brand_lookalike_domain"] == 1
    # The real PayPal domain is NOT a look-alike.
    f2 = features.extract_features("https://www.paypal.com/signin")
    assert f2["brand_lookalike_domain"] == 0


def test_sensitive_keywords_counted_outside_registered_domain():
    f = features.extract_features("https://example.com/login?verify=1&secure=true")
    assert f["sensitive_keyword_count"] >= 2
    # A real bank's own domain must not be penalised for its own name.
    f2 = features.extract_features("https://www.bankofamerica.com/login")
    assert f2["sensitive_keyword_count"] == 1  # only the /login path word


def test_entropy_high_for_random_host():
    random_host = features.extract_features("https://x7kq9z2m4p8w1.example.com/")
    normal_host = features.extract_features("https://www.wikipedia.org/")
    assert random_host["entropy_host"] > normal_host["entropy_host"]


def test_path_depth_and_query_params():
    f = features.extract_features("https://example.com/a/b/c?x=1&y=2&z=3")
    assert f["path_depth"] == 3
    assert f["query_param_count"] == 3


def test_scheme_assumed_when_missing():
    url, assumed = features.normalize_url("www.example.com/page")
    assert assumed is True
    assert url.startswith("https://")


def test_empty_input_rejected():
    with pytest.raises(features.URLValidationError):
        features.extract_features("")


def test_garbage_input_rejected():
    with pytest.raises(features.URLValidationError):
        features.extract_features("not a url at all!!!")


def test_absurdly_long_input_rejected():
    with pytest.raises(features.URLValidationError):
        features.extract_features("x" * 3000)


def test_hostless_input_rejected():
    with pytest.raises(features.URLValidationError):
        features.extract_features("https://")


def test_feature_vector_length_matches_feature_names():
    v = features.feature_vector("https://www.example.com/a/b?x=1")
    assert len(v) == len(features.FEATURE_NAMES)
    assert all(isinstance(x, float) for x in v)


def test_at_trick_detected():
    f = features.extract_features("http://google.com@evil.example.com/")
    assert f["has_at"] == 1
    assert f["has_at_trick"] == 1
    assert f["_meta"]["at_trick"]["decoy"] == "google.com"
    assert f["_meta"]["at_trick"]["real_host"] == "evil.example.com"


def test_at_in_path_is_not_a_trick():
    f = features.extract_features("https://example.com/@username")
    assert f["has_at_trick"] == 0


def test_typosquat_detected():
    f = features.extract_features("https://paypaI.com/login")
    assert f["is_typosquat"] == 1
    assert f["_meta"]["typosquat_brand"] == "paypal"
    f2 = features.extract_features("https://gooogle.com/login")
    assert f2["is_typosquat"] == 1
    assert f2["_meta"]["typosquat_brand"] == "google"


def test_real_brand_is_not_typosquat():
    f = features.extract_features("https://www.paypal.com/signin")
    assert f["is_typosquat"] == 0


def test_homoglyph_brand_detected():
    # Cyrillic 'a' (U+0430) in place of Latin 'a' — built from the code
    # point, never typed literally.
    url = "https://p" + chr(0x0430) + "ypal.com/login"
    f = features.extract_features(url)
    assert f["has_confusable"] == 1
    assert f["confusable_brand"] == 1
    assert f["_meta"]["confusable"]["confusable_brand"] == "paypal"
    assert f["_meta"]["confusable"]["mechanism"] == "homoglyph"


def test_real_brand_is_not_confusable():
    f = features.extract_features("https://www.paypal.com/signin")
    assert f["has_confusable"] == 0
    assert f["confusable_brand"] == 0


def test_open_redirect_detected():
    f = features.extract_features(
        "https://www.google.com/url?q=https://evil.example.com/verify")
    assert f["is_open_redirect"] == 1
    assert f["_meta"]["redirect_target"].startswith("https://evil.example.com")


def test_google_search_is_not_open_redirect():
    f = features.extract_features("https://www.google.com/search?q=hello")
    assert f["is_open_redirect"] == 0


def test_file_ext_tld_detected():
    f = features.extract_features("https://invoice.zip/login")
    assert f["has_file_ext_tld"] == 1
    f2 = features.extract_features("https://trailer.mov/watch")
    assert f2["has_file_ext_tld"] == 1
    f3 = features.extract_features("https://www.google.com/")
    assert f3["has_file_ext_tld"] == 0


def test_invisible_chars_detected():
    f = features.extract_features(
        "https://example.com/" + chr(0x202E) + "login")
    assert f["has_invisible_chars"] == 1
    assert "bidirectional-override" in f["_meta"]["invisible_kinds"]
    f2 = features.extract_features(
        "https://example.com/" + chr(0x200B) + "login")
    assert f2["has_invisible_chars"] == 1
    assert "zero-width" in f2["_meta"]["invisible_kinds"]


def test_free_hosting_login_detected():
    f = features.extract_features("https://paypal-login.firebaseapp.com/verify")
    assert f["is_free_hosting_login"] == 1
    assert f["_meta"]["free_host"] == "firebaseapp.com"


def test_free_hosting_without_login_words_is_not_flagged():
    f = features.extract_features("https://my-cool-app.netlify.app/")
    assert f["is_free_hosting_login"] == 0


def test_keyword_weights_are_tiered():
    f = features.extract_features("https://example.com/login/verify")
    assert f["keyword_weighted_score"] == 50  # login 25 + verify 25
    f2 = features.extract_features("https://example.com/secure")
    assert f2["keyword_weighted_score"] == 10  # 'secure' is a weak word


def test_brand_tier_max():
    f = features.extract_features("http://paypal-secure-login.com/verify")
    assert f["brand_tier_max"] == 70


def test_embedded_tld_detected():
    f = features.extract_features("https://paypal.com-login.net/verify")
    assert f["has_embedded_tld"] == 1
    f2 = features.extract_features("https://www.google.com/")
    assert f2["has_embedded_tld"] == 0
