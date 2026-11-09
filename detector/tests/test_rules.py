"""Unit tests for the rule-based detector (detector/rules.py)."""

from detector import features, rules


def _score(url: str):
    feats = features.extract_features(url)
    meta = feats.pop("_meta")
    # Same details the app passes, so dynamic messages name the trick.
    details = dict(meta["confusable"])
    details.update({
        "at_decoy": (meta["at_trick"] or {}).get("decoy", ""),
        "at_real_host": (meta["at_trick"] or {}).get("real_host", ""),
        "typosquat_brand": meta["typosquat_brand"],
        "typosquat_label": meta["typosquat_label"],
        "typosquat_distance": meta["typosquat_distance"],
        "redirect_host": meta["registered_domain"],
        "redirect_target": meta["redirect_target"],
        "file_ext_tld": meta["tld"],
        "invisible_kinds": meta["invisible_kinds"],
        "free_host": meta["free_host"],
    })
    return rules.evaluate_rules(feats, details)


def test_ip_host_login_url_scores_high():
    r = _score("http://185.23.41.9/login.php")
    assert r["score"] >= 30
    assert any(t["id"] == "R01" for t in r["triggered"])


def test_normal_google_scores_low():
    r = _score("https://www.google.com/search?q=hello")
    assert r["score"] <= 10
    assert r["level"] == "Low"
    assert r["triggered"] == []


def test_lookalike_brand_domain_triggers():
    r = _score("http://paypal-secure-login.com/verify/account")
    ids = {t["id"] for t in r["triggered"]}
    assert any(i.startswith("R06") for i in ids)  # brand look-alike
    assert any(i.startswith("R10") for i in ids)  # sensitive keywords
    assert r["score"] >= 30


def test_shortener_triggers_rule():
    r = _score("https://bit.ly/3xYzAbC")
    assert any(t["id"] == "R04" for t in r["triggered"])


def test_at_symbol_triggers_rule():
    r = _score("https://www.google.com@evil.example.com/")
    assert any(t["id"] == "R02" for t in r["triggered"])


def test_real_paypal_scores_low():
    r = _score("https://www.paypal.com/signin")
    assert r["level"] == "Low"


def test_level_boundaries():
    assert rules.level_for_score(0) == "Low"
    assert rules.level_for_score(29) == "Low"
    assert rules.level_for_score(30) == "Medium"
    assert rules.level_for_score(59) == "Medium"
    assert rules.level_for_score(60) == "High"
    assert rules.level_for_score(100) == "High"


def test_triggered_rules_sorted_by_weight():
    r = _score("http://185.23.41.9@xn--evil.com:8080/login_underscore")
    weights = [t["weight"] for t in r["triggered"]]
    assert weights == sorted(weights, reverse=True)


def test_every_rule_has_message_and_weight():
    for rule in rules.RULES:
        assert rule.id and rule.name and rule.message
        assert rule.weight > 0


def test_at_trick_triggers_rule():
    r = _score("http://google.com@evil-login.example.com/verify")
    assert any(t["id"] == "R24" for t in r["triggered"])
    assert any(t["id"] == "R02" for t in r["triggered"])
    msg = next(t["message"] for t in r["triggered"] if t["id"] == "R24")
    assert "evil-login.example.com" in msg


def test_at_in_path_is_not_the_trick():
    r = _score("https://example.com/@username")
    assert not any(t["id"] == "R24" for t in r["triggered"])


def test_typosquat_triggers_rule():
    r = _score("https://paypaI.com/login")
    assert any(t["id"] == "R25" for t in r["triggered"])
    msg = next(t["message"] for t in r["triggered"] if t["id"] == "R25")
    assert "paypal" in msg
    r2 = _score("https://gooogle.com/login")
    assert any(t["id"] == "R25" for t in r2["triggered"])


def test_real_brand_is_not_typosquat():
    r = _score("https://www.paypal.com/signin")
    assert not any(t["id"] == "R25" for t in r["triggered"])


def test_open_redirect_triggers_rule():
    r = _score("https://www.google.com/url?q=https://evil-login.example.com/verify")
    assert any(t["id"] == "R26" for t in r["triggered"])


def test_google_search_is_not_open_redirect():
    r = _score("https://www.google.com/search?q=hello")
    assert not any(t["id"] == "R26" for t in r["triggered"])


def test_file_ext_tld_triggers_rule():
    r = _score("https://invoice.zip/login")
    assert any(t["id"] == "R27" for t in r["triggered"])
    r2 = _score("https://trailer.mov/watch")
    assert any(t["id"] == "R27" for t in r2["triggered"])


def test_invisible_chars_trigger_rule():
    r = _score("https://verify-account.com/" + chr(0x202E) + "login")
    assert any(t["id"] == "R28" for t in r["triggered"])


def test_free_hosting_login_triggers_rule():
    r = _score("https://paypal-login.firebaseapp.com/verify")
    assert any(t["id"] == "R29" for t in r["triggered"])


def test_free_hosting_without_login_words_does_not_trigger():
    r = _score("https://my-cool-app.netlify.app/")
    assert not any(t["id"] == "R29" for t in r["triggered"])


def test_homoglyph_brand_triggers_rule():
    # Cyrillic 'a' (U+0430) in place of Latin 'a' — built from the code
    # point, never typed literally.
    url = "https://p" + chr(0x0430) + "ypal.com/login"
    r = _score(url)
    assert any(t["id"] == "R22" for t in r["triggered"])
    msg = next(t["message"] for t in r["triggered"] if t["id"] == "R22")
    assert "Cyrillic" in msg or "look-alike" in msg
