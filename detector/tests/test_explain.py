"""Tests for SHAP -> plain-language explanations (detector/explain.py)."""

from detector import explain


def test_raised_sentence_shown_when_value_is_risky():
    out = explain.shap_to_sentences([
        {"feature": "is_ip_host", "value": 1, "shap": 0.3},
    ])
    assert out["raised"] == ["The address uses an IP number instead of a domain name."]
    assert out["lowered"] == []


def test_raised_sentence_hidden_when_value_is_not_risky():
    # A model can push toward phishing *because* a feature is low
    # (e.g. zero subdomains is typical of bare look-alike domains).
    # The sentence "deep chain of subdomains" would be false, so it
    # must not be shown.
    out = explain.shap_to_sentences([
        {"feature": "subdomain_count", "value": 0, "shap": 0.25},
    ])
    assert out["raised"] == []
    assert out["lowered"] == []


def test_lowered_sentence_shown_when_value_is_safe():
    out = explain.shap_to_sentences([
        {"feature": "is_ip_host", "value": 0, "shap": -0.2},
    ])
    assert out["lowered"] == ["The address uses a normal domain name, not a bare IP number."]
    assert out["raised"] == []


def test_lowered_sentence_hidden_when_value_is_risky():
    out = explain.shap_to_sentences([
        {"feature": "is_ip_host", "value": 1, "shap": -0.2},
    ])
    assert out["lowered"] == []


def test_tiny_shap_values_are_ignored():
    out = explain.shap_to_sentences([
        {"feature": "is_ip_host", "value": 1, "shap": 0.005},
    ])
    assert out == {"raised": [], "lowered": []}


def test_unknown_feature_is_skipped():
    out = explain.shap_to_sentences([
        {"feature": "tld_is_common", "value": 1, "shap": 0.3},
    ])
    assert out == {"raised": [], "lowered": []}


def test_top_contributions_orders_by_abs_shap():
    top = explain.top_contributions(
        [0.1, -0.5, 0.3], ["a", "b", "c"], [1.0, 2.0, 3.0], top_n=2
    )
    assert [t["feature"] for t in top] == ["b", "c"]
    assert top[0]["shap"] == -0.5


def test_every_model_feature_has_a_sentence_or_is_deliberately_silent():
    # Every feature the model can rank must either have a plain-language
    # sentence pair or be knowingly absent (tld_is_common is the one
    # deliberate silence — a common TLD says nothing either way).
    from detector import features

    silent = {"tld_is_common"}
    for name in features.FEATURE_NAMES:
        if name in silent:
            continue
        assert name in explain.FEATURE_SENTENCES, f"no sentence for {name}"
        assert name in explain.RISKY_VALUE, f"no risky range for {name}"


def test_new_trick_sentences_are_truthful():
    out = explain.shap_to_sentences([
        {"feature": "has_at_trick", "value": 1, "shap": 0.4},
        {"feature": "is_typosquat", "value": 1, "shap": 0.3},
        {"feature": "has_invisible_chars", "value": 1, "shap": 0.2},
        {"feature": "is_open_redirect", "value": 0, "shap": -0.2},
    ])
    assert len(out["raised"]) == 3
    assert any("decoy" in s for s in out["raised"])
    assert any("misspelling" in s for s in out["raised"])
    assert any("invisible" in s for s in out["raised"])
    assert out["lowered"] == [
        "The link does not pass through a trusted site's redirector."
    ]
