"""Tests for the exhibit annotation (forensic-lab signature move)."""

from detector import annotate
from detector.model import check_url


def _annotate(url):
    result = check_url(url)
    assert not result.get("error"), url
    return annotate.annotate_url(
        result["url"], result.get("tricks"), result["rule_triggered"]
    )


def _rendered(ann):
    return "".join(seg["text"] for seg in ann["segments"])


def _marked(ann):
    return {seg["mark"] for seg in ann["segments"] if seg["mark"] is not None}


def test_homoglyph_char_gets_circled():
    url = "https://p\u0430ypal.com/login"
    ann = _annotate(url)
    by_id = {a["rule_id"]: a for a in ann["annotations"]}
    assert "R22" in by_id
    assert by_id["R22"]["circle"] == by_id["R22"]["num"]
    # The circled segment is exactly the Cyrillic letter.
    circled = [s for s in ann["segments"] if s["mark"] == by_id["R22"]["num"]]
    assert circled and circled[0]["text"] == "\u0430"
    assert _rendered(ann) == url


def test_at_trick_circles_the_decoy():
    url = "https://google.com@evil-login.example/verify"
    ann = _annotate(url)
    by_id = {a["rule_id"]: a for a in ann["annotations"]}
    assert "R24" in by_id
    assert by_id["R24"]["circle"] is not None
    circled = "".join(
        s["text"] for s in ann["segments"] if s["mark"] == by_id["R24"]["num"]
    )
    assert circled == "google.com"
    assert _rendered(ann) == url


def test_typosquat_circles_the_label():
    url = "https://paypaI.com/login"
    ann = _annotate(url)
    by_id = {a["rule_id"]: a for a in ann["annotations"]}
    assert "R25" in by_id
    assert by_id["R25"]["circle"] is not None
    circled = "".join(
        s["text"] for s in ann["segments"] if s["mark"] == by_id["R25"]["num"]
    )
    assert circled == "paypaI"
    # The look-alike rule shares the typosquat circle.
    assert by_id["R06a"]["shares"] == by_id["R25"]["num"] or by_id["R06a"]["circle"] is not None


def test_file_extension_tld_circled():
    url = "https://invoice.zip/login"
    ann = _annotate(url)
    by_id = {a["rule_id"]: a for a in ann["annotations"]}
    assert "R27" in by_id
    assert by_id["R27"]["circle"] is not None
    circled = "".join(
        s["text"] for s in ann["segments"] if s["mark"] == by_id["R27"]["num"]
    )
    assert circled == ".zip"


def test_free_hosting_circles_the_host():
    url = "https://paypal-login.firebaseapp.com/verify"
    ann = _annotate(url)
    by_id = {a["rule_id"]: a for a in ann["annotations"]}
    assert "R29" in by_id
    assert by_id["R29"]["circle"] is not None


def test_trigger_words_circled_on_example_phishing_link():
    url = "http://paypal-secure-login.com/verify/account/update?session=8839201"
    ann = _annotate(url)
    by_id = {a["rule_id"]: a for a in ann["annotations"]}
    assert "R10a" in by_id or "R10b" in by_id
    rule = by_id.get("R10a") or by_id["R10b"]
    assert rule["circle"] is not None
    marked_text = "".join(
        s["text"] for s in ann["segments"] if s["mark"] == rule["num"]
    )
    assert "login" in marked_text or "verify" in marked_text


def test_whole_address_rules_have_notes_but_no_circle():
    # google.com/search triggers nothing; use a long URL for R09.
    url = "https://example.com/" + "a" * 130
    ann = _annotate(url)
    by_id = {a["rule_id"]: a for a in ann["annotations"]}
    assert "R09" in by_id
    assert by_id["R09"]["circle"] is None
    assert by_id["R09"]["shares"] is None


def test_invisible_characters_shown_as_boxes():
    url = "https://exam\u200bple.com/login"
    ann = _annotate(url)
    assert ann["has_invisible"] is True
    assert "\u2423" in _rendered(ann)
    assert "\u200b" not in _rendered(ann)
    by_id = {a["rule_id"]: a for a in ann["annotations"]}
    assert "R28" in by_id
    assert by_id["R28"]["circle"] is not None


def test_clean_url_has_no_marks():
    ann = _annotate("https://www.google.com/search")
    assert ann["annotations"] == []
    assert _marked(ann) == set()
    assert _rendered(ann) == "https://www.google.com/search"


def test_annotation_never_returns_markup():
    url = "https://example.com/<script>alert(1)</script>"
    ann = _annotate(url)
    assert "<span" not in _rendered(ann)
    assert "<script>" in _rendered(ann)  # raw text; the template escapes it
