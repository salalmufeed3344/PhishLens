"""
Rule-based phishing detector for PhishLens.

A transparent, fully auditable detector: every rule has an id, a condition
over the extracted features, a weight, and a plain-language message. The
weights are summed and capped at 100 to give a 0–100 risk score, then mapped
to Low / Medium / High.

Weight provenance: the keyword and brand weights are adapted from the
battle-tested scoring lists in x0rz/phishing_catcher (GPL-3.0,
``suspicious.yaml``, 2017–2024) — generic trigger words 25, weak words 10,
brand names 30–70 by category — rescaled to our 0–100 scale instead of
copied blindly. Their TLD list (+20 per hit on a scale where 65 is
suspicious) and their tricks (fake embedded TLD, Levenshtein-1 near-miss
to a top brand, unconfusing homoglyphs before matching) are adapted the
same way. No phishing_catcher code is used; only the published scoring
lists informed the numbers.

The Low/Medium/High thresholds are tuned on the validation split in
scripts/train.py and stored in the model artifacts. If no tuned
thresholds are available, the defaults below are used.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

# Default thresholds (overridden by tuned values in model artifacts).
DEFAULT_LOW_MAX = 29      # score <= 29  -> Low
DEFAULT_MEDIUM_MAX = 59   # score 30-59  -> Medium, >= 60 -> High


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    weight: int
    message: str
    condition: Callable[[dict], bool]
    # Optional dynamic message: (features, details) -> str. Details carry
    # the confusable analysis (which character, which brand) so the
    # explanation can name the exact trick.
    format_message: Optional[Callable[[dict, dict], str]] = field(default=None)


def _tier(feats: dict) -> int:
    return int(feats.get("brand_tier_max", 0))


def _confusable_brand_message(feats: dict, details: dict) -> str:
    brand = details.get("confusable_brand", "")
    mechanism = details.get("mechanism", "")
    chars = details.get("chars", []) or []
    raw = details.get("raw_label", "")
    skel = details.get("skeleton_label", "")
    if mechanism == "homoglyph" and chars and brand:
        c = chars[0]
        return (
            f"This domain uses a look-alike character — the "
            f"'{c['looks_like']}' in '{brand}' is actually a "
            f"{c['script']} letter, not a Latin one. What you read as "
            f"'{skel}' is really '{raw}'."
        )
    if mechanism == "ascii" and brand and raw and skel:
        if len(raw) == len(skel):
            for i, (a, b) in enumerate(zip(raw, skel)):
                if a != b:
                    return (
                        f"This domain spells '{brand}' with look-alike "
                        f"characters — '{raw}' uses '{a}' where '{b}' "
                        f"belongs."
                    )
        return (
            f"This domain spells '{brand}' with look-alike characters — "
            f"'{raw}' instead of '{brand}'."
        )
    if mechanism == "near-miss" and brand and raw:
        return (
            f"The domain is one letter away from the real brand "
            f"'{brand}' — '{raw}' instead of '{brand}'."
        )
    if brand:
        return (
            f"This domain impersonates '{brand}' with look-alike "
            f"characters."
        )
    return "This domain uses look-alike characters to impersonate a brand."


def _mixed_script_message(feats: dict, details: dict) -> str:
    if details.get("mixed_script"):
        return (
            "The domain mixes letters from different alphabets (for "
            "example Latin and Cyrillic). Real brands don't do this."
        )
    return (
        "The domain contains look-alike letters borrowed from another "
        "alphabet."
    )


def _at_trick_message(feats: dict, details: dict) -> str:
    decoy = details.get("at_decoy", "")
    real = details.get("at_real_host", "")
    if decoy and real:
        return (
            f"Everything before the '@' is ignored by the browser — "
            f"the address you see is '{decoy}', but the site you would "
            f"actually visit is '{real}'."
        )
    return (
        "Everything before the '@' is ignored by the browser, so the "
        "address you see is not the address you visit."
    )


def _typosquat_message(feats: dict, details: dict) -> str:
    brand = details.get("typosquat_brand", "")
    label = details.get("typosquat_label", "")
    dist = details.get("typosquat_distance", 1)
    if brand and label:
        away = "one letter" if dist == 1 else "two letters"
        return (
            f"'{label}' is {away} away from the real brand '{brand}' — "
            f"a misspelling attackers register to catch typos and "
            f"glances."
        )
    if brand:
        return (
            f"This domain is a misspelling of the real brand '{brand}'."
        )
    return "This domain is a misspelling of a famous brand name."


def _open_redirect_message(feats: dict, details: dict) -> str:
    host = details.get("redirect_host", "")
    target = details.get("redirect_target", "")
    if host and target:
        return (
            f"This link starts on {host} — a site you trust — but it "
            f"redirects to '{target}'. The trusted name is just the "
            f"doorway; the destination is somewhere else entirely."
        )
    return (
        "This link starts on a trusted site but redirects elsewhere — "
        "the trusted name is just the doorway."
    )


def _file_ext_tld_message(feats: dict, details: dict) -> str:
    tld = details.get("file_ext_tld", "")
    if tld:
        return (
            f"This address ends in .{tld}, which looks like a file "
            f"name — but here it is a website address, not a file. "
            f"Attackers register domains like 'invoice.{tld}' because "
            f"your eye reads them as documents."
        )
    return (
        "This address ends in a file extension, not a normal domain "
        "ending."
    )


def _invisible_chars_message(feats: dict, details: dict) -> str:
    kinds = details.get("invisible_kinds") or []
    if kinds:
        desc = " and ".join(kinds)
        return (
            f"The address contains invisible {desc} characters. What "
            f"you see on screen can differ from the real address — "
            f"characters you cannot see can flip the order of the text "
            f"or hide extra letters."
        )
    return (
        "The address contains invisible characters that can change "
        "what you see."
    )


def _free_hosting_message(feats: dict, details: dict) -> str:
    host = details.get("free_host", "")
    if host:
        return (
            f"This login page lives on {host}, a free hosting service "
            f"where anyone can publish a page in minutes. The trusted "
            f"platform name is not the site owner's name."
        )
    return (
        "This login page lives on a free hosting service where anyone "
        "can publish a page in minutes."
    )


RULES: list[Rule] = [
    Rule(
        "R01", "IP address as host", 25,
        "The address uses an IP number instead of a domain name. Real "
        "websites use names; attackers hide behind bare numbers so the "
        "site cannot be recognised at a glance.",
        lambda f: bool(f.get("is_ip_host")),
    ),
    Rule(
        "R02", "'@' in the URL", 15,
        "The link contains an '@'. Everything before it is ignored by the "
        "browser, so the address you see is not the address you visit.",
        lambda f: bool(f.get("has_at")),
    ),
    Rule(
        "R03", "Punycode domain", 15,
        "The domain uses punycode (xn--), which can disguise look-alike "
        "letters borrowed from other alphabets.",
        lambda f: bool(f.get("is_punycode")),
    ),
    Rule(
        "R04", "Link shortener", 12,
        "The link is shortened, so the real destination stays hidden "
        "until you click it.",
        lambda f: bool(f.get("is_shortener")),
    ),
    Rule(
        "R05a", "Top-target brand in subdomain", 24,
        "A name belonging to one of the most impersonated brands sits "
        "in the subdomain, but the site belongs to someone else.",
        lambda f: bool(f.get("brand_in_subdomain")) and _tier(f) >= 70,
    ),
    Rule(
        "R05b", "Brand name in subdomain", 20,
        "A well-known brand name appears in the subdomain, but the site "
        "itself belongs to a different domain — a classic impersonation "
        "trick.",
        lambda f: bool(f.get("brand_in_subdomain")) and 50 <= _tier(f) < 70,
    ),
    Rule(
        "R05c", "Lower-priority brand in subdomain", 15,
        "A brand name appears in the subdomain, but the site itself "
        "belongs to a different domain.",
        lambda f: bool(f.get("brand_in_subdomain")) and 0 < _tier(f) < 50,
    ),
    Rule(
        "R06a", "Top-target brand look-alike domain", 26,
        "The domain name imitates one of the most impersonated brands, "
        "but it is not that brand's real address.",
        lambda f: bool(f.get("brand_lookalike_domain")) and _tier(f) >= 70,
    ),
    Rule(
        "R06b", "Brand look-alike domain", 22,
        "The domain name contains a famous brand name, but it is not "
        "that brand's real address.",
        lambda f: bool(f.get("brand_lookalike_domain")) and 50 <= _tier(f) < 70,
    ),
    Rule(
        "R06c", "Lower-priority brand look-alike domain", 18,
        "The domain name contains a brand name, but it is not that "
        "brand's real address.",
        lambda f: bool(f.get("brand_lookalike_domain")) and 0 < _tier(f) < 50,
    ),
    Rule(
        "R07", "Many subdomains", 10,
        "The address has an unusually deep chain of subdomains, often "
        "used to bury the real domain where you will not notice it.",
        lambda f: f.get("subdomain_count", 0) >= 3,
    ),
    Rule(
        "R08", "Plain HTTP", 5,
        "The link uses plain HTTP instead of HTTPS. On its own this "
        "proves little — many phishing pages use HTTPS too — but it is "
        "one more weak sign.",
        lambda f: bool(f.get("is_http")),
    ),
    Rule(
        "R09", "Very long URL", 6,
        "The address is unusually long. Phishing links are often padded "
        "with extra characters to push the suspicious part out of view.",
        lambda f: f.get("url_length", 0) > 120,
    ),
    Rule(
        "R10a", "Multiple strong trigger words", 12,
        "The link is stuffed with strong trigger words like 'login', "
        "'verify' or 'password' — language used to rush you into "
        "entering credentials.",
        lambda f: f.get("keyword_weighted_score", 0) >= 50,
    ),
    Rule(
        "R10b", "Trigger words present", 8,
        "The link uses trigger words like 'login', 'verify' or "
        "'secure' — language used to rush you into entering credentials.",
        lambda f: 25 <= f.get("keyword_weighted_score", 0) < 50,
    ),
    Rule(
        "R10c", "Weak trigger words", 4,
        "The link uses a mild trigger word such as 'secure' or "
        "'online'. On its own this means little.",
        lambda f: 10 <= f.get("keyword_weighted_score", 0) < 25,
    ),
    Rule(
        "R11", "Random-looking domain", 8,
        "The domain name looks randomly generated rather than chosen by "
        "a person — a common trait of mass-produced phishing domains.",
        lambda f: f.get("entropy_host", 0) > 4.2,
    ),
    Rule(
        "R12", "Long run of digits", 6,
        "A long run of digits in the address is unusual for a normal "
        "website and common in generated phishing links.",
        lambda f: f.get("longest_digit_run", 0) >= 6,
    ),
    Rule(
        "R13", "Abuse-prone domain ending", 8,
        "The address ends in a domain ending that is very often abused "
        "for phishing.",
        lambda f: bool(f.get("tld_is_suspicious")),
    ),
    Rule(
        "R14", "Unusual port", 10,
        "The link uses an unusual port number. Normal websites almost "
        "never do this.",
        lambda f: bool(f.get("has_non_default_port")),
    ),
    Rule(
        "R15", "'//' inside the path", 8,
        "The address contains '//' inside the path, a trick sometimes "
        "used to disguise where a link really goes.",
        lambda f: bool(f.get("double_slash_in_path")),
    ),
    Rule(
        "R16", "Many dots in host", 5,
        "The host name contains a lot of dots — the address is built "
        "from many pieces, which makes the real domain harder to spot.",
        lambda f: f.get("dot_count_host", 0) >= 5,
    ),
    Rule(
        "R17", "Heavy percent-encoding", 5,
        "Parts of the address are percent-encoded, which can hide the "
        "real characters from the reader.",
        lambda f: f.get("percent_encoding_count", 0) >= 3,
    ),
    Rule(
        "R18", "Hyphen-packed host", 6,
        "The domain is packed with hyphens, a common way to imitate a "
        "real brand name (brand-name-secure-login.com).",
        lambda f: f.get("hyphen_count_host", 0) >= 3,
    ),
    Rule(
        "R19", "Digit-heavy address", 5,
        "An unusually large share of the address is digits, which is "
        "rare for a normal website.",
        lambda f: f.get("digit_ratio_url", 0) > 0.25,
    ),
    Rule(
        "R20", "Underscores in address", 4,
        "The address contains several underscores. Real domains cannot "
        "contain them at all, and they are often used to fake a "
        "familiar name.",
        lambda f: f.get("underscore_count_url", 0) >= 2,
    ),
    Rule(
        "R21", "Domain ending hidden mid-address", 10,
        "A real domain ending such as '.com' appears in the middle of "
        "the address (for example paypal.com-login.net). The part you "
        "trust is not the part that owns the site.",
        lambda f: bool(f.get("has_embedded_tld")),
    ),
    Rule(
        "R22", "Look-alike letters impersonating a brand", 22,
        "This domain uses look-alike characters to impersonate a brand.",
        lambda f: bool(f.get("confusable_brand")),
        format_message=_confusable_brand_message,
    ),
    Rule(
        "R23", "Mixed alphabets in the domain", 15,
        "The domain mixes letters from different alphabets. Real "
        "brands don't do this.",
        lambda f: bool(f.get("has_confusable")) and not bool(f.get("confusable_brand")),
        format_message=_mixed_script_message,
    ),
    Rule(
        "R24", "The '@' trick — a decoy before '@'", 30,
        "Everything before the '@' is ignored by the browser, so the "
        "address you see is not the address you visit.",
        lambda f: bool(f.get("has_at_trick")),
        format_message=_at_trick_message,
    ),
    Rule(
        "R25", "Typosquat — a misspelling of a real brand", 28,
        "The domain is a misspelling of a famous brand name — a trap "
        "for typos and fast glances.",
        lambda f: bool(f.get("is_typosquat")),
        format_message=_typosquat_message,
    ),
    Rule(
        "R26", "Open redirect through a trusted site", 18,
        "This link starts on a trusted site but redirects elsewhere — "
        "the trusted name is just the doorway.",
        lambda f: bool(f.get("is_open_redirect")),
        format_message=_open_redirect_message,
    ),
    Rule(
        "R27", "File-extension domain (.zip, .mov, ...)", 20,
        "This address ends in a file extension, not a normal domain "
        "ending — 'invoice.zip' looks like a file, but here it is a "
        "website.",
        lambda f: bool(f.get("has_file_ext_tld")),
        format_message=_file_ext_tld_message,
    ),
    Rule(
        "R28", "Invisible characters in the address", 30,
        "The address contains invisible characters that can change "
        "what you see on screen.",
        lambda f: bool(f.get("has_invisible_chars")),
        format_message=_invisible_chars_message,
    ),
    Rule(
        "R29", "Login page on free hosting", 24,
        "This login page lives on a free hosting service where anyone "
        "can publish a page in minutes.",
        lambda f: bool(f.get("is_free_hosting_login")),
        format_message=_free_hosting_message,
    ),
]


def level_for_score(score: int, low_max: int = DEFAULT_LOW_MAX,
                    medium_max: int = DEFAULT_MEDIUM_MAX) -> str:
    """Map a 0–100 score to Low / Medium / High."""
    if score <= low_max:
        return "Low"
    if score <= medium_max:
        return "Medium"
    return "High"


def evaluate_rules(features: dict, details: dict | None = None) -> dict:
    """Run all rules over an extracted feature dict.

    ``details`` (optional) carries the confusable analysis from
    extract_features' ``_meta`` so rules like R22 can name the exact
    trick. When absent (e.g. training), static messages are used.

    Returns {"score": int 0-100, "level": str, "triggered": [rule dicts]}.
    Triggered rules are sorted by weight, heaviest first.
    """
    details = details or {}
    triggered = []
    total = 0
    for rule in RULES:
        try:
            hit = rule.condition(features)
        except Exception:
            hit = False
        if hit:
            total += rule.weight
            message = rule.message
            if rule.format_message is not None:
                try:
                    message = rule.format_message(features, details)
                except Exception:
                    pass
            triggered.append({
                "id": rule.id,
                "name": rule.name,
                "weight": rule.weight,
                "message": message,
            })
    triggered.sort(key=lambda r: -r["weight"])
    score = min(100, total)
    return {
        "score": score,
        "level": level_for_score(score),
        "triggered": triggered,
        "total_weight": total,
    }
