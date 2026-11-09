"""
Plain-language explanations for PhishLens.

Two sources:
1. Rule triggers — already plain language (see detector/rules.py).
2. SHAP attributions from the Random Forest — each feature maps to a pair
   of sentences: one for when it pushes the prediction toward phishing
   ("raised risk"), one for when it pushes toward legitimate ("lowered
   risk"). Explanations are always worded as risk indicators, never proof.
"""

from __future__ import annotations

# feature -> (raised_risk_sentence, lowered_risk_sentence)
FEATURE_SENTENCES: dict[str, tuple[str, str]] = {
    "is_ip_host": (
        "The address uses an IP number instead of a domain name.",
        "The address uses a normal domain name, not a bare IP number.",
    ),
    "has_at": (
        "The link contains an '@', which hides the real destination.",
        "There is no '@' trick hiding the real destination.",
    ),
    "is_punycode": (
        "The domain uses punycode, which can disguise look-alike letters.",
        "The domain uses ordinary letters — no punycode disguise.",
    ),
    "is_shortener": (
        "The link is shortened, so the real destination is hidden.",
        "The link is not shortened — the destination is visible.",
    ),
    "brand_in_subdomain": (
        "A famous brand name sits in the subdomain, but the site belongs to someone else.",
        "No brand name is being borrowed in the subdomain.",
    ),
    "brand_lookalike_domain": (
        "The domain borrows a famous brand name but is not that brand's real address.",
        "The domain does not imitate a famous brand name.",
    ),
    "brand_in_path": (
        "A brand name appears in the path of a site that is not that brand.",
        "No brand name is borrowed in the path.",
    ),
    "brand_count": (
        "Several brand names appear where they should not.",
        "No brand names appear where they should not.",
    ),
    "subdomain_count": (
        "The address has an unusually deep chain of subdomains.",
        "The subdomain structure is shallow and ordinary.",
    ),
    "dot_count_host": (
        "The host name is built from many pieces, hiding the real domain.",
        "The host name has a normal number of parts.",
    ),
    "is_http": (
        "The link uses plain HTTP instead of HTTPS.",
        "The link uses HTTPS.",
    ),
    "url_length": (
        "The address is unusually long for a normal link.",
        "The address is a normal length.",
    ),
    "host_length": (
        "The host name is unusually long.",
        "The host name is a normal length.",
    ),
    "path_length": (
        "The path after the domain is unusually long.",
        "The path is a normal length.",
    ),
    "path_depth": (
        "The address goes unusually deep into folders.",
        "The address is not buried deep in folders.",
    ),
    "query_param_count": (
        "The link carries a lot of tracking-style parameters.",
        "The link carries few or no extra parameters.",
    ),
    "hyphen_count_host": (
        "The domain is packed with hyphens, often used to imitate a brand.",
        "The domain is not packed with hyphens.",
    ),
    "underscore_count_url": (
        "The address contains underscores, which real domains never use.",
        "The address contains no underscores.",
    ),
    "double_slash_in_path": (
        "There is a '//' hidden inside the path.",
        "There is no '//' hidden inside the path.",
    ),
    "percent_encoding_count": (
        "Parts of the address are encoded, hiding the real characters.",
        "The address is not hiding characters behind encoding.",
    ),
    "digit_ratio_url": (
        "An unusually large share of the address is digits.",
        "The address is mostly letters, as normal addresses are.",
    ),
    "digit_ratio_host": (
        "The host name is unusually digit-heavy.",
        "The host name is mostly letters.",
    ),
    "has_non_default_port": (
        "The link uses an unusual port number.",
        "The link uses a standard port.",
    ),
    "tld_length": (
        "The domain ending is unusually long.",
        "The domain ending is a normal length.",
    ),
    "tld_is_suspicious": (
        "The domain ending is one that is very often abused for phishing.",
        "The domain ending is not one commonly abused for phishing.",
    ),
    "registered_domain_length": (
        "The registered domain is unusually long.",
        "The registered domain is a normal length.",
    ),
    "subdomain_total_length": (
        "The subdomains add up to an unusually long prefix.",
        "The subdomains are short and ordinary.",
    ),
    "sensitive_keyword_count": (
        "The link uses urgent words like 'login', 'verify' or 'secure'.",
        "The link does not use credential-harvesting trigger words.",
    ),
    "keyword_weighted_score": (
        "The link is stuffed with strong trigger words that push you to act fast.",
        "The link uses few or no strong trigger words.",
    ),
    "brand_tier_max": (
        "It borrows the name of one of the most impersonated brands.",
        "No heavily impersonated brand name is misused here.",
    ),
    "has_embedded_tld": (
        "A real domain ending is hidden in the middle of the address.",
        "No domain ending is hidden in the middle of the address.",
    ),
    "has_confusable": (
        "The domain uses look-alike letters borrowed from another alphabet.",
        "The domain uses ordinary letters from a single alphabet.",
    ),
    "confusable_brand": (
        "A brand name appears only after unconfusing look-alike letters.",
        "No brand name is hidden behind look-alike letters.",
    ),
    "has_at_trick": (
        "Everything before the '@' is a decoy — the real host is after it.",
        "There is no '@' decoy hiding the real host.",
    ),
    "is_typosquat": (
        "The domain is a misspelling of a famous brand name.",
        "The domain is not a misspelling of a famous brand.",
    ),
    "is_open_redirect": (
        "The link starts on a trusted site but redirects somewhere else.",
        "The link does not pass through a trusted site's redirector.",
    ),
    "has_file_ext_tld": (
        "The address ends in a file extension, not a normal domain ending.",
        "The address ends in a normal domain ending.",
    ),
    "has_invisible_chars": (
        "The address contains invisible characters that can change what you see.",
        "The address contains no invisible characters.",
    ),
    "is_free_hosting_login": (
        "A login page is hosted on a free platform anyone can use.",
        "The page is not a login form sitting on free hosting.",
    ),
    "keyword_in_subdomain": (
        "A sensitive word like 'login' or 'verify' sits in the subdomain.",
        "No sensitive word sits in the subdomain.",
    ),
    "entropy_host": (
        "The domain name looks randomly generated rather than human-chosen.",
        "The domain name looks human-chosen, not randomly generated.",
    ),
    "entropy_path": (
        "The path looks randomly generated.",
        "The path looks like ordinary words and structure.",
    ),
    "longest_digit_run": (
        "There is a long run of digits, typical of generated links.",
        "There is no suspicious run of digits.",
    ),
    "vowel_consonant_ratio_host": (
        "The host name has an odd letter pattern for a real word.",
        "The host name reads like a normal word.",
    ),
}


def shap_to_sentences(shap_contributions: list[dict]) -> dict:
    """Turn SHAP contributions into plain-language reason lists.

    Input: [{"feature": name, "value": float (raw feature value),
             "shap": float (attribution toward the phishing class)}]
    Output: {"raised": [...sentences...], "lowered": [...sentences...]}
    Only contributions with a meaningful magnitude are shown.

    A SHAP value alone does not make a sentence true: a model can push
    toward phishing *because* a feature is low (e.g. zero subdomains is
    typical of bare look-alike domains). A raised sentence is therefore
    shown only when the raw value is actually in the risky range, and a
    lowered sentence only when it is in the safe range. Anything else is
    dropped rather than narrated incorrectly.
    """
    raised: list[str] = []
    lowered: list[str] = []
    for item in shap_contributions:
        feature = item["feature"]
        value = item["shap"]
        raw = item["value"]
        if abs(value) < 0.01:
            continue
        pair = FEATURE_SENTENCES.get(feature)
        if pair is None:
            continue
        risky = _is_risky(feature, raw)
        if value > 0 and risky:
            raised.append(pair[0])
        elif value < 0 and not risky:
            lowered.append(pair[1])
    return {"raised": raised, "lowered": lowered}


# feature -> predicate: is this raw value in the risky range?
# Binary flags are risky when 1; continuous features have a cut-off.
RISKY_VALUE: dict[str, object] = {
    "is_ip_host": lambda v: v == 1,
    "has_at": lambda v: v == 1,
    "is_punycode": lambda v: v == 1,
    "is_shortener": lambda v: v == 1,
    "brand_in_subdomain": lambda v: v == 1,
    "brand_lookalike_domain": lambda v: v == 1,
    "brand_in_path": lambda v: v == 1,
    "brand_count": lambda v: v >= 1,
    "has_non_default_port": lambda v: v == 1,
    "double_slash_in_path": lambda v: v == 1,
    "tld_is_suspicious": lambda v: v == 1,
    "keyword_in_subdomain": lambda v: v == 1,
    "is_http": lambda v: v == 1,
    "url_length": lambda v: v > 75,
    "host_length": lambda v: v > 25,
    "path_length": lambda v: v > 30,
    "path_depth": lambda v: v >= 2,
    "dot_count_host": lambda v: v >= 4,
    "subdomain_count": lambda v: v >= 2,
    "query_param_count": lambda v: v >= 3,
    "hyphen_count_host": lambda v: v >= 2,
    "underscore_count_url": lambda v: v >= 2,
    "percent_encoding_count": lambda v: v >= 2,
    "digit_ratio_url": lambda v: v > 0.15,
    "digit_ratio_host": lambda v: v > 0.15,
    "tld_length": lambda v: v > 5,
    "registered_domain_length": lambda v: v > 20,
    "subdomain_total_length": lambda v: v > 15,
    "sensitive_keyword_count": lambda v: v >= 1,
    "keyword_weighted_score": lambda v: v >= 25,
    "brand_tier_max": lambda v: v >= 60,
    "has_embedded_tld": lambda v: v == 1,
    "has_confusable": lambda v: v == 1,
    "confusable_brand": lambda v: v == 1,
    "has_at_trick": lambda v: v == 1,
    "is_typosquat": lambda v: v == 1,
    "is_open_redirect": lambda v: v == 1,
    "has_file_ext_tld": lambda v: v == 1,
    "has_invisible_chars": lambda v: v == 1,
    "is_free_hosting_login": lambda v: v == 1,
    "entropy_host": lambda v: v > 4.0,
    "entropy_path": lambda v: v > 4.0,
    "longest_digit_run": lambda v: v >= 5,
    "vowel_consonant_ratio_host": lambda v: v < 0.35 or v > 1.2,
}


def _is_risky(feature: str, value: float) -> bool:
    pred = RISKY_VALUE.get(feature)
    if pred is None:
        return True  # no range defined: trust the SHAP direction
    return bool(pred(value))


def top_contributions(shap_values, feature_names: list[str],
                      feature_values: list[float], top_n: int = 6) -> list[dict]:
    """Pick the top-N features by |SHAP value|, heaviest first."""
    ranked = sorted(
        range(len(feature_names)),
        key=lambda i: -abs(float(shap_values[i])),
    )
    out = []
    for i in ranked[:top_n]:
        out.append({
            "feature": feature_names[i],
            "value": feature_values[i],
            "shap": round(float(shap_values[i]), 4),
        })
    return out
