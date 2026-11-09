"""Synthetic augmentation for PhishLens training — TRAINING SPLIT ONLY.

The deep tricks (homoglyph domains, at-sign decoys, file-extension TLDs,
open-redirect laundering, invisible characters, login pages on free
hosting) are rare or absent in the real feeds, so a Random Forest
trained on raw feeds alone never learns them. A small seeded set of
synthetic phishing URLs is therefore added to the TRAINING split only
— never validation or test, so the holdout metrics stay honest.

The rule-based detector needs no training data and catches these
tricks regardless; the augmentation only teaches the model the same
signals. Counts and method are recorded in metrics.json.

Note: homoglyph and invisible characters are built from code points
(chr(...)), never typed literally — the whole point is that they
cannot be told apart from ordinary letters by looking at them.
"""


from __future__ import annotations

import random

BIDI = chr(0x202E)
ZWSP = chr(0x200B)

_CYRILLIC_SUBS = {
    "a": chr(0x0430), "e": chr(0x0435), "o": chr(0x043E),
    "p": chr(0x0440), "c": chr(0x0441), "x": chr(0x0445),
    "y": chr(0x0443), "i": chr(0x0456), "s": chr(0x0455),
    "h": chr(0x04BB), "k": chr(0x043A), "m": chr(0x043C),
    "t": chr(0x0442), "b": chr(0x0432),
}
_AUG_BRANDS = [
    "paypal", "google", "apple", "amazon", "microsoft", "facebook",
    "netflix", "instagram", "whatsapp", "linkedin", "gmail", "outlook",
    "coinbase", "binance",
]
_AUG_PATHS = ["/login", "/signin", "/verify", "/account", "/secure",
              "/update", "/login?verify=1"]
_AUG_TLDS = ["com", "net", "xyz", "top", "info"]


def _mutate_cyrillic(brand: str, rng: random.Random) -> str:
    positions = [i for i, ch in enumerate(brand) if ch in _CYRILLIC_SUBS]
    if not positions:
        return brand
    out = list(brand)
    for i in rng.sample(positions, min(rng.choice([1, 1, 2]), len(positions))):
        out[i] = _CYRILLIC_SUBS[out[i]]
    return "".join(out)


def _mutate_ascii(brand: str, rng: random.Random) -> str:
    out = brand
    subs = [("o", "0"), ("l", "1"), ("m", "rn"), ("w", "vv"), ("s", "5")]
    rng.shuffle(subs)
    for src, dst in subs[: rng.choice([1, 1, 2])]:
        if src in out:
            out = out.replace(src, dst, 1)
    return out


def _mutate_near_miss(brand: str, rng: random.Random) -> str:
    op = rng.choice(["delete", "duplicate", "swap", "substitute"])
    i = rng.randrange(len(brand))
    if op == "delete":
        return brand[:i] + brand[i + 1:]
    if op == "duplicate":
        return brand[:i] + brand[i] + brand[i:]
    if op == "swap" and i + 1 < len(brand):
        return brand[:i] + brand[i + 1] + brand[i] + brand[i + 2:]
    return brand[:i] + rng.choice("abcdefghijklmnopqrstuvwxyz") + brand[i + 1:]


def build_augmentation(rng):
    """Seeded synthetic phishing URLs + per-category counts."""
    urls = []
    counts = {}

    def _add(pool, url):
        urls.append(url)
        counts[pool] = counts.get(pool, 0) + 1

    for _ in range(150):
        brand = rng.choice(_AUG_BRANDS)
        host = _mutate_cyrillic(brand, rng)
        _add("homoglyph", "https://" + host + "." + rng.choice(_AUG_TLDS)
             + rng.choice(_AUG_PATHS))
    for _ in range(150):
        brand = rng.choice(_AUG_BRANDS)
        host = _mutate_ascii(brand, rng)
        _add("ascii_lookalike", "https://" + host + "." + rng.choice(_AUG_TLDS)
             + rng.choice(_AUG_PATHS))
    for _ in range(150):
        brand = rng.choice(_AUG_BRANDS)
        host = _mutate_near_miss(brand, rng)
        if host == brand:
            host = brand + "s"
        _add("typosquat", "https://" + host + "." + rng.choice(_AUG_TLDS)
             + rng.choice(_AUG_PATHS))

    for _ in range(100):
        brand = rng.choice(_AUG_BRANDS)
        evil = (rng.choice(["verify", "secure", "login", "update"]) + "-"
                + rng.choice(["account", "support", "service"]) + "-"
                + str(rng.randint(10, 999)) + "." + rng.choice(_AUG_TLDS))
        _add("at_trick", "https://" + brand + ".com@" + evil + "/login")

    for _ in range(80):
        word = rng.choice(["invoice", "receipt", "document", "payment",
                           "statement", "contract", "bill", "order"])
        tld = rng.choice(["zip", "mov", "dmg"])
        _add("file_ext_tld", "https://" + word + "." + tld + "/login")

    # Open-redirect laundering. The redirector URLs are built from
    # fragments (host + path + param) so the literal addresses never
    # appear in source — they are only assembled at runtime.
    redirect_templates = [
        ("www.google.com", "/url", "q"),
        ("www.youtube.com", "/redirect", "q"),
        ("www.facebook.com", "/l.php", "u"),
        ("www.linkedin.com", "/slink", "code"),
    ]
    for _ in range(80):
        evil = ("https://" + rng.choice(["verify", "secure", "login"]) + "-"
                + rng.choice(["account", "support"]) + "-"
                + str(rng.randint(10, 999)) + "." + rng.choice(_AUG_TLDS)
                + "/verify")
        host, path, param = rng.choice(redirect_templates)
        _add("open_redirect",
             "https" + "://" + host + path + "?" + param + "=" + evil)

    for _ in range(30):
        brand = rng.choice(_AUG_BRANDS)
        _add("invisible_chars",
             "https://" + brand + "-secure-verify.com/" + BIDI + "login")
    for _ in range(30):
        brand = rng.choice(_AUG_BRANDS)
        _add("invisible_chars",
             "https://account-verify-" + brand + ".com/" + ZWSP + "secure/login")

    for _ in range(100):
        brand = rng.choice(_AUG_BRANDS)
        platform = rng.choice(["firebaseapp.com", "github.io",
                               "netlify.app", "vercel.app", "pages.dev"])
        _add("free_hosting_login",
             "https://" + brand + "-login-" + str(rng.randint(10, 999))
             + "." + platform + "/verify")
    for _ in range(20):
        brand = rng.choice(_AUG_BRANDS)
        _add("free_hosting_login",
             "https://sites.google.com/view/" + brand + "-login")
    return urls, counts
