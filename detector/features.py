"""
Feature extraction for PhishLens.

Converts a URL string into a fixed numeric feature vector. The URL is NEVER
fetched or visited: every feature is computed from the characters of the URL
itself (lexical, host-based, keyword and statistical features), exactly as
specified in Table 1 of the FYP proposal.

The feature list is the single source of truth shared by training
(scripts/train.py) and the web app (detector/model.py), so training and
serving can never drift apart.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import parse_qsl, urlparse

import tldextract

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

SENSITIVE_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "security", "update", "account", "bank", "banking", "password",
    "credential", "confirm", "wallet", "unlock", "suspended", "suspend",
    "limited", "alert", "payment", "billing", "invoice", "refund",
]

# Sensitive keywords, weighted by how strongly each one signals
# credential-harvesting intent. Weights adapted from the battle-tested
# scoring lists in x0rz/phishing_catcher (GPL-3.0, 2017–2024):
# strong trigger words score 25, mid words 15–20, weak words 10.
# Our scale is 0–100 (Low <= 25, Medium <= 35), so these weights feed
# the rules through the keyword_weighted_score feature, not directly.
KEYWORD_WEIGHTS = {
    # Strong (25): the classic credential-harvesting vocabulary.
    "login": 25, "log-in": 25, "signin": 25, "sign-in": 25,
    "account": 25, "verification": 25, "verify": 25, "webscr": 25,
    "password": 25, "credential": 25, "support": 25, "activity": 25,
    "security": 25, "update": 25, "authentication": 25,
    "authenticate": 25, "authorize": 25, "wallet": 25, "alert": 25,
    "purchase": 25, "transaction": 25, "recover": 25, "unlock": 25,
    # Mid (20): worth noting on its own.
    "confirm": 20,
    # Mid (15): common in phishing lures, also common elsewhere.
    "live": 15, "office": 15, "service": 15, "manage": 15,
    "portal": 15, "invoice": 15, "bank": 15, "banking": 15,
    "payment": 15, "billing": 15, "refund": 15, "suspended": 15,
    "suspend": 15, "limited": 15,
    # Weak (10): barely suspicious alone.
    "secure": 10, "customer": 10, "client": 10, "bill": 10,
    "online": 10, "safe": 10, "form": 10,
}
SENSITIVE_KEYWORDS = list(KEYWORD_WEIGHTS)

# Well-known brands phishers impersonate. Used only to detect a brand name
# appearing where it should not be (subdomain, path, or inside a look-alike
# registered domain) — never as proof on its own.
BRANDS = [
    "paypal", "google", "facebook", "meta", "amazon", "apple", "microsoft",
    "netflix", "instagram", "whatsapp", "binance", "coinbase", "chase",
    "bankofamerica", "wellsfargo", "hsbc", "barclays", "dhl", "fedex",
    "ups", "usps", "steam", "roblox", "discord", "telegram", "linkedin",
    "twitter", "adobe", "dropbox", "icloud", "outlook", "gmail", "yahoo",
    "ebay", "alibaba", "tiktok", "spotify", "visa", "mastercard",
    "americanexpress", "skrill", "payoneer", "wise", "blockchain",
    "ledger", "metamask", "openai", "chatgpt",
    # Added from the phishing_catcher brand lists, by category.
    "appleid", "iforgot", "itunes", "office365", "protonmail", "tutanota",
    "hotmail", "yandex", "tumblr", "reddit", "youtube", "flickr",
    "localbitcoin", "poloniex", "coinhive", "bithumb", "kraken",
    "bitstamp", "bittrex", "bitflyer", "hitbtc", "lakebtc", "bitfinex",
    "bitconnect", "coinsbank", "moneygram", "westernunion", "citigroup",
    "santander", "morganstanley", "scottrade", "ameritrade", "merilledge",
    "overstock", "aliexpress", "leboncoin", "skype", "github", "onedrive",
]

# Brand tiers, adapted from x0rz/phishing_catcher's suspicious.yaml
# (70 = most impersonated, 30 = lower priority / more false positives).
# Brands absent from that list are tiered by judgement in the same spirit.
BRAND_TIERS = {
    "paypal": 70, "appleid": 70, "gmail": 70, "netflix": 70,
    "protonmail": 70, "localbitcoin": 70, "coinhive": 70,
    "blockchain": 70, "leboncoin": 70, "ledger": 70, "metamask": 70,
    "icloud": 60, "iforgot": 60, "microsoft": 60, "tutanota": 60,
    "hotmail": 60, "outlook": 60, "yahoo": 60, "google": 60,
    "yandex": 60, "twitter": 60, "facebook": 60, "tumblr": 60,
    "reddit": 60, "linkedin": 60, "instagram": 60, "flickr": 60,
    "whatsapp": 60, "poloniex": 60, "bithumb": 60, "bitstamp": 60,
    "bittrex": 60, "bitflyer": 60, "coinbase": 60, "hitbtc": 60,
    "lakebtc": 60, "bitfinex": 60, "bitconnect": 60, "coinsbank": 60,
    "moneygram": 60, "westernunion": 60, "bankofamerica": 60,
    "wellsfargo": 60, "citigroup": 60, "santander": 60,
    "morganstanley": 60, "scottrade": 60, "ameritrade": 60,
    "merilledge": 60, "amazon": 60, "overstock": 60, "alibaba": 60,
    "aliexpress": 60, "skype": 60, "github": 60, "onedrive": 60,
    "dropbox": 60, "meta": 60, "binance": 60, "chase": 60, "dhl": 60,
    "fedex": 60, "steam": 60, "discord": 60, "telegram": 60,
    "adobe": 60, "ebay": 60, "tiktok": 60, "visa": 60,
    "mastercard": 60, "americanexpress": 60, "wise": 60, "openai": 60,
    "chatgpt": 60,
    "itunes": 50, "office365": 50, "kraken": 50, "barclays": 50,
    "hsbc": 50, "ups": 50, "usps": 50, "roblox": 50, "spotify": 50,
    "skrill": 50, "payoneer": 50,
    "youtube": 40,
    "apple": 30, "windows": 30,
}
# Any brand missing from BRAND_TIERS defaults to tier 60.
DEFAULT_BRAND_TIER = 60

# Official domains of the brands above (brand -> set of real registered
# domains). A registered domain that merely *contains* a brand string but
# is not the official domain is a look-alike. A domain whose label IS the
# brand string (e.g. google.co.uk, paypal.fr) is the brand's own.
BRAND_OFFICIAL_DOMAINS = {
    "paypal": {"paypal.com"},
    "google": {"google.com"},
    "facebook": {"facebook.com"},
    "meta": {"meta.com"},
    "amazon": {"amazon.com"},
    "apple": {"apple.com"},
    "appleid": {"apple.com"},
    "iforgot": {"apple.com"},
    "itunes": {"apple.com"},
    "microsoft": {"microsoft.com"},
    "office365": {"office365.com"},
    "netflix": {"netflix.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "chase": {"chase.com"},
    "bankofamerica": {"bankofamerica.com"},
    "wellsfargo": {"wellsfargo.com"},
    "hsbc": {"hsbc.com"},
    "barclays": {"barclays.co.uk"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "usps": {"usps.com"},
    "steam": {"steampowered.com"},
    "roblox": {"roblox.com"},
    "discord": {"discord.com"},
    "telegram": {"telegram.org"},
    "linkedin": {"linkedin.com"},
    "twitter": {"twitter.com"},
    "adobe": {"adobe.com"},
    "dropbox": {"dropbox.com"},
    "icloud": {"icloud.com"},
    "outlook": {"outlook.com"},
    "gmail": {"gmail.com"},
    "yahoo": {"yahoo.com"},
    "ebay": {"ebay.com"},
    "alibaba": {"alibaba.com"},
    "aliexpress": {"aliexpress.com"},
    "tiktok": {"tiktok.com"},
    "spotify": {"spotify.com"},
    "visa": {"visa.com"},
    "mastercard": {"mastercard.com"},
    "americanexpress": {"americanexpress.com"},
    "skrill": {"skrill.com"},
    "payoneer": {"payoneer.com"},
    "wise": {"wise.com"},
    "blockchain": {"blockchain.com"},
    "ledger": {"ledger.com"},
    "metamask": {"metamask.io"},
    "openai": {"openai.com"},
    "chatgpt": {"chatgpt.com"},
    "protonmail": {"protonmail.com", "proton.me"},
    "tutanota": {"tutanota.com"},
    "hotmail": {"hotmail.com"},
    "yandex": {"yandex.com", "yandex.ru"},
    "tumblr": {"tumblr.com"},
    "reddit": {"reddit.com"},
    "youtube": {"youtube.com"},
    "flickr": {"flickr.com"},
    "localbitcoin": {"localbitcoins.com"},
    "poloniex": {"poloniex.com"},
    "coinhive": {"coinhive.com"},
    "bithumb": {"bithumb.com"},
    "kraken": {"kraken.com"},
    "bitstamp": {"bitstamp.net"},
    "bittrex": {"bittrex.com"},
    "bitflyer": {"bitflyer.com"},
    "hitbtc": {"hitbtc.com"},
    "lakebtc": {"lakebtc.com"},
    "bitfinex": {"bitfinex.com"},
    "bitconnect": {"bitconnect.co"},
    "coinsbank": {"coinsbank.com"},
    "moneygram": {"moneygram.com"},
    "westernunion": {"westernunion.com"},
    "citigroup": {"citigroup.com", "citi.com"},
    "santander": {"santander.com"},
    "morganstanley": {"morganstanley.com"},
    "scottrade": {"scottrade.com"},
    "ameritrade": {"tdameritrade.com"},
    "merilledge": {"merilledge.com"},
    "overstock": {"overstock.com"},
    "leboncoin": {"leboncoin.fr"},
    "skype": {"skype.com"},
    "github": {"github.com"},
    "onedrive": {"onedrive.live.com"},
}

# Shortening services hide the real destination until the link is clicked.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rb.gy", "cutt.ly", "shorturl.at", "rebrand.ly", "t.ly", "s.id",
    "tiny.cc", "adf.ly", "bit.do", "mcaf.ee", "qr.ae", "2h.ae", "shorte.st",
    "bc.vc", "soo.gd", "v.gd", "cli.re", "u.to", "x.co", "tiny.one",
    "bl.ink", "yourls.org", "lnkd.in", "fb.me", "amzn.to", "youtu.be",
}

# Domain endings that appear disproportionately often in phishing reports
# (Spamhaus / Interisle abused-TLD reporting, plus the sketchy-TLD list
# from x0rz/phishing_catcher's suspicious.yaml). A weak signal on its own.
# Deliberately NOT included: '.bank' — it is a restricted TLD only real
# banks can hold, so it is safer, not riskier, than average.
SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "online", "site", "buzz", "click", "link",
    "work", "live", "fun", "icu", "cyou", "rest", "fit", "today", "vip",
    "shop", "monster", "quest", "sbs", "lol", "cam", "uno", "zip", "mov",
    "dad", "phd", "prof", "esq", "foo", "nexus", "ing", "meme", "mom",
    "day", "boo", "lat", "autos", "boats", "yachts", "cfd",
    # From phishing_catcher (free/abused TLDs seen in the wild 2017-2024).
    "ga", "gq", "ml", "cf", "tk", "pw", "cc", "support", "info",
    "study", "country", "stream", "gdn", "xin", "kim", "men", "loan",
    "download", "racing", "center", "ren", "gb", "win", "review",
    "party", "tech", "science", "business",
}

# Brands phishers typosquat most often — the names a one- or two-letter
# slip turns into a trap (paypaI, gooogle, arnazon). Checked with
# Levenshtein distance against the domain label after unconfusing it.
TYPO_BRANDS = [
    "paypal", "google", "apple", "amazon", "microsoft", "facebook",
    "netflix", "instagram", "whatsapp", "linkedin", "gmail", "outlook",
    "coinbase", "binance", "youtube", "twitter", "adobe", "dropbox",
    "steam", "discord", "telegram", "chase", "hsbc", "spotify",
]

# Trusted sites whose own redirector endpoints attackers launder links
# through, so the link starts with a name you trust:
# google.com/url?q=, youtube.com/redirect, facebook.com/l.php,
# linkedin.com/slink. Only these exact paths count — google.com/search
# is not a redirector, and must not be flagged.
OPEN_REDIRECTORS = {
    "google.com": {"/url"},
    "youtube.com": {"/redirect"},
    "facebook.com": {"/l.php"},
    "linkedin.com": {"/slink"},
}
# Query parameters that carry the redirect destination.
REDIRECT_PARAMS = {
    "q", "url", "u", "redirect", "next", "target", "return", "r",
    "link", "dest", "destination", "out", "goto", "redirect_to",
}

# Domain endings that are really file extensions. "invoice.zip" looks
# like a file you would download — but as a domain it is a website, and
# the browser will happily open it. .zip and .mov are live TLDs now.
FILE_EXTENSION_TLDS = {
    "zip", "mov", "dmg", "exe", "msi", "apk", "bat", "scr", "jar",
    "iso", "sh",
}

# Characters that are invisible (or change display order) in most fonts:
# bidirectional overrides U+202A–U+202E and isolates U+2066–U+2069 /
# U+061C, and zero-width characters U+200B/U+200C/U+200D/U+FEFF. A URL
# containing them can display differently from the address it really is
# (Trojan Source style).
BIDI_CHARS = set(
    list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A)) + [0x061C]
)
ZERO_WIDTH_CHARS = {0x200B, 0x200C, 0x200D, 0xFEFF}
INVISIBLE_CHARS = BIDI_CHARS | ZERO_WIDTH_CHARS

# Free hosting platforms where anyone can publish a page in minutes —
# including a fake login page under a trusted-looking name. A login page
# here is not proof of phishing on its own, but combined with
# login/verify wording it is a real warning sign.
FREE_HOSTS = {
    "sites.google.com", "firebaseapp.com", "web.app", "github.io",
    "gitlab.io", "netlify.app", "vercel.app", "s3.amazonaws.com",
    "azurewebsites.net", "pages.dev", "glitch.me", "herokuapp.com",
    "pythonanywhere.com", "repl.co", "webflow.io", "wixsite.com",
    "wordpress.com", "blogspot.com", "weebly.com", "000webhostapp.com",
    "infinityfreeapp.com",
}

COMMON_TLDS = {
    "com", "org", "net", "edu", "gov", "io", "co", "ai", "app", "dev",
    "uk", "de", "fr", "jp", "au", "ca", "in", "nl", "br", "it", "es",
}

# ---------------------------------------------------------------------------
# Feature list — the fixed order is the model's input order. Never reorder.
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    "url_length",
    "host_length",
    "path_length",
    "path_depth",
    "dot_count_host",
    "subdomain_count",
    "query_param_count",
    "has_at",
    "hyphen_count_host",
    "underscore_count_url",
    "double_slash_in_path",
    "percent_encoding_count",
    "digit_ratio_url",
    "digit_ratio_host",
    "is_ip_host",
    "has_non_default_port",
    "is_punycode",
    "is_shortener",
    "tld_length",
    "tld_is_suspicious",
    "tld_is_common",
    "registered_domain_length",
    "subdomain_total_length",
    "sensitive_keyword_count",
    "keyword_weighted_score",
    "keyword_in_subdomain",
    "brand_in_subdomain",
    "brand_in_path",
    "brand_lookalike_domain",
    "brand_tier_max",
    "brand_count",
    "has_embedded_tld",
    "has_confusable",
    "confusable_brand",
    "entropy_host",
    "entropy_path",
    "longest_digit_run",
    "vowel_consonant_ratio_host",
    "is_http",
    # Deep attacker tricks (all-in-one checks).
    "has_at_trick",
    "is_typosquat",
    "is_open_redirect",
    "has_file_ext_tld",
    "has_invisible_chars",
    "is_free_hosting_login",
]

FEATURE_DESCRIPTIONS = {
    "url_length": "Total length of the address",
    "host_length": "Length of the host name",
    "path_length": "Length of the path after the domain",
    "path_depth": "How many folders deep the path goes",
    "dot_count_host": "Dots in the host name",
    "subdomain_count": "Number of subdomains before the main domain",
    "query_param_count": "Number of ?key=value pairs",
    "has_at": "'@' in the address",
    "hyphen_count_host": "Hyphens in the host name",
    "underscore_count_url": "Underscores in the address",
    "double_slash_in_path": "'//' inside the path",
    "percent_encoding_count": "Percent-encoded (%XX) characters",
    "digit_ratio_url": "Share of digits in the whole address",
    "digit_ratio_host": "Share of digits in the host name",
    "is_ip_host": "Host is a bare IP number, not a domain name",
    "has_non_default_port": "Unusual port number in the address",
    "is_punycode": "Domain uses punycode (xn--)",
    "is_shortener": "Domain is a known link shortener",
    "tld_length": "Length of the domain ending (.com, .xyz, ...)",
    "tld_is_suspicious": "Domain ending is frequently abused for phishing",
    "tld_is_common": "Domain ending is a common, well-established one",
    "registered_domain_length": "Length of the registered domain",
    "subdomain_total_length": "Total length of all subdomains",
    "sensitive_keyword_count": "Sensitive words (login, verify, secure, ...)",
    "keyword_weighted_score": "Weighted score of sensitive words (strong words count more)",
    "keyword_in_subdomain": "Sensitive word inside a subdomain",
    "brand_in_subdomain": "Famous brand name inside a subdomain",
    "brand_in_path": "Famous brand name inside the path",
    "brand_lookalike_domain": "Brand name inside a domain that is not the brand's real address",
    "brand_tier_max": "Highest impersonation tier among misplaced brand names (70 = most targeted)",
    "brand_count": "How many different brand names appear where they should not",
    "has_embedded_tld": "A real domain ending (.com/.net/...) hidden mid-address",
    "has_confusable": "Look-alike letters from another alphabet, or mixed scripts",
    "confusable_brand": "A brand name appears only after unconfusing look-alike letters",
    "entropy_host": "Randomness of the host name (Shannon entropy)",
    "entropy_path": "Randomness of the path (Shannon entropy)",
    "longest_digit_run": "Longest run of digits in a row",
    "vowel_consonant_ratio_host": "Vowel-to-consonant ratio of the host name",
    "is_http": "Plain HTTP instead of HTTPS (weak signal)",
    "has_at_trick": "'@' trick: a decoy address before '@', real host after it",
    "is_typosquat": "Domain is 1–2 letters away from a famous brand name",
    "is_open_redirect": "Link passes through a trusted site's redirector",
    "has_file_ext_tld": "Domain ending is a file extension (.zip, .mov, ...)",
    "has_invisible_chars": "Invisible or order-changing characters in the address",
    "is_free_hosting_login": "Login page hosted on a free platform",
}

MAX_URL_LENGTH = 2048

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_extractor = tldextract.TLDExtract(cache_dir=None)


def _shannon_entropy(text: str) -> float:
    """Shannon entropy of a string, in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _longest_digit_run(text: str) -> int:
    runs = re.findall(r"\d+", text)
    return max((len(r) for r in runs), default=0)


def _vowel_consonant_ratio(text: str) -> float:
    letters = [c for c in text.lower() if c.isalpha()]
    if not letters:
        return 0.0
    vowels = sum(1 for c in letters if c in "aeiou")
    consonants = len(letters) - vowels
    if consonants == 0:
        return float(len(letters))
    return vowels / consonants


def _is_ip(host: str) -> bool:
    """True if the host is an IP address (v4 or v6, incl. dotted-quad)."""
    if not host:
        return False
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Dotted decimal quad that ipaddress rejects only if out of range —
    # still counts as an IP-shaped host.
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        return True
    # Hex / octal IP forms, e.g. 0xC0.0x00.0x02.0xeb
    if re.fullmatch(r"0x[0-9a-fA-F]+(\.0x[0-9a-fA-F]+){3}", host):
        return True
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class URLValidationError(ValueError):
    """Raised when the submitted text cannot be analysed as a URL."""


def registered_domain_of(raw_url: str) -> str:
    """Registered domain of a URL (lightweight — no feature extraction)."""
    try:
        url, _ = normalize_url(raw_url)
    except URLValidationError:
        return ""
    ext = _extractor(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return (urlparse(url).hostname or "").lower()


def normalize_url(raw: str) -> tuple[str, bool]:
    """Clean user input into an analysable URL.

    Returns (normalized_url, scheme_was_assumed). Raises URLValidationError
    for empty, absurdly long, or host-less input. Never fetches anything.
    """
    if raw is None:
        raise URLValidationError("No URL was provided.")
    url = raw.strip()
    if not url:
        raise URLValidationError("Please paste a URL first.")
    if len(url) > MAX_URL_LENGTH:
        raise URLValidationError(
            f"That URL is {len(url)} characters long — over the "
            f"{MAX_URL_LENGTH} character limit. Check for a copy-paste error."
        )
    # Strip angle brackets / quotes people often paste around links.
    url = url.strip("<>\"'")
    scheme_assumed = False
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url
        scheme_assumed = True
    parsed = urlparse(url)
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise URLValidationError(
            "That does not look like a web address — no host name could be "
            "found. A URL looks like https://example.com/login"
        )
    # A host must be a valid DNS name or an IP address. Without this,
    # strings like "not a url at all" would parse as a host.
    # Non-ASCII hosts are allowed: they are checked in their punycode
    # (idna) form, so homoglyph domains like pаypal.com are analysable
    # instead of rejected — catching them is the point.
    if not _is_ip(host) and not _valid_hostname(host):
        raise URLValidationError(
            f'"{host}" is not a valid host name. A URL looks like '
            "https://example.com/login"
        )
    return url, scheme_assumed


def _valid_hostname(host: str) -> bool:
    """True if the host is a plausible DNS name (ASCII or Unicode)."""
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except Exception:
        return False
    return bool(re.fullmatch(
        r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*",
        ascii_host,
    ))


def extract_features(raw_url: str) -> dict:
    """Extract the fixed feature vector from a URL string.

    Accepts a raw user string (scheme optional). Returns a dict keyed by
    FEATURE_NAMES with numeric values, plus a `_meta` entry with parsed
    parts for display (not a model feature).
    """
    url, scheme_assumed = normalize_url(raw_url)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    port = parsed.port  # None when absent or invalid
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    ext = _extractor(url)
    subdomain = ext.subdomain or ""
    domain = ext.domain or ""
    suffix = ext.suffix or ""
    registered = f"{domain}.{suffix}" if domain and suffix else (domain or host)
    host_no_port = host

    # --- Confusable analysis (Unicode homoglyphs, ASCII look-alikes,
    # near-miss spellings) -------------------------------------------
    # Like phishing_catcher, brand/keyword matching below runs on the
    # UNCONFUSED form as well as the raw form: a Cyrillic 'а' reads as
    # 'a' to a human, so the detector must read it that way too.
    from . import confusables as _conf

    strong_brands = [b for b in BRANDS
                     if BRAND_TIERS.get(b, DEFAULT_BRAND_TIER) >= 70]
    conf = _conf.analyze_host(host_no_port, BRANDS, strong_brands)
    skel_host = conf["skeleton_host"]
    ext_skel = _extractor(skel_host)
    skel_subdomain = ext_skel.subdomain or ""
    skel_domain = ext_skel.domain or ""
    skel_suffix = ext_skel.suffix or ""
    registered_skel = (f"{skel_domain}.{skel_suffix}"
                       if skel_domain and skel_suffix
                       else (skel_domain or skel_host))

    # Keywords / brands are counted where they do NOT belong: subdomains,
    # path and query — not inside the registered domain itself, so a real
    # bank's own address is not penalised for containing "bank".
    searchable = f"{subdomain} {path} {query} {fragment}".lower()
    searchable_host = subdomain.lower()
    searchable_skel = _conf.ascii_skeleton(_conf.skeleton(searchable))
    searchable_host_skel = _conf.ascii_skeleton(_conf.skeleton(searchable_host))

    def matched_keywords(text: str) -> list[str]:
        """Distinct keywords found in text, longest first.

        A shorter word that sits inside an already-matched longer word
        (e.g. 'verify' inside 'verification', 'bank' inside 'banking')
        is not counted twice.
        """
        found = [w for w in KEYWORD_WEIGHTS if w in text]
        found.sort(key=len, reverse=True)
        kept: list[str] = []
        for word in found:
            if not any(word in longer for longer in kept):
                kept.append(word)
        return kept

    kw_hits = matched_keywords(searchable)
    kw_count = len(kw_hits)
    kw_score = sum(KEYWORD_WEIGHTS[w] for w in kw_hits)
    kw_in_sub = 1 if any(w in searchable_host for w in KEYWORD_WEIGHTS) else 0

    def brands_in(text_raw: str, text_skel: str) -> list[str]:
        """Brands appearing in either the raw or the unconfused text."""
        return [b for b in BRANDS if b in text_raw or b in text_skel]

    brands_in_sub = brands_in(searchable_host, searchable_host_skel)
    brands_in_path = brands_in((path + " " + query).lower(),
                               _conf.ascii_skeleton(_conf.skeleton((path + " " + query).lower())))

    # Look-alike: a brand string inside the registered domain (read in its
    # unconfused form), but the domain is not that brand's own address.
    # The brand's own address is recognised two ways: the registered
    # domain is in its official set, or the domain label IS the brand
    # (google.co.uk, paypal.fr). A homoglyph of the official domain
    # (raw != skeleton) is never the brand's own address.
    lookalike_brand = ""
    for brand in BRANDS:
        if brand not in registered_skel.lower():
            continue
        official = BRAND_OFFICIAL_DOMAINS.get(brand, set())
        own = (
            registered.lower() == registered_skel.lower()
            and (registered.lower() in official or skel_domain.lower() == brand)
        )
        if not own:
            lookalike_brand = brand
            break
    lookalike = 1 if lookalike_brand else 0
    # A near-miss brand (one edit away) is a look-alike too.
    if conf["confusable_brand"] and conf["mechanism"] == "near-miss":
        lookalike = 1
        lookalike_brand = lookalike_brand or conf["confusable_brand"]

    misplaced_brands = set(brands_in_sub) | set(brands_in_path)
    if lookalike_brand:
        misplaced_brands.add(lookalike_brand)
    if conf["confusable_brand"]:
        misplaced_brands.add(conf["confusable_brand"])
    brand_tier_max = max(
        (BRAND_TIERS.get(b, DEFAULT_BRAND_TIER) for b in misplaced_brands),
        default=0,
    )
    brand_count = len(misplaced_brands)

    # Embedded-TLD trick: a real domain ending (.com/.net/.org/.gov)
    # hidden mid-address, e.g. paypal.com-login.net or
    # www.paypal.com.security.example.com.
    labels = host_no_port.split(".")
    has_embedded_tld = 0
    if any(lbl in ("com", "net", "org", "gov") for lbl in labels[:-1]):
        has_embedded_tld = 1
    elif re.search(r"\.(com|net|org|gov)-", host_no_port) or \
            re.search(r"-(com|net|org|gov)\.", host_no_port):
        has_embedded_tld = 1

    is_ip = _is_ip(host_no_port)
    default_port = {"http": 80, "https": 443}.get(parsed.scheme.lower())
    has_port = 1 if (port is not None and port != default_port) else 0

    query_params = parse_qsl(query, keep_blank_values=True)
    path_segments = [s for s in path.split("/") if s]

    # --- Deep attacker tricks (all-in-one checks) ----------------------
    # Invisible characters: scanned in the RAW input, before any
    # normalisation — the whole point is that they are invisible.
    found_chars = {ord(c) for c in raw_url}
    invisible_kinds: list[str] = []
    if found_chars & BIDI_CHARS:
        invisible_kinds.append("bidirectional-override")
    if found_chars & ZERO_WIDTH_CHARS:
        invisible_kinds.append("zero-width")
    has_invisible_chars = 1 if invisible_kinds else 0

    # The "@" trick: anything before the last "@" is userinfo, which the
    # browser ignores. http://google.com@evil.com really goes to
    # evil.com — google.com is only a decoy.
    at_trick = None
    if parsed.username:
        at_trick = {"decoy": parsed.username, "real_host": host_no_port}
    has_at_trick = 1 if at_trick else 0

    # Typosquat: the domain label (after unconfusing look-alikes) is one
    # or two edits away from a famous brand — paypaI, gooogle, arnazon.
    # Distance 2 only counts for longer brands, to keep false alarms
    # down. The brand's own domain is distance 0 and never flags.
    typosquat_brand = ""
    typosquat_label = ""
    typosquat_distance = 0
    label_skel = skel_domain.lower()
    if label_skel and len(label_skel) >= 4:
        best: tuple[int, str] | None = None
        for brand in TYPO_BRANDS:
            if len(brand) < 4 or brand == label_skel:
                continue
            d = _conf.edit_distance(label_skel, brand)
            if d == 0 or d > 2 or (d == 2 and len(brand) < 6):
                continue
            if best is None or d < best[0] or (
                d == best[0]
                and BRAND_TIERS.get(brand, DEFAULT_BRAND_TIER)
                > BRAND_TIERS.get(best[1], DEFAULT_BRAND_TIER)
            ):
                best = (d, brand)
        if best:
            typosquat_distance, typosquat_brand = best
            typosquat_label = label_skel
    is_typosquat = 1 if typosquat_brand else 0

    # Open-redirect laundering: the link starts on a trusted site's own
    # redirector endpoint (google.com/url?q=, youtube.com/redirect,
    # facebook.com/l.php, linkedin.com/slink) and hands you to a
    # different destination. Only the exact redirector paths count, so
    # google.com/search?q=... is never flagged.
    redirect_target = ""
    is_open_redirect = 0
    redirect_paths = OPEN_REDIRECTORS.get(registered.lower())
    if redirect_paths and parsed.path.lower() in redirect_paths:
        for key, val in query_params:
            if key.lower() in REDIRECT_PARAMS and val:
                v = val.strip()
                if "://" in v or re.match(
                    r"^(www\.)?[a-z0-9-]+\.[a-z]{2,}", v, re.I
                ):
                    redirect_target = v[:80]
                    is_open_redirect = 1
                    break

    # File-extension TLD: the domain ending is a file extension, so
    # "invoice.zip" reads as a file — but here it is a website.
    has_file_ext_tld = 1 if suffix.lower() in FILE_EXTENSION_TLDS else 0

    # Free hosting + login wording: a login/verify page on a platform
    # where anyone can publish in minutes (firebaseapp.com, github.io,
    # netlify.app, sites.google.com, ...). Only login-flavoured wording
    # counts — a plain support page on the same platform does not.
    LOGIN_KEYWORDS = {
        "login", "log-in", "signin", "sign-in", "verify", "verification",
        "password", "account", "secure", "update", "wallet", "credential",
    }
    free_host = ""
    for fh in FREE_HOSTS:
        if host_no_port == fh or host_no_port.endswith("." + fh):
            free_host = fh
            break
    is_free_hosting_login = 1 if (
        free_host and any(w in searchable for w in LOGIN_KEYWORDS)
    ) else 0

    feats = {
        "url_length": len(url),
        "host_length": len(host_no_port),
        "path_length": len(path),
        "path_depth": len(path_segments),
        "dot_count_host": host_no_port.count("."),
        "subdomain_count": subdomain.count(".") + 1 if subdomain else 0,
        "query_param_count": len(query_params),
        "has_at": 1 if "@" in url else 0,
        "hyphen_count_host": host_no_port.count("-"),
        "underscore_count_url": url.count("_"),
        "double_slash_in_path": 1 if "//" in path else 0,
        "percent_encoding_count": len(re.findall(r"%[0-9a-fA-F]{2}", url)),
        "digit_ratio_url": sum(c.isdigit() for c in url) / max(len(url), 1),
        "digit_ratio_host": sum(c.isdigit() for c in host_no_port) / max(len(host_no_port), 1),
        "is_ip_host": 1 if is_ip else 0,
        "has_non_default_port": has_port,
        "is_punycode": 1 if "xn--" in host_no_port else 0,
        "is_shortener": 1 if registered.lower() in SHORTENERS else 0,
        "tld_length": len(suffix),
        "tld_is_suspicious": 1 if suffix.lower() in SUSPICIOUS_TLDS else 0,
        "tld_is_common": 1 if suffix.lower() in COMMON_TLDS else 0,
        "registered_domain_length": len(registered),
        "subdomain_total_length": len(subdomain),
        "sensitive_keyword_count": kw_count,
        "keyword_weighted_score": kw_score,
        "keyword_in_subdomain": kw_in_sub,
        "brand_in_subdomain": 1 if brands_in_sub else 0,
        "brand_in_path": 1 if brands_in_path else 0,
        "brand_lookalike_domain": lookalike,
        "brand_tier_max": brand_tier_max,
        "brand_count": brand_count,
        "has_embedded_tld": has_embedded_tld,
        "has_confusable": 1 if conf["has_confusable"] else 0,
        "confusable_brand": 1 if conf["confusable_brand"] else 0,
        "entropy_host": round(_shannon_entropy(host_no_port), 3),
        "entropy_path": round(_shannon_entropy(path), 3),
        "longest_digit_run": _longest_digit_run(url),
        "vowel_consonant_ratio_host": round(_vowel_consonant_ratio(host_no_port), 3),
        "is_http": 1 if parsed.scheme.lower() == "http" else 0,
        "has_at_trick": has_at_trick,
        "is_typosquat": is_typosquat,
        "is_open_redirect": is_open_redirect,
        "has_file_ext_tld": has_file_ext_tld,
        "has_invisible_chars": has_invisible_chars,
        "is_free_hosting_login": is_free_hosting_login,
    }

    feats["_meta"] = {
        "url": url,
        "scheme_assumed": scheme_assumed,
        "scheme": parsed.scheme.lower(),
        "host": host_no_port,
        "subdomain": subdomain,
        "registered_domain": registered,
        "tld": suffix,
        "path": path,
        "is_ip_host": bool(is_ip),
        "brands_in_subdomain": brands_in_sub,
        "brands_in_path": brands_in_path,
        "keyword_hits": kw_hits,
        "keyword_weighted_score": kw_score,
        "lookalike_brand": lookalike_brand,
        "brand_tier_max": brand_tier_max,
        "confusable": conf,
        "at_trick": at_trick,
        "typosquat_brand": typosquat_brand,
        "typosquat_label": typosquat_label,
        "typosquat_distance": typosquat_distance,
        "redirect_target": redirect_target,
        "invisible_kinds": invisible_kinds,
        "free_host": free_host,
    }
    return feats


def feature_vector(raw_url: str) -> list[float]:
    """Feature values in FEATURE_NAMES order (no _meta) — model input."""
    feats = extract_features(raw_url)
    return [float(feats[name]) for name in FEATURE_NAMES]
