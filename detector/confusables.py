"""
Homoglyph / confusable-character detection for PhishLens.

Written from scratch for this project (standard library only). The idea —
unconfuse a domain by mapping look-alike characters back to Latin, then
check whether a brand name appears — is borrowed from the approach in
x0rz/phishing_catcher (GPL-3.0), whose confusables table itself is a
large generated mapping from Unicode TR39 data. This module does NOT copy
that table: it uses a small hand-written map of the Cyrillic and Greek
look-alikes most abused in phishing, plus mixed-script detection via
``unicodedata``.

What it catches that punycode (xn--) detection alone misses:
- Raw-Unicode homoglyph domains, e.g. ``pаypal.com`` (Cyrillic 'а').
- Punycode domains whose decoded form is a homoglyph brand, e.g.
  ``xn--pple-43d.com`` decodes to ``аpple.com``.
- ASCII look-alikes that never leave ASCII: 'rn' for 'm'
  (``hotrnail.com``), '0' for 'o' (``g00gle.com``), '1' for 'l'.
- Near-miss spellings one edit away from a heavily impersonated brand
  (``paypol`` for ``paypal``).
- Any domain that mixes scripts (Latin + Cyrillic/Greek), which real
  brands essentially never do.
"""

from __future__ import annotations

import unicodedata

# Hand-written homoglyph map: non-Latin character -> the Latin letter it
# impersonates. Only the visually identical look-alikes that matter for
# brand impersonation. (Code points are given so the map is auditable.)
HOMOGLYPHS: dict[str, str] = {
    # Cyrillic lowercase (U+0400 block)
    "\u0430": "a",  # а CYRILLIC SMALL LETTER A
    "\u0435": "e",  # е CYRILLIC SMALL LETTER IE
    "\u043e": "o",  # о CYRILLIC SMALL LETTER O
    "\u0440": "p",  # р CYRILLIC SMALL LETTER ER
    "\u0441": "c",  # с CYRILLIC SMALL LETTER ES
    "\u0445": "x",  # х CYRILLIC SMALL LETTER KHA
    "\u0443": "y",  # у CYRILLIC SMALL LETTER U
    "\u0456": "i",  # і CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "\u0458": "j",  # ј CYRILLIC SMALL LETTER JE
    "\u0455": "s",  # ѕ CYRILLIC SMALL LETTER DZE
    "\u04bb": "h",  # һ CYRILLIC SMALL LETTER SHHA
    "\u043a": "k",  # к CYRILLIC SMALL LETTER KA
    "\u043c": "m",  # м CYRILLIC SMALL LETTER EM
    "\u043d": "h",  # н CYRILLIC SMALL LETTER EN
    "\u0442": "t",  # т CYRILLIC SMALL LETTER TE
    "\u0432": "b",  # в CYRILLIC SMALL LETTER VE
    "\u0433": "r",  # г CYRILLIC SMALL LETTER GHE
    "\u0437": "3",  # з CYRILLIC SMALL LETTER ZE
    "\u044d": "e",  # э CYRILLIC SMALL LETTER E
    # Cyrillic uppercase
    "\u0410": "A",  # А
    "\u0412": "B",  # В
    "\u0415": "E",  # Е
    "\u041a": "K",  # К
    "\u041c": "M",  # М
    "\u041d": "H",  # Н
    "\u041e": "O",  # О
    "\u0420": "P",  # Р
    "\u0421": "C",  # С
    "\u0422": "T",  # Т
    "\u0425": "X",  # Х
    "\u0423": "Y",  # У
    # Greek lowercase
    "\u03b1": "a",  # α GREEK SMALL LETTER ALPHA
    "\u03b5": "e",  # ε GREEK SMALL LETTER EPSILON
    "\u03b9": "i",  # ι GREEK SMALL LETTER IOTA
    "\u03ba": "k",  # κ GREEK SMALL LETTER KAPPA
    "\u03bd": "v",  # ν GREEK SMALL LETTER NU
    "\u03bf": "o",  # ο GREEK SMALL LETTER OMICRON
    "\u03c1": "p",  # ρ GREEK SMALL LETTER RHO
    "\u03c4": "t",  # τ GREEK SMALL LETTER TAU
    "\u03c7": "x",  # χ GREEK SMALL LETTER CHI
    "\u03c5": "u",  # υ GREEK SMALL LETTER UPSILON
    "\u03b7": "n",  # η GREEK SMALL LETTER ETA
    "\u03bc": "u",  # μ GREEK SMALL LETTER MU
    "\u03c9": "w",  # ω GREEK SMALL LETTER OMEGA
    # Greek uppercase
    "\u0391": "A",  # Α
    "\u0392": "B",  # Β
    "\u0395": "E",  # Ε
    "\u0397": "H",  # Η
    "\u0399": "I",  # Ι
    "\u039a": "K",  # Κ
    "\u039c": "M",  # Μ
    "\u039d": "N",  # Ν
    "\u039f": "O",  # Ο
    "\u03a1": "P",  # Ρ
    "\u03a4": "T",  # Τ
    "\u03a7": "X",  # Χ
    "\u0396": "Z",  # Ζ
}

# Scripts that matter for mixed-script detection. Anything else alphabetic
# (Armenian, Hebrew, Arabic, ...) is grouped as OTHER.
_SCRIPT_RANGES = [
    (0x0041, 0x007A, "LATIN"),
    (0x00C0, 0x00FF, "LATIN"),
    (0x0100, 0x017F, "LATIN"),
    (0x0370, 0x03FF, "GREEK"),
    (0x0400, 0x04FF, "CYRILLIC"),
    (0x0500, 0x052F, "CYRILLIC"),
    (0x0530, 0x058F, "ARMENIAN"),
    (0x0590, 0x05FF, "HEBREW"),
    (0x0600, 0x06FF, "ARABIC"),
    (0x0900, 0x097F, "DEVANAGARI"),
    (0x3040, 0x30FF, "JAPANESE"),
    (0x4E00, 0x9FFF, "CJK"),
    (0xAC00, 0xD7AF, "HANGUL"),
]


def _script_of(char: str) -> str | None:
    """Script of one character, or None for digits/punctuation."""
    if not char.isalpha():
        return None
    code = ord(char)
    for start, end, name in _SCRIPT_RANGES:
        if start <= code <= end:
            return name
    # Fall back to the Unicode character name, e.g. "CYRILLIC ...".
    name = unicodedata.name(char, "")
    return name.split(" ")[0] if name else "OTHER"


def decode_idna(host: str) -> str:
    """Decode punycode (xn--) labels to Unicode, label by label.

    Returns the host unchanged when it is already plain text or a label
    cannot be decoded. Uses only the standard library ``idna`` codec.
    """
    if "xn--" not in host:
        return host
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                labels.append(label.encode("ascii").decode("idna"))
            except Exception:
                labels.append(label)
        else:
            labels.append(label)
    return ".".join(labels)


def skeleton(text: str) -> str:
    """Replace every known homoglyph with its Latin look-alike."""
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in text)


# ASCII look-alikes: characters (or pairs) that impersonate a Latin letter
# without leaving ASCII at all — 'rn' for 'm', '0' for 'o', '1' for 'l'.
# Applied left to right so "rn" is consumed as one unit.
_ASCII_LOOKALIKES = {"0": "o", "1": "l", "5": "s"}


def ascii_skeleton(text: str) -> str:
    """Replace ASCII look-alike spellings with the letters they imitate."""
    out: list[str] = []
    i = 0
    while i < len(text):
        two = text[i:i + 2]
        if two == "rn":
            out.append("m")
            i += 2
        elif two == "vv":
            out.append("w")
            i += 2
        else:
            out.append(_ASCII_LOOKALIKES.get(text[i], text[i]))
            i += 1
    return "".join(out)


def edit_distance(a: str, b: str) -> int:
    """Levenshtein distance between two short strings (stdlib only)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(
                prev[j] + 1,          # deletion
                cur[j - 1] + 1,       # insertion
                prev[j - 1] + (ca != cb),  # substitution
            ))
        prev = cur
    return prev[-1]


def scripts_present(text: str) -> set[str]:
    """Set of scripts used by the letters in the text."""
    return {s for ch in text if (s := _script_of(ch))}


def analyze_host(host: str, brands: list[str],
                   strong_brands: list[str] | None = None) -> dict:
    """Confusable analysis of one host name.

    Three mechanisms, all brand-gated (a look-alike only counts when it
    resolves to a known brand):
    1. Unicode homoglyphs — a Cyrillic/Greek letter impersonating Latin.
    2. ASCII look-alikes — 'rn' for 'm', '0' for 'o', '1' for 'l'.
    3. Near-miss — a domain label one edit away from a heavily
       impersonated brand (e.g. 'paypol' for 'paypal').

    Returns {"decoded_host", "skeleton_host", "has_confusable",
    "mixed_script", "confusable_brand", "mechanism", "chars",
    "raw_label", "skeleton_label"}.
    "chars" lists the exact homoglyph characters found, each as
    {"char", "looks_like", "script"} — used to explain the trick in
    plain language.
    """
    decoded = decode_idna(host)
    skel = ascii_skeleton(skeleton(decoded))
    has_mapped = any(ch in HOMOGLYPHS for ch in decoded)
    scripts = scripts_present(decoded)
    mixed = len(scripts) > 1

    chars = []
    for ch in decoded:
        if ch in HOMOGLYPHS:
            name = unicodedata.name(ch, "")
            chars.append({
                "char": ch,
                "looks_like": HOMOGLYPHS[ch],
                "script": name.split(" ")[0].capitalize() if name else "non-Latin",
            })

    decoded_lower = decoded.lower()
    skel_lower = skel.lower()
    confusable_brand = ""
    mechanism = ""
    raw_label = ""
    skeleton_label = ""
    for brand in brands:
        if brand in skel_lower and brand not in decoded_lower:
            confusable_brand = brand
            mechanism = "homoglyph" if has_mapped else "ascii"
            # The label that carries the trick, for the explanation.
            for raw, sk in zip(decoded_lower.split("."), skel_lower.split(".")):
                if brand in sk and brand not in raw:
                    raw_label, skeleton_label = raw, sk
                    break
            break
    if not confusable_brand and strong_brands:
        # Near-miss: one edit away from a heavily impersonated brand.
        for label in skel_lower.split("."):
            if len(label) < 4:
                continue
            for brand in strong_brands:
                if edit_distance(label, brand) == 1:
                    confusable_brand = brand
                    mechanism = "near-miss"
                    raw_label, skeleton_label = label, brand
                    break
            if confusable_brand:
                break

    return {
        "decoded_host": decoded,
        "skeleton_host": skel,
        "has_confusable": bool(has_mapped or mixed),
        "mixed_script": mixed,
        "confusable_brand": confusable_brand,
        "mechanism": mechanism,
        "chars": chars,
        "raw_label": raw_label,
        "skeleton_label": skeleton_label,
    }
