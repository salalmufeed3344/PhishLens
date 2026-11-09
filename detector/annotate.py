"""Exhibit annotation for PhishLens.

The forensic-lab signature move: circle the forgery on the address
itself. Given a checked URL, the triggered rules and the trick details
from :func:`detector.model.check_url`, this module works out which
character ranges of the URL each rule fired on, and returns the URL
split into segments plus a numbered margin-note list.

Rules that describe the whole address (very long, digit-heavy, random
looking) have no single place to circle: they still get a margin note,
but no circle. When two rules point at the same characters, the
heaviest rule owns the circle and the other note says so.

Invisible characters are replaced in the displayed text with ``␣``
(U+2423) so the visitor can see that something is there at all; the
result notes this under the exhibit. The returned text is raw — the
template escapes it, so nothing here is markup.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from .features import KEYWORD_WEIGHTS

# Characters that are invisible (or change display order) in most fonts.
_INVISIBLE = set(
    list(range(0x200B, 0x2010))  # zero-width space/joiners, LRM/RLM...
    + list(range(0x202A, 0x2030))  # bidi overrides and isolates
    + list(range(0x2060, 0x2065))  # word joiner, invisible operators
    + [0xFEFF]  # byte-order mark
)
INVISIBLE_REPLACEMENT = "\u2423"  # ␣ open box

_COMMON_TLDS = (".com", ".net", ".org", ".co", ".io", ".xyz", ".info")


def _host_span(parsed) -> tuple[int, int] | None:
    """Character range of the host inside the raw URL string."""
    host = parsed.hostname
    if not host:
        return None
    # hostname is lowercased by urlparse; the netloc keeps its case.
    start = parsed.netloc.lower().find(host)
    if start < 0:
        return None
    base = len(parsed.scheme) + 3  # "scheme://"
    return (base + start, base + start + len(host))


def _find(haystack: str, needle: str, start: int = 0) -> tuple[int, int] | None:
    if not needle:
        return None
    i = haystack.lower().find(needle.lower(), start)
    if i < 0:
        return None
    return (i, i + len(needle))


def _spans_for_rule(rule_id: str, url: str, parsed, tricks: dict) -> list[tuple[int, int]]:
    """Character ranges in ``url`` that the rule fired on (possibly empty)."""
    host_span = _host_span(parsed)
    host = parsed.hostname or ""
    spans: list[tuple[int, int]] = []

    if rule_id == "R01" or rule_id == "R04" or rule_id == "R18":
        if host_span:
            spans.append(host_span)
    elif rule_id == "R02":
        at = url.find("@")
        if at >= 0:
            spans.append((at, at + 1))
    elif rule_id == "R03":
        if host_span:
            for label in host.split("."):
                if label.startswith("xn--"):
                    s = _find(url, label, host_span[0])
                    if s:
                        spans.append(s)
    elif rule_id in ("R05a", "R05b", "R05c", "R06a", "R06b", "R06c"):
        # The brand word, wherever it sits in the host. For a look-alike
        # the literal brand is not in the URL at all (that is the trick),
        # so fall back to the label that carries it.
        conf = tricks.get("confusable") or {}
        brand = conf.get("confusable_brand", "")
        span = None
        if brand and host_span:
            span = _find(url, brand, host_span[0])
        if not span and host_span:
            for label in (conf.get("raw_label", ""), tricks.get("typosquat_label", "")):
                if label:
                    span = _find(url, label, host_span[0])
                    if span:
                        break
        if not span and host_span:
            # Last resort: any known brand word inside the host.
            from .features import BRANDS

            for candidate in BRANDS:
                if candidate in host.lower():
                    span = _find(url, candidate, host_span[0])
                    if span:
                        break
        if span:
            spans.append(span)
    elif rule_id == "R07":
        # The subdomain chain: host up to the registered domain.
        reg = (tricks.get("confusable") or {}).get("decoded_host", host)
        if host_span and reg and host.lower().endswith(reg.lower()):
            sub = host[: len(host) - len(reg)].rstrip(".")
            if sub:
                s = _find(url, sub, host_span[0])
                if s:
                    spans.append(s)
    elif rule_id in ("R10a", "R10b", "R10c"):
        hits = tricks.get("keyword_hits") or []
        if not hits:
            hits = [w for w in KEYWORD_WEIGHTS if w in url.lower()]
        # Longest first so "sign-in" wins over "sign"; cap the circles.
        for word in sorted(hits, key=len, reverse=True)[:4]:
            start = 0
            while True:
                s = _find(url, word, start)
                if not s:
                    break
                spans.append(s)
                start = s[1]
                if len(spans) >= 4:
                    break
            if len(spans) >= 4:
                break
    elif rule_id in ("R13", "R27"):
        if host_span:
            tld = "." + host.rsplit(".", 1)[-1] if "." in host else ""
            s = _find(url, tld, host_span[0]) if tld else None
            if s:
                spans.append(s)
    elif rule_id == "R14":
        if parsed.port:
            s = _find(url, f":{parsed.port}", host_span[0] if host_span else 0)
            if s:
                spans.append(s)
    elif rule_id == "R15":
        path_start = url.find("/", len(parsed.scheme) + 3)
        if path_start >= 0:
            i = url.find("//", path_start + 1)
            if i >= 0:
                spans.append((i, i + 2))
    elif rule_id == "R17":
        spans.extend((m.start(), m.end()) for m in re.finditer(r"%[0-9A-Fa-f]{2}", url))
    elif rule_id == "R21":
        if host_span:
            for tld in _COMMON_TLDS:
                i = url.lower().find(tld, host_span[0])
                # The embedded ending is not the host's own final TLD.
                if 0 <= i < host_span[1] - len(tld):
                    spans.append((i, i + len(tld)))
                    break
    elif rule_id == "R22":
        chars = ((tricks.get("confusable") or {}).get("chars") or [])
        for entry in chars:
            ch = entry.get("char", "")
            if not ch:
                continue
            s = _find(url, ch, host_span[0] if host_span else 0)
            if s:
                spans.append(s)
        if not spans:
            # Fall back to any non-ASCII character in the host.
            for i, ch in enumerate(url):
                if host_span and host_span[0] <= i < host_span[1] and ord(ch) > 127:
                    spans.append((i, i + 1))
    elif rule_id == "R23":
        if host_span:
            for i, ch in enumerate(url):
                if host_span[0] <= i < host_span[1] and ord(ch) > 127:
                    spans.append((i, i + 1))
    elif rule_id == "R24":
        at = url.find("@")
        if at >= 0:
            scheme_end = len(parsed.scheme) + 3
            spans.append((scheme_end, at))
    elif rule_id == "R25":
        label = tricks.get("typosquat_label", "")
        if label and host_span:
            s = _find(url, label, host_span[0])
            if s:
                spans.append(s)
    elif rule_id == "R26":
        target = tricks.get("redirect_target", "")
        if target:
            s = _find(url, target)
            if not s:
                # The target may be URL-encoded; fall back to its host.
                try:
                    target_host = urlparse(target).hostname or ""
                except ValueError:
                    target_host = ""
                if target_host:
                    s = _find(url, target_host)
            if s:
                spans.append(s)
    elif rule_id == "R28":
        for i, ch in enumerate(url):
            if ord(ch) in _INVISIBLE:
                spans.append((i, i + 1))
    elif rule_id == "R29":
        free_host = tricks.get("free_host", "")
        if free_host and host_span:
            s = _find(url, free_host, host_span[0])
            if s:
                spans.append(s)
    # R08, R09, R11, R12, R16, R19, R20 describe the whole address and
    # have no single place to circle: no spans on purpose.
    return spans


def _display_text(url: str) -> tuple[str, bool]:
    """URL with invisible characters replaced by a visible box."""
    has_invisible = any(ord(ch) in _INVISIBLE for ch in url)
    if not has_invisible:
        return url, False
    return "".join(
        INVISIBLE_REPLACEMENT if ord(ch) in _INVISIBLE else ch for ch in url
    ), True


def annotate_url(url: str, tricks: dict | None, triggered: list[dict]) -> dict:
    """Split ``url`` into segments and number the margin notes.

    Returns {"segments": [{"text": str, "mark": int | None}], ...,
    "annotations": [{"num": int, "rule_id": str, "name": str,
    "message": str, "weight": int, "circle": int | None,
    "shares": int | None}], "has_invisible": bool}.

    ``mark`` on a segment is the annotation number circled there.
    ``circle`` on an annotation is its own number when at least one of
    its spans is drawn; ``shares`` names the number it shares a circle
    with when its spans all overlap a heavier rule's circle.
    """
    tricks = tricks or {}
    display, has_invisible = _display_text(url)
    # Spans are computed against the original URL: the display text
    # replaces invisible characters 1:1, so indices still line up, but
    # only the original contains the invisible characters to find.
    parsed = urlparse(url)

    # Candidate spans per annotation, in triggered (weight) order.
    wanted: list[tuple[int, int, int]] = []  # (start, end, num)
    annotations: list[dict] = []
    for num, rule in enumerate(triggered, start=1):
        spans = _spans_for_rule(rule["id"], url, parsed, tricks)
        for start, end in spans:
            wanted.append((start, end, num))
        annotations.append({
            "num": num,
            "rule_id": rule["id"],
            "name": rule["name"],
            "message": rule["message"],
            "weight": rule["weight"],
            "circle": None,
            "shares": None,
        })

    # Resolve overlaps by precision first: the shortest span is the
    # most specific finding (one homoglyph letter beats the whole
    # look-alike label), ties broken by weight (lowest number first).
    # The winning rule owns the circle; the others share it.
    wanted.sort(key=lambda item: (item[1] - item[0], item[2]))
    kept: list[tuple[int, int, int]] = []  # (start, end, num)
    by_num: dict[int, list[tuple[int, int]]] = {}
    for start, end, num in wanted:
        if any(start < k_end and end > k_start for k_start, k_end, _ in kept):
            continue
        kept.append((start, end, num))
        by_num.setdefault(num, []).append((start, end))
    kept.sort()

    for ann in annotations:
        spans = by_num.get(ann["num"], [])
        if spans:
            ann["circle"] = ann["num"]
        else:
            # Did any of its spans overlap a kept circle? Name it.
            own = _spans_for_rule(
                ann["rule_id"], url, parsed, tricks
            )
            for start, end in own:
                for k_start, k_end, k_num in kept:
                    if start < k_end and end > k_start:
                        ann["shares"] = k_num
                        break
                if ann["shares"] is not None:
                    break

    # Build segments from the kept spans.
    segments: list[dict] = []
    pos = 0
    for start, end, num in kept:
        if start > pos:
            segments.append({"text": display[pos:start], "mark": None})
        segments.append({"text": display[start:end], "mark": num})
        pos = end
    if pos < len(display):
        segments.append({"text": display[pos:], "mark": None})
    if not segments:
        segments.append({"text": display, "mark": None})

    return {
        "segments": segments,
        "annotations": annotations,
        "has_invisible": has_invisible,
    }
