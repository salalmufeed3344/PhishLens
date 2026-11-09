# DESIGN.md — PhishLens

Direction: **Forensic document lab** (seed:985b9651b6cafb9b). Chosen by the
founder over the roll's assigned banknote direction. Built 2026-11-09.

## The world

PhishLens is the examiner's bench. The visitor brings a document — a link —
they suspect is forged, and the page examines it in the open, circling each
forgery in red pencil and writing the finding in the margin. The verdict is
never a bare number; the evidence is the page.

## Palette

- Ground: pale cool-grey evidence paper `#f2f3ef`. Surface: white.
- Ink `#191c18`, soft ink `#44483f`, muted ink `#5c6156` (5.7:1 on paper).
- One red, the examiner's pencil: `#b42318` (5.9:1 on paper). It circles
  findings, carries the High/danger state, and is the only accent.
- State colours on the same palette: Low green `#1f6b2e`, Medium amber
  `#8a5a00`. Every text colour meets 4.5:1 on its ground (verified).

## Type

A precise system grotesque for the interface; monospace for the address
itself and all data — the URL is evidence and is set like evidence.
Headings carry their own weight (no eyebrow above them). Body measure is
capped at 60–65ch; `text-wrap: pretty` keeps orphan words off last lines.
Numbers in tables and scores use tabular figures.

## Density and structure

Hairline rules separate sections; there are no cards and no nested boxes.
The metrics page is a table, not a hero-metric grid. The two detectors are
a table, not two boxes. The advice is a ruled panel with a small square
marker — never a coloured side border. Browser surfaces are themed from
the palette: red text selection, red caret in the address field, red focus
rings, quiet scrollbars.

## The signature move

**Exhibit A.** On the result page the checked URL is shown large in mono
as "the address as received", and each finding is circled on it in red
pencil with a superscript number. The margin notes below carry the same
numbers: rule id, name, weight, and the plain-language reason. A rule
that shares its characters with a heavier finding says so ("Circled with
2 — the same characters"). A rule that describes the whole address says
so instead ("No single place to circle"). Invisible characters are shown
as ␣ so the visitor can see that something is there at all. The
annotation is computed by `detector/annotate.py` (10 tests): spans are
resolved by precision first — one homoglyph letter beats the whole
look-alike label — ties broken by weight.

## Motion

One authored moment: the loading panel's pulse while a check runs.
Nothing else moves.

## Verification (2026-11-09, local)

- 97 tests pass (87 existing + 10 annotation tests).
- Impeccable detector: source scan `[]`; rendered scans of home and
  metrics `[]` (zero findings, after fixing contrast, line length, the
  side-border, stragglers, and the footer measure).
- Screenshots: home, fake-PayPal result, homoglyph result, clean result,
  metrics, 404, home mobile, result mobile — all in
  `hidden_files/previews/lab-*.png`.
- Known limits: the result page is POST-only, so the detector could not
  scan it rendered — it was checked visually instead. The pencil circle
  is a CSS ellipse, not a drawn stroke; it reads as a neat ellipse.
- WhiteNoise caches static in memory when DEBUG=False: a running server
  serves stale CSS after collectstatic until it is restarted.

## Polish pass (2026-11-09, evening — unslop audit + Impeccable re-check)

Scope was light slop, so polish mode inside this world, no new direction.
The audit's real finds: every heading rendered at weight 700 because no
font-weight was set (the browser default did the shouting); about twenty
spacing values sat off the 4px grid (13px, 22px, 26px, 30px, 34px…);
the verdict badge was a full pill; the Exhibit A label was uppercase with
wide tracking; the lede used italic for emphasis; the loading bar animated
width. Fixed: headings 500, emphasis 600 max, all spacing on the 4px
grid, badge as a quiet 6px tag, label in sentence case, emphasis by weight
and colour, bar fill on transform scaleX with one easing curve
(cubic-bezier(0.22, 1, 0.36, 1)). The font family stays the system
grotesque stack on purpose — no webfont dependency, works offline. The
pulse on the active loading step stays: it marks a genuinely live state.
Re-verified after the pass: 97 tests, Impeccable source `[]`, rendered
home `[]`, rendered metrics `[]`, fresh lab-*.png screenshots.
