# DESIGN.md — PhishLens

Direction: **E2 — Stripe-based, de-slopped** (from the Stripe DESIGN.md in
VoltAgent/awesome-design-md, via mockup E, de-slopped to E2). Chosen by the
founder 2026-11-09. Built 2026-11-09.

## The world

PhishLens is a plain, professional tool page: white canvas, one indigo
action colour, verdicts in solid colour, everything in ruled rows and
tables. No mesh, no gradient, no decorative dots, no three-card rows, no
cream bands. The page reads like a real company's product page — the
examiner's evidence (Exhibit A, below) survives inside it, restyled.

## Palette

- Canvas `#FFFFFF`, ink `#0A1F33`, secondary `#334155`, muted `#64748B`.
- Soft band `#F2F6FC`, hairline `#D8E2EF`.
- Accent indigo `#4338CA` — the CTA pill and inline links only, never
  body text.
- HIGH ruby `#C0352B`, LOW green `#157347`. **Medium is indigo
  `#4338CA` — there is no amber anywhere in the design.** The Medium
  badge, the gauge fill at Medium, and any Medium text all use indigo,
  so the three states are ruby / indigo / green and nothing else.
- Every text colour meets 4.5:1 on its ground (verified).

## Type

- Inter, embedded as data URIs in style.css (variable font, weight
  range 100–900; no Google Fonts, no external font requests): H1 56px weight
  300, tracking −1.4px; body 17px weight 400; headings 500; emphasis
  600 max. Tabular numerals (`font-feature-settings: "tnum"`) on all
  scores and table figures.
- JetBrains Mono, embedded the same way, for the URL and all data — the address is
  evidence and is set like evidence.
- Body measure capped at 60–65ch (lede 62ch, step paragraphs 60ch,
  reason lists 60ch, Data &amp; splits description column 50ch);
  `text-wrap: pretty` keeps orphan words off last lines.

## Density and structure

- ~1200px container, 64–96px section padding, full-width 1440px
  viewport. No narrow centred column.
- Hairline rules separate sections; there are no cards except the
  checker form and the example-result card (both hairline + Level 1
  shadow, no nested boxes). The metrics page is tables. The two
  detectors are a table. How it works is three ruled rows 01/02/03 —
  never three cards. The tricks list is a two-column hairline list with
  no decorative dots. The HTTPS note is a plain white panel with a small
  solid ruby square. The advice is a ruled panel with a small square
  marker — never a coloured side border. Browser surfaces are themed
  from the palette: indigo text selection, indigo caret in the address
  field, indigo focus rings, quiet scrollbars, tabular numerals.

## The signature move

**Exhibit A** (carried over from the forensic-lab design, restyled).
On the result page the checked URL is shown large in mono as "the
address as received", and each finding is circled on it in red pencil
(now ruby `#C0352B`, same hand-drawn border-radius technique) with a
superscript number. The margin notes below carry the same numbers:
rule id, name, weight, and the plain-language reason. A rule that shares
its characters with a heavier finding says so ("Circled with 2 — the
same characters"). A rule that describes the whole address says so
instead ("No single place to circle"). Invisible characters are shown
as ␣ so the visitor can see that something is there at all. The
annotation is computed by `detector/annotate.py` (10 tests): spans are
resolved by precision first — one homoglyph letter beats the whole
look-alike label — ties broken by weight.

## The home page example card

The hero's right-hand card is a **static example result, hardcoded in
the template — the home page never runs the model on load.** It shows
the fake-PayPal example (`http://paypal-secure-login.com/verify/account/update`):
HIGH 61/100, rule 49, model 72.6%, findings R06a +26 / R10a +12 / R12 +6 /
R08 +5, labelled "Example check". Those numbers are a snapshot of a real
live check (deployment ec0fae8f, 9 Nov 2026); the live model retrains on
each deploy, so a fresh check of the same URL can score a few points
differently. The card is clearly labelled as an example and exists so
the verdict is visible on the home page itself.

## Legal pages

Four plain pages — `/privacy`, `/cookies`, `/terms`, `/about` (no
trailing slash, matching `/metrics`) — served by one `legal_page` view
in `detector/views.py`. Short, honest, plain-language content: no
accounts, pasted URLs analysed and discarded, the only cookie is
Django's CSRF security cookie, verdicts are guidance not guarantees,
and the About page states the URL-only promise and links to the repo.

## History: the forensic-lab look (2026-11-09, superseded)

The first redesign was a forensic document lab: pale cool-grey paper
`#f2f3ef`, ink `#191c18`, examiner's pencil red `#b42318`, moss-free,
system grotesque + mono, hairline rules, metrics as tables, Exhibit A
as the signature move. It shipped live (deployment 2d8f7f99) and passed
a polish pass the same evening (headings 500, spacing on the 4px grid,
badge as a quiet tag, scaleX progress bar). The founder's verdict on
screenshots was that it still looked fishy itself — dead white space
from the narrow 760px column, serif-ish small letters — and asked for a
full professional redesign with mockups first. Four mockups (A Harbour,
B Watchtower, C Ledger, D Signal) and the Stripe-based direction E were
built and screenshotted; E was picked, de-slopped into E2, and E2 is
what this file now describes. The forensic-lab world is gone; Exhibit A
and the WhiteNoise lesson below survive it.

## Verification (2026-11-09, local — E2)

- 97 tests pass; `python manage.py check` clean. No Python logic
  changed for the redesign (only the 4 legal views added); all form
  ids, the home JavaScript, the progress panel, badge markup, SHAP
  sections, feature breakdown, and "Check another link" are untouched.
- Impeccable detector: source scan — 2 "overused-font" warnings for
  Inter (deliberate: Inter is what the Stripe DESIGN.md specifies and
  what the founder picked; the skill's note about Inter being common
  is acknowledged and overruled by the direction). Rendered scans of
  home and metrics — after fixes, only the same Inter warning remains:
  an em-dash advisory (9 in the home copy) was fixed by rewording the
  lede and the example-card footnote (now 6); three line-length
  warnings on the How-it-works steps were fixed by capping the step
  paragraphs at 60ch; three more on the metrics page were fixed by
  capping the reason lists at 60ch and the Data &amp; splits
  description column at 50ch.
- Screenshots: home, fake-PayPal result (High 59 locally — the local
  model scores a few points below the live snapshot), metrics, privacy,
  home mobile at 390px — all in `hidden_files/previews/e2-*.png`.
  Mobile: single column, nav links hide, checker button full width,
  metrics-table columns get 12px gutters so they never touch.
- Known limits: the result page is POST-only, so the detector could
  not scan it rendered — it was checked visually instead. The pencil
  circle is a CSS ellipse, not a drawn stroke; it reads as a neat
  ellipse. Django template comments `{# ... #}` must be single-line —
  a multi-line comment renders as literal text (verified against
  Django 5.1.4's lexer); the home template's developer note is one
  line for that reason.
- WhiteNoise caches static in memory when DEBUG=False: a running
  server serves stale CSS after collectstatic until it is restarted.
  The manifest storage (`CompressedManifestStaticFilesStorage`) gives
  the stylesheet a content-hashed filename, so a redeploy changes the
  URL and the edge cache cannot serve the old design.
