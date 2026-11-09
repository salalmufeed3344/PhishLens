# PhishLens — Explainable Phishing URL Detection

[![CI](https://github.com/salalmufeed3344/PhishLens/actions/workflows/ci.yml/badge.svg)](https://github.com/salalmufeed3344/PhishLens/actions/workflows/ci.yml)

Paste a suspicious link. PhishLens analyses the **URL text alone** — it never
opens, downloads, or visits the link — and returns a risk verdict (Low /
Medium / High), a 0–100 score, and plain-language reasons why.

**Live demo:** https://phishlens.deployxa.online
**Built for:** IceHacks 2026 (Nov 9–16, 2026)

Most link checkers give a verdict and nothing else. PhishLens shows its work:
every triggered rule with its weight, and the model's reasoning translated
from SHAP attributions into plain sentences — so you can see exactly which
part of the address is suspicious, and learn the trick behind it.

## How it works

1. **Feature extraction** (`detector/features.py`) — 45 features from the URL
   string only: lengths, dots and subdomains, special characters (`@`,
   hyphens, underscores, `//` in the path, percent-encoding, digit ratio),
   host signals (IP-as-host, non-default port, punycode, link shortener,
   TLD category), sensitive keywords and brand names in the wrong place,
   Shannon entropy, longest digit run, vowel–consonant ratio, and HTTP vs
   HTTPS (a weak signal — see below). Domain parsing uses `tldextract`.
   The same pass runs the **deep-trick checks** (next section): the `@`
   decoy, typosquat / brand edit-distance, open-redirect laundering,
   file-extension TLDs, invisible Unicode characters, free-hosting login
   pages, and homoglyph / confusable-letter detection
   (`detector/confusables.py`).
2. **Rule-based detector** (`detector/rules.py`) — 29 weighted, documented
   indicators. Every triggered rule is listed with its weight and a
   plain-language sentence.
3. **Random Forest** (`scripts/train.py`, `detector/model.py`) — trained on
   verified PhishTank phishing URLs and Tranco top domains. Outputs a
   phishing probability.
4. **Explanations** (`detector/explain.py`) — SHAP (TreeExplainer)
   attributions from the model, translated into plain sentences, plus the
   triggered rules.
5. **Headline score** = 0.5 × rule score + 0.5 × model probability × 100.
   Verdict thresholds (Low ≤ 25, Medium ≤ 35) are tuned on the validation
   set, not hand-picked.

## Deep attacker tricks — one paste, every check

Most people only know the obvious signs (misspelled brand, plain HTTP).
These are the tricks that actually fool people — each is a named rule with
a one-line plain-language explainer on the result page:

| Check | What it catches | Example |
|---|---|---|
| The `@` trick (R24) | Everything before `@` is ignored by the browser; the visible address is a decoy | `google.com@evil.com` really goes to evil.com |
| Typosquat (R25) | Domain 1–2 letters from a top brand | `paypaI`, `gooogle`, `arnazon` |
| Open-redirect laundering (R26) | Link starts on a trusted site's redirector, ends elsewhere | `google.com/url?q=evil…` |
| File-extension TLD (R27) | The domain ending is a file extension, not a file | `invoice.zip` is a website |
| Invisible characters (R28) | Bidi-override / zero-width characters change what you see | Text that displays differently from the real address |
| Free-hosting login (R29) | A login page on a platform anyone can publish on | `paypal-login.firebaseapp.com` |
| Homoglyphs (R22–R23) | Look-alike letters from another alphabet impersonating a brand | Cyrillic `а` for Latin `a` in `paypal` |

**HTTPS does not mean safe.** Most phishing sites now use HTTPS — the
result page says so plainly, and the model treats HTTPS as a weak signal
only. A padlock means the connection is encrypted, not that the site is
honest.

## Results

Real holdout results (test set, 3,117 URLs — 1,419 phishing, 1,698 benign),
printed by `scripts/train.py` and saved to
`detector/model_artifacts/metrics.json`. Not rounded up, not cherry-picked.

| Metric | Value |
|---|---|
| Accuracy | **0.912** |
| Precision | **0.935** |
| Recall | **0.866** |
| F1 | **0.899** |
| ROC-AUC | **0.971** |
| False-positive rate | **0.051** |
| Headline verdict (combined score) | 3-level accuracy **0.846**, High false-alarm rate **0.022**, High recall **0.749** |

| | |
|---|---|
| Phishing | PhishTank `online-valid.csv`, verified + online, collected 2026-11-09 (~9,500 sampled, max 5 URLs per registered domain) |
| Benign | Tranco top-1M list (top 100k domains), turned into full URLs with realistic paths; see *Limitations* |
| Split | 70 / 15 / 15, **grouped by registered domain** (no domain leaks across splits) |
| Model | RandomForestClassifier (120 trees, max depth 18), 45 features |
| Augmentation | 890 seeded synthetic phishing URLs (homoglyph / typosquat / `@`-trick / file-extension TLD / open-redirect / invisible-character / free-hosting) added to the **training split only** — never validation or test |

## Try it

**Live:** https://phishlens.deployxa.online — paste any link, get a verdict.

**Run locally:**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/train.py        # trains from data/ (~2 minutes)
python manage.py runserver     # http://127.0.0.1:8000/
```

**Docker** (what the live demo runs):

```bash
docker build -t phishlens .
docker run -p 8000:8000 -e DJANGO_SECRET_KEY=<random-value> phishlens
```

Pages: `/` (checker), `/metrics` (live holdout metrics),
`POST /api/check` (JSON: `{"url": "..."}` → verdict, scores, rules,
SHAP reasons).

No login, no data stored, no secrets. The submitted URL is never rendered
as a clickable link.

## Tests

```bash
python -m pytest
```

83 tests: unit tests for feature extraction and rules, plus end-to-end
tests of the checker flow and the JSON API — including one test per deep
trick (each must score High) and a regression test that mainstream endings
(`.online`, `.site`, `.tech`, `.shop`) score Low.

## Limitations (read before trusting the model)

- **Benign URLs are synthesised.** Tranco gives domain names, not full
  URLs, so paths are generated from templates. The templates were
  calibrated against real URLs (Wikipedia, Amazon, GitHub, YouTube,
  Stack Overflow), but synthesised benign data can never fully match real
  browsing. The rule-based detector needs no training data and is
  reported alongside as a cross-check.
- **Mainstream endings need real examples.** The top-100k benign set is
  almost all `.com` / `.org` / `.net`, so the model initially learned
  that an unusual ending means phishing — and flagged a legitimate
  `.online` site as High risk. The fix: mainstream endings
  (`.online`, `.site`, `.shop`, `.tech`, `.info`, …) are excluded from
  the suspicious-TLD list, and 1,500 benign URLs on those endings from
  Tranco ranks 100k–1M were added to training. The regression test above
  locks this in.
- **Shorteners.** Phishing feeds are full of shortener links; Tranco has
  none. 240 synthetic benign shortener URLs (random slugs) were added to
  break the perfect correlation. An unknown shortened link still scores
  Medium/High — that is the honest verdict for a link whose destination
  is hidden.
- **URL-only analysis cannot catch phishing hosted on legitimate or
  compromised domains.** Results are an estimate of risk, not a
  guarantee, and the UI says so.
- **PhishTank skews toward freshly reported, short-lived phishing pages.**
  Performance on older or targeted attacks may differ.

## Project layout

```
phishlens/            Django project (settings, urls)
detector/
  features.py         URL feature extraction (shared by training + serving)
  confusables.py      homoglyph / look-alike letter detection (hand-written)
  rules.py            weighted rule-based detector
  explain.py          SHAP → plain-language sentences
  model.py            model loading, combined scoring, check_url()
  views.py            home / check / metrics / api/check
  templates/detector/ home, result, metrics pages
  static/detector/    warm-paper CSS (no gradients, no purple)
  model_artifacts/    model.joblib (git-ignored, 14 MB) + metrics.json
  tests/              pytest suite (83 tests)
scripts/train.py      dataset build + training + evaluation + threshold tuning
scripts/augment.py    seeded synthetic phishing URLs (training split only)
data/                 raw downloads (git-ignored): PhishTank CSV, Tranco zip
Dockerfile            python:3.12-slim, trains at build, gunicorn + WhiteNoise
```

## Credits

Keyword and brand weights are adapted from the scoring lists in
x0rz/phishing_catcher (GPL-3.0, `suspicious.yaml`, 2017–2024) — generic
trigger words, brand tiers (30–70), sketchy TLDs, embedded-TLD and
near-miss tricks — rescaled to our 0–100 scale. No phishing_catcher code
is used; only its published scoring lists informed the numbers. The
homoglyph mapping (`detector/confusables.py`) is hand-written from
Unicode code points. Phishing data: PhishTank. Benign domains: Tranco.
