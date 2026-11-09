# PhishLens — Explainable Phishing URL Detection System

Paste a suspicious link. PhishLens analyses the **URL text alone** — it never
opens, downloads or visits the link — and returns a risk verdict (Low /
Medium / High), a 0–100 score, and plain-language reasons why.

Built for **IceHacks 2026** (Nov 9–16, 2026). The same code is the final-year
project *“Explainable Phishing URL Detection System”* (BS Computer Science,
Abdul Wali Khan University Mardan) — so it is built properly in Django, not
as throwaway hackathon code. The FYP extras (3-model comparison, user survey,
thesis) continue after the hackathon; this repo is the hackathon slice:
rule-based detector + one Random Forest + SHAP explanations + web UI.

## How it works

1. **Feature extraction** (`detector/features.py`) — 45 features from the URL
   string only: lengths, dots/subdomains, special characters (`@`, hyphens,
   underscores, `//` in path, percent-encoding, digit ratio), host signals
   (IP-as-host, non-default port, punycode, link shortener, TLD category),
   sensitive keywords and brand names in the wrong place, Shannon entropy,
   longest digit run, vowel–consonant ratio, and HTTP vs HTTPS (weak signal).
   Domain parsing uses `tldextract`. On top of the proposal's features, one
   paste also runs the **deep-trick checks** (see below): the `@` decoy,
   typosquat / brand edit-distance, open-redirect laundering, file-extension
   TLDs, invisible Unicode characters, free-hosting login pages, and
   homoglyph / confusable-letter detection (`detector/confusables.py`).
2. **Rule-based detector** (`detector/rules.py`) — 29 weighted, documented
   indicators. Every triggered rule is listed with its weight and a
   plain-language sentence.
3. **Random Forest** (`scripts/train.py`, `detector/model.py`) — trained on
   verified PhishTank phishing URLs and Tranco top domains. Outputs a
   phishing probability.
4. **Explanations** (`detector/explain.py`) — SHAP (TreeExplainer) attributions
   from the model, translated into plain sentences, plus the triggered rules.
5. **Headline score** = 0.5 × rule score + 0.5 × model probability × 100.
   Low/Medium/High thresholds are tuned on the validation set (see below).

## Deep attacker tricks — one paste, every check

Most people only know the obvious signs (misspelled brand, HTTP). These
are the tricks judges and users usually *don't* know about — each is a
named rule with a one-line plain-language explainer on the result page:

| Check | What it catches | Example |
|---|---|---|
| The `@` trick (R24) | Everything before `@` is ignored by the browser; the visible address is a decoy | `google.com@evil.com` really goes to evil.com |
| Typosquat (R25) | Domain 1–2 letters from a top brand | `paypaI`, `gooogle`, `arnazon` |
| Open-redirect laundering (R26) | Link starts on a trusted site's redirector, ends elsewhere | `google.com/url?q=evil…` |
| File-extension TLD (R27) | The domain ending is a file extension, not a file | `invoice.zip` is a website |
| Invisible characters (R28) | Bidi-override / zero-width characters change what you see | text that displays differently from the real address |
| Free-hosting login (R29) | A login page on a platform anyone can publish on | `paypal-login.firebaseapp.com` |
| Homoglyphs (R22–R23) | Look-alike letters from another alphabet impersonating a brand | Cyrillic `а` for Latin `a` in `paypal` |

**HTTPS does not mean safe.** Most phishing sites now use HTTPS — the
result page says so plainly, and the model treats HTTPS as a weak signal
only (a padlock means the connection is encrypted, not that the site is
honest).

Weight provenance: the keyword and brand weights are adapted from the
battle-tested scoring lists in x0rz/phishing_catcher (GPL-3.0,
`suspicious.yaml`, 2017–2024) — generic trigger words, brand tiers
(30–70), sketchy TLDs, embedded-TLD and near-miss tricks — rescaled to
our 0–100 scale. No phishing_catcher code is used; only its published
scoring lists informed the numbers. The homoglyph mapping
(`detector/confusables.py`) is hand-written from Unicode code points.

## Run it

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/train.py        # downloads nothing new; trains from data/
python manage.py runserver     # http://127.0.0.1:8000/
```

Pages: `/` (checker), `/metrics` (real holdout metrics), `POST /api/check`
(JSON: `{"url": "..."}` → verdict, scores, rules, SHAP reasons).

No login, no data stored, no secrets. The submitted URL is never rendered
as a clickable link.

## Data & honest metrics

| | |
|---|---|
| Phishing | PhishTank `online-valid.csv`, verified + online, collected 2026-11-09 (~9,500 sampled, max 5 URLs per registered domain) |
| Benign | Tranco top-1M list (top 100k domains), turned into full URLs with realistic paths; see *Bias notes* |
| Split | 70 / 15 / 15, stratified as far as grouping allows, **grouped by registered domain** (no domain leaks across splits) |
| Model | RandomForestClassifier (250 trees, max depth 24), 45 features |
| Augmentation | 890 seeded synthetic phishing URLs (homoglyph / typosquat / `@`-trick / file-extension TLD / open-redirect / invisible-character / free-hosting) added to the **training split only** — never validation or test; see *Bias notes* |

Real holdout results (test set, 2,841 URLs) — see `/metrics` for the live
numbers after training:

- Accuracy **0.910**, precision **0.929**, recall **0.878**, F1 **0.903**,
  ROC-AUC **0.971**, false-positive rate **0.060**
- Headline verdict: High false-alarm rate **0.046**, High recall **0.842**

These are the numbers from the latest training run, printed by
`scripts/train.py` and saved to `detector/model_artifacts/metrics.json`.
They are not rounded up and not cherry-picked: the same script that trains
the model prints them.

## Bias notes (read before trusting the model)

- **Benign URLs are synthesised.** Tranco gives domain names, not full
  URLs, so paths are generated from templates. The first version of those
  templates was too shallow and too query-heavy: the model learned the
  artefacts “any path deeper than one folder = phishing” and “no query
  string = phishing”, and flagged ordinary pages (e.g.
  `wikipedia.org/wiki/Phishing`). The templates were fixed — deeper paths,
  product codes, login/account pages, and a realistic ~30% query rate —
  and the fix was verified against real URLs (Wikipedia, Amazon, GitHub,
  YouTube, Stack Overflow) before the model shipped. The residual risk is
  real: synthesised benign data can never fully match real browsing.
- **Shorteners.** Phishing feeds are full of shortener links; Tranco has
  none. 240 synthetic benign shortener URLs (random slugs) were added to
  break the perfect correlation. An unknown shortened link still scores
  Medium/High — that is the honest verdict for a link whose destination
  is hidden.
- **Synthetic augmentation.** The deep tricks are rare in the real feeds,
  so 890 seeded synthetic phishing URLs (scripts/augment.py) teach the
  model those signals. They go into the training split only — validation
  and test contain zero synthetic URLs, so the holdout metrics stay
  honest. The rule-based detector needs no training data and catches the
  same tricks regardless.
- **URL-only analysis cannot catch phishing hosted on legitimate or
  compromised domains.** Results are an estimate of risk, not a guarantee,
  and the UI says so.
- **PhishTank skews toward freshly reported, short-lived phishing pages.**
  Performance on older or targeted attacks may differ.

## Tests

```bash
python -m pytest
```

Unit tests for feature extraction and rules, plus end-to-end tests of the
checker flow and the JSON API (including that a submitted URL is never
rendered as a clickable link).

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
  model_artifacts/    model.joblib (git-ignored, 38 MB) + metrics.json
  tests/              pytest suite
scripts/train.py      dataset build + training + evaluation + threshold tuning
scripts/augment.py    seeded synthetic phishing URLs (training split only)
data/                 raw downloads (git-ignored): PhishTank CSV, Tranco zip
```

## Deployment

Not part of this repo step. The app is a standard Django project; the
deploy target for IceHacks is DeployXA (Django cannot run on Netlify).
`model.joblib` is git-ignored (binary, 38 MB) — a deploy must either copy
it from this checkout or run `python scripts/train.py` on the host
(datasets are public downloads, training takes ~2 minutes).
