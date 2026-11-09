#!/usr/bin/env python3
"""
Train the PhishLens Random Forest and evaluate it honestly.

Data:
  - Phishing: PhishTank verified online URLs (data/online-valid.csv).
  - Benign: Tranco top-1M domains (data/top-1m.csv.zip), turned into full
    URLs (see build_benign_urls). This construction is a known limitation:
    benign URLs are synthesised from domain names, so their paths are
    simpler than real browsing. It is documented in the README and on the
    metrics page, and the rule-based detector (which needs no training
    data) is reported alongside as a cross-check.

Splits: 70/15/15, stratified as far as grouping allows, grouped by
registered domain so no domain leaks between train/validation/test.

Outputs (detector/model_artifacts/):
  - model.joblib   — trained RandomForestClassifier
  - metrics.json   — real holdout metrics, thresholds, dataset notes

Usage:  python scripts/train.py [--phish N] [--benign N]
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from augment import build_augmentation  # noqa: E402
from detector import features, rules  # noqa: E402

DATA_DIR = ROOT / "data"
ARTIFACT_DIR = ROOT / "detector" / "model_artifacts"

RANDOM_STATE = 42

# Paths used to turn bare Tranco domains into realistic full URLs.
# Deliberately varied in depth (0–3 segments) and length: the first
# version of this list was too shallow, and the model learned the
# artefact "any path deeper than one folder = phishing" — which flagged
# ordinary pages like wikipedia.org/wiki/Phishing. Real browsing has
# deep paths, so the benign set must too.
BENIGN_PATH_TEMPLATES = [
    ("", 0.30), ("/", 0.12),
    ("/about", 0.03), ("/products", 0.02), ("/blog", 0.02),
    ("/contact", 0.02), ("/support", 0.02), ("/help", 0.01),
    ("/news", 0.01), ("/shop", 0.01), ("/services", 0.01),
    ("/privacy", 0.01), ("/terms", 0.01), ("/faq", 0.01),
    ("/careers", 0.01), ("/sitemap.xml", 0.005),
    ("/wiki/{word}_{word}", 0.03), ("/wiki/{word}", 0.02),
    ("/blog/{year}/{month}/{slug}", 0.03),
    ("/blog/{slug}", 0.02),
    ("/products/{category}/{slug}", 0.03),
    ("/products/{slug}", 0.01),
    ("/category/{category}/{slug}", 0.02),
    ("/search", 0.02),
    ("/user/{name}", 0.01), ("/u/{name}", 0.01),
    ("/watch", 0.01), ("/item/{num}", 0.01),
    ("/p/{num}/{slug}", 0.01),
    ("/article/{slug}", 0.02),
    ("/questions/{num}/{slug}", 0.01),
    ("/docs/{slug}/{slug2}", 0.01),
    ("/docs/{slug}", 0.01),
    ("/profile/{name}", 0.01),
    ("/store/{category}", 0.01),
    ("/news/{year}/{slug}", 0.01),
    ("/{category}", 0.02),
    ("/{category}/{slug}", 0.02),
    # Legitimate pages that contain "sensitive" words in normal contexts —
    # real sites have login and account pages, and Wikipedia has
    # Computer_security. Without these, the model learns that the mere
    # presence of such a word means phishing.
    ("/login", 0.01), ("/signin", 0.005),
    ("/account/settings", 0.01), ("/account/{slug}", 0.005),
    ("/help/security", 0.005), ("/security/{slug}", 0.005),
    ("/wiki/{word}_security", 0.005),
    ("/{word}_{word}", 0.01),
    # Product codes and numeric IDs, as on real shops and trackers.
    ("/dp/{code10}", 0.01), ("/product/{code10}", 0.01),
    ("/item/{code10}", 0.005),
]
BENIGN_QUERIES = [
    ("", 0.70),
    ("?lang=en", 0.04), ("?q={word}", 0.04), ("?search={word}", 0.03),
    ("?id={num}", 0.03), ("?page={small}", 0.03),
    ("?utm_source=google", 0.03), ("?utm_medium=social", 0.02),
    ("?ref=homepage", 0.02), ("?s={word}", 0.02),
    ("?query={word}+{word}", 0.01), ("?v={code}", 0.01),
    ("?tab=overview", 0.01), ("?sort=popular", 0.01),
]
BENIGN_SUBDOMAINS = [
    ("", 0.33), ("www.", 0.38),
    ("blog.", 0.04), ("shop.", 0.04), ("support.", 0.04),
    ("docs.", 0.03), ("app.", 0.03), ("news.", 0.02),
    ("help.", 0.02), ("mail.", 0.01), ("store.", 0.01),
    ("en.", 0.03), ("m.", 0.01), ("api.", 0.01), ("cdn.", 0.01),
]
_PATH_WORDS = [
    "guide", "review", "best", "how-to", "tips", "news", "update",
    "getting-started", "introduction", "overview", "features",
    "pricing", "download", "tutorial", "example", "report", "analysis",
    "photos", "video", "music", "health", "travel", "food", "tech",
    "science", "history", "python", "design", "market", "world",
]
_PATH_CATEGORIES = [
    "electronics", "books", "clothing", "sports", "home", "garden",
    "toys", "beauty", "shoes", "phones", "laptops", "furniture",
]
_PATH_NAMES = ["alex", "sara", "mike", "emma", "john", "lisa", "david", "anna"]


def _fill_path_template(template: str, rng: random.Random) -> str:
    slug = "-".join(rng.sample(_PATH_WORDS, 2))
    slug2 = rng.choice(_PATH_WORDS)
    return template.format(
        word=rng.choice(_PATH_WORDS),
        slug=slug,
        slug2=slug2,
        category=rng.choice(_PATH_CATEGORIES),
        name=rng.choice(_PATH_NAMES),
        year=rng.choice(["2024", "2025", "2026"]),
        month=f"{rng.randint(1, 12):02d}",
        num=rng.randint(100, 999999),
        small=rng.randint(1, 9),
        code="".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=11)),
        code10="".join(rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=10)),
    )


def _fill_query(query: str, rng: random.Random) -> str:
    return query.format(
        word=rng.choice(_PATH_WORDS),
        num=rng.randint(100, 999999),
        small=rng.randint(1, 9),
        code="".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=11)),
    )


# Well-known shorteners appear in the phishing feed constantly and never in
# Tranco, so a model trained on raw feeds learns "shortener = phishing"
# with near-certainty — and then flags every ordinary bit.ly link. A
# small set of synthetic benign shortener URLs (random slugs, no
# destination implied) breaks that perfect correlation. Documented as a
# de-biasing step in the README and metrics page.
BENIGN_SHORTENER_DOMAINS = [
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
    "rb.gy", "cutt.ly",
]


def load_phishing(max_n: int) -> list[str]:
    df = pd.read_csv(DATA_DIR / "online-valid.csv", usecols=["url", "verified", "online"])
    df = df[(df["verified"] == "yes") & (df["online"] == "yes")]
    urls = df["url"].dropna().astype(str).tolist()
    urls = [u.strip() for u in urls if u.strip()]
    # Dedupe by full URL, then cap per registered domain so one compromised
    # host cannot dominate the class.
    seen: set[str] = set()
    by_domain: Counter = Counter()
    kept: list[str] = []
    for u in urls:
        if u in seen:
            continue
        reg = features.registered_domain_of(u)
        if not reg:
            continue
        if by_domain[reg] >= 5:
            continue
        seen.add(u)
        by_domain[reg] += 1
        kept.append(u)
        if len(kept) >= max_n:
            break
    return kept


def build_benign_urls(max_n: int, rng: random.Random) -> list[str]:
    with zipfile.ZipFile(DATA_DIR / "top-1m.csv.zip") as z:
        name = z.namelist()[0]
        with z.open(name) as fh:
            domains = []
            for line in fh:
                parts = line.decode().strip().split(",")
                if len(parts) == 2 and parts[1]:
                    domains.append(parts[1].strip().lower())
                if len(domains) >= 100_000:
                    break
    paths, weights = zip(*BENIGN_PATH_TEMPLATES)
    subdomains, sub_weights = zip(*BENIGN_SUBDOMAINS)
    queries, query_weights = zip(*BENIGN_QUERIES)
    urls: list[str] = []
    seen: set[str] = set()
    for domain in domains:
        if len(urls) >= max_n:
            break
        host = rng.choices(subdomains, weights=sub_weights, k=1)[0] + domain
        path = _fill_path_template(
            rng.choices(paths, weights=weights, k=1)[0], rng)
        query = _fill_query(
            rng.choices(queries, weights=query_weights, k=1)[0], rng)
        scheme = "https" if rng.random() < 0.9 else "http"
        url = f"{scheme}://{host}{path}{query}"
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)
    # De-biasing: a few benign shortener URLs (see note above).
    for i in range(240):
        short_domain = BENIGN_SHORTENER_DOMAINS[i % len(BENIGN_SHORTENER_DOMAINS)]
        slug = "".join(rng.choices(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            k=rng.randint(6, 8)))
        urls.append(f"https://{short_domain}/{slug}")
    return urls


# Mainstream generic endings with heavy legitimate use (the same set that
# lives in features.COMMON_TLDS, minus the old/common ones the top-100k
# already covers). Used for the de-biasing top-up below.
MAINSTREAM_NEW_GTLDS = {
    "online", "site", "shop", "live", "tech", "info", "business",
    "center", "study", "country", "stream", "support", "party",
    "science", "link", "today", "fit", "club", "work", "fun", "racing",
}


def build_benign_mainstream_gtld_urls(max_n: int, rng: random.Random) -> list[str]:
    """Benign URLs on mainstream new gTLDs, from Tranco ranks 100k–1M.

    The main benign set comes from the Tranco top 100k, which is almost
    all .com/.org/.net — so the model almost never sees a LEGITIMATE
    .online/.site/.shop site in training, and learns "unusual ending =
    phishing". That flagged Toolixy itself as High risk (Nov 9). These
    extra real domains (genuine sites ranked in the top 1M, just below
    the top 100k cut) teach the model that mainstream new endings host
    real sites. Same URL synthesis as build_benign_urls; the domains are
    real, only the paths are synthesised.
    """
    with zipfile.ZipFile(DATA_DIR / "top-1m.csv.zip") as z:
        name = z.namelist()[0]
        with z.open(name) as fh:
            domains = []
            for i, line in enumerate(fh):
                if i < 100_000:
                    continue
                parts = line.decode().strip().split(",")
                if len(parts) == 2 and parts[1]:
                    domain = parts[1].strip().lower()
                    suffix = domain.rsplit(".", 1)[-1]
                    if suffix in MAINSTREAM_NEW_GTLDS:
                        domains.append(domain)
                if len(domains) >= max_n * 4:
                    break
    rng.shuffle(domains)
    paths, weights = zip(*BENIGN_PATH_TEMPLATES)
    subdomains, sub_weights = zip(*BENIGN_SUBDOMAINS)
    queries, query_weights = zip(*BENIGN_QUERIES)
    urls: list[str] = []
    seen: set[str] = set()
    for domain in domains:
        if len(urls) >= max_n:
            break
        host = rng.choices(subdomains, weights=sub_weights, k=1)[0] + domain
        path = _fill_path_template(
            rng.choices(paths, weights=weights, k=1)[0], rng)
        query = _fill_query(
            rng.choices(queries, weights=query_weights, k=1)[0], rng)
        scheme = "https" if rng.random() < 0.9 else "http"
        url = f"{scheme}://{host}{path}{query}"
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return urls


def extract_matrix(urls: list[str]) -> tuple[np.ndarray, list[str], list[str]]:
    """Feature matrix + registered domains (for group splitting)."""
    rows = []
    regs = []
    skipped = 0
    for u in urls:
        try:
            f = features.extract_features(u)
        except Exception:
            skipped += 1
            continue
        rows.append([float(f[n]) for n in features.FEATURE_NAMES])
        regs.append(f["_meta"]["registered_domain"])
    if skipped:
        print(f"  skipped {skipped} unparseable URLs")
    return np.array(rows, dtype=float), regs, urls


def level_accuracy(y_true: np.ndarray, scores: np.ndarray,
                   low_max: int, medium_max: int) -> float:
    pred = np.array([rules.level_for_score(int(round(s)), low_max, medium_max)
                     for s in scores])
    return float((pred == y_true).mean())


def tune_thresholds(y_true_levels: np.ndarray, scores: np.ndarray) -> tuple[int, int, float]:
    """Grid-search the two thresholds on the validation set.

    Truth has only High (phishing) and Low (benign), so plain accuracy
    favours a razor-thin Medium band. Among pairs within 0.5pp of the
    best validation accuracy, pick the widest Medium band — a usable
    "be careful" zone — instead of the degenerate optimum.
    """
    results = []
    for low in range(5, 60, 5):
        for med in range(low + 10, 96, 5):
            acc = level_accuracy(y_true_levels, scores, low, med)
            results.append((acc, low, med))
    best_acc = max(r[0] for r in results)
    near_best = [r for r in results if r[0] >= best_acc - 0.005]
    # Widest Medium band; tie-break toward the higher Medium cut.
    acc, low, med = max(near_best, key=lambda r: (r[2] - r[1], r[2]))
    return low, med, acc


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--phish", type=int, default=10_000)
    ap.add_argument("--benign", type=int, default=10_000)
    args = ap.parse_args()

    rng = random.Random(RANDOM_STATE)
    np.random.seed(RANDOM_STATE)

    print("Loading PhishTank phishing URLs ...")
    phish_urls = load_phishing(args.phish)
    print(f"  {len(phish_urls)} phishing URLs")

    print("Building benign URLs from Tranco ...")
    benign_urls = build_benign_urls(args.benign, rng)
    extra_benign = build_benign_mainstream_gtld_urls(1500, rng)
    benign_urls = benign_urls + extra_benign
    print(f"  {len(benign_urls)} benign URLs "
          f"(incl. {len(extra_benign)} on mainstream new gTLDs)")

    # Drop any benign domain that also appears as a phishing domain.
    phish_regs = {features.registered_domain_of(u) for u in phish_urls}
    benign_urls = [u for u in benign_urls
                   if features.registered_domain_of(u) not in phish_regs]
    print(f"  {len(benign_urls)} benign URLs after removing overlaps with phishing domains")

    print("Extracting features ...")
    Xp, regs_p, _ = extract_matrix(phish_urls)
    Xb, regs_b, _ = extract_matrix(benign_urls)
    X = np.vstack([Xp, Xb])
    y = np.array([1] * len(Xp) + [0] * len(Xb))
    groups = np.array(regs_p + regs_b)
    print(f"  matrix {X.shape}, phishing={int(y.sum())}, benign={int((1 - y).sum())}")

    # 70 / 15 / 15 grouped split.
    gss = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=RANDOM_STATE)
    train_idx, temp_idx = next(gss.split(X, y, groups))
    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=RANDOM_STATE)
    val_rel, test_rel = next(gss2.split(X[temp_idx], y[temp_idx], groups[temp_idx]))
    val_idx, test_idx = temp_idx[val_rel], temp_idx[test_rel]
    print("  splits:",
          f"train={len(train_idx)} (phish {int(y[train_idx].sum())}),",
          f"val={len(val_idx)} (phish {int(y[val_idx].sum())}),",
          f"test={len(test_idx)} (phish {int(y[test_idx].sum())})")

    print("Training Random Forest ...")
    # Synthetic augmentation — TRAINING SPLIT ONLY (see scripts/augment.py).
    # The deep tricks are rare in the real feeds, so the model is taught
    # them with seeded synthetic phishing URLs. Validation and test are
    # untouched, so the holdout metrics stay honest.
    aug_urls, aug_counts = build_augmentation(rng)
    X_aug, _, _ = extract_matrix(aug_urls)
    print(f"  augmentation: {len(aug_urls)} generated, {X_aug.shape[0]} "
          f"usable, added to the training split only: {aug_counts}")
    X_train = np.vstack([X[train_idx], X_aug])
    y_train = np.concatenate(
        [y[train_idx], np.ones(len(X_aug), dtype=int)])
    print(f"  training rows: {len(X_train)} "
          f"(phish {int(y_train.sum())})")

    # Slim forest: the full 250-tree model is too heavy for a 512 MB free
    # container (first SHAP call compiles numba and spikes RAM, and live
    # checks hang). 120 trees keeps the accuracy; verified by retraining.
    clf = RandomForestClassifier(
        n_estimators=120, max_depth=18, min_samples_leaf=2,
        class_weight="balanced_subsample", n_jobs=-1,
        random_state=RANDOM_STATE,
    )
    clf.fit(X_train, y_train)

    # --- Validation: tune thresholds on the combined score ---
    val_proba = clf.predict_proba(X[val_idx])[:, 1]
    val_rule = np.array([rules.evaluate_rules(
        dict(zip(features.FEATURE_NAMES, row)))["score"] for row in X[val_idx]])
    val_combined = 0.5 * val_rule + 0.5 * val_proba * 100
    val_levels = np.where(y[val_idx] == 1, "High", "Low")
    low_max, medium_max, val_acc = tune_thresholds(val_levels, val_combined)
    print(f"  tuned thresholds: Low<={low_max}, Medium<={medium_max} "
          f"(validation 3-level accuracy {val_acc:.3f})")

    # --- Test: report real holdout metrics, once ---
    test_proba = clf.predict_proba(X[test_idx])[:, 1]
    test_pred = (test_proba >= 0.5).astype(int)
    test_rule = np.array([rules.evaluate_rules(
        dict(zip(features.FEATURE_NAMES, row)))["score"] for row in X[test_idx]])
    test_combined = 0.5 * test_rule + 0.5 * test_proba * 100
    test_pred_levels = np.array([rules.level_for_score(int(round(s)), low_max, medium_max)
                                 for s in test_combined])
    test_rule_levels = np.array([rules.level_for_score(int(round(s)), low_max, medium_max)
                                 for s in test_rule])
    test_true_levels = np.where(y[test_idx] == 1, "High", "Low")
    # Binary view of the headline verdict: High vs not-High.
    test_high_pred = test_pred_levels == "High"
    test_high_true = y[test_idx] == 1

    tn, fp, fn, tp = confusion_matrix(y[test_idx], test_pred).ravel()
    metrics = {
        "dataset": {
            "phishing_source": "PhishTank online-valid.csv (verified=yes, online=yes)",
            "phishing_count": len(phish_urls),
            "benign_source": "Tranco top-1m.csv.zip (top 100k domains, full URLs synthesised with realistic paths) + 240 synthetic benign shortener URLs (de-biasing step) + 1,500 benign URLs on mainstream new gTLDs (.online/.site/.shop/.tech/...) from Tranco ranks 100k-1M (Nov 9 de-biasing: the top-100k set almost never shows a legitimate new-gTLD site, which taught the model that those endings mean phishing)",
            "benign_count": len(benign_urls),
            "collected": "2026-11-09",
            "features": len(features.FEATURE_NAMES),
            "augmentation": {
                "applied_to": "training split only (never validation or test)",
                "generated": len(aug_urls),
                "usable": int(X_aug.shape[0]),
                "counts": aug_counts,
                "method": "Seeded synthetic phishing URLs (scripts/augment.py) "
                          "teaching the model the deep tricks that are rare "
                          "in the real feeds: homoglyph/ASCII/near-miss brand "
                          "mutations, '@'-trick decoys, file-extension TLDs, "
                          "open-redirect laundering, invisible Unicode "
                          "characters, and login pages on free hosting.",
            },
        },
        "splits": {
            "train": len(train_idx), "validation": len(val_idx), "test": len(test_idx),
            "grouped_by": "registered domain (no domain leaks across splits)",
            "train_phishing": int(y[train_idx].sum()),
            "validation_phishing": int(y[val_idx].sum()),
            "test_phishing": int(y[test_idx].sum()),
        },
        "model": {
            "type": "RandomForestClassifier",
            "params": {"n_estimators": 120, "max_depth": 18,
                       "min_samples_leaf": 2,
                       "class_weight": "balanced_subsample"},
            "test_accuracy": round(float(accuracy_score(y[test_idx], test_pred)), 4),
            "test_precision": round(float(precision_score(y[test_idx], test_pred)), 4),
            "test_recall": round(float(recall_score(y[test_idx], test_pred)), 4),
            "test_f1": round(float(f1_score(y[test_idx], test_pred)), 4),
            "test_roc_auc": round(float(roc_auc_score(y[test_idx], test_proba)), 4),
            "test_false_positive_rate": round(float(fp / max(tn + fp, 1)), 4),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp),
                                 "fn": int(fn), "tp": int(tp)},
        },
        "rule_detector": {
            "test_accuracy_3level": round(
                float((test_rule_levels == test_true_levels).mean()), 4),
            "note": "Rule score alone, mapped with the tuned thresholds.",
        },
        "combined": {
            "test_accuracy_3level": round(
                float((test_pred_levels == test_true_levels).mean()), 4),
            "test_high_false_alarm_rate": round(
                float((test_high_pred & (y[test_idx] == 0)).sum()
                      / max(int((y[test_idx] == 0).sum()), 1)), 4),
            "test_high_recall": round(
                float((test_high_pred & test_high_true).sum()
                      / max(int(test_high_true.sum()), 1)), 4),
            "note": "Headline score = 0.5 * rule score + 0.5 * model "
                    "probability * 100. '3-level accuracy' counts a Medium "
                    "verdict as wrong because the test truth has only High "
                    "(phishing) and Low (benign); the High false-alarm "
                    "rate and recall describe the headline verdict fairly.",
        },
        "thresholds": {"low_max": low_max, "medium_max": medium_max,
                       "validation_accuracy": round(val_acc, 4)},
        "feature_importance": [
            {"feature": features.FEATURE_NAMES[i],
             "importance": round(float(v), 4)}
            for i, v in sorted(enumerate(clf.feature_importances_),
                               key=lambda t: -t[1])[:10]
        ],
        "limitations": [
            "Benign URLs are synthesised from Tranco domain names, so their "
            "paths are simpler than real browsing; the model may partly key "
            "on URL length. The rule-based detector needs no training data "
            "and is reported alongside as a cross-check.",
            "URL-only analysis cannot catch phishing hosted on legitimate or "
            "compromised domains.",
            "PhishTank skews toward freshly reported, short-lived phishing "
            "pages; performance on older or targeted attacks may differ.",
        ],
    }

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    import joblib
    joblib.dump(clf, ARTIFACT_DIR / "model.joblib")
    (ARTIFACT_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2))

    print("\n==== HOLDOUT (TEST) METRICS — RANDOM FOREST ====")
    m = metrics["model"]
    for k in ("test_accuracy", "test_precision", "test_recall", "test_f1",
              "test_roc_auc", "test_false_positive_rate"):
        print(f"  {k}: {m[k]}")
    print(f"  confusion: TN={tn} FP={fp} FN={fn} TP={tp}")
    print(f"  rule-only 3-level accuracy: {metrics['rule_detector']['test_accuracy_3level']}")
    print(f"  combined 3-level accuracy: {metrics['combined']['test_accuracy_3level']}")
    print(f"  combined High false-alarm rate: {metrics['combined']['test_high_false_alarm_rate']}")
    print(f"  combined High recall: {metrics['combined']['test_high_recall']}")
    print("Artifacts saved to", ARTIFACT_DIR)


if __name__ == "__main__":
    main()
