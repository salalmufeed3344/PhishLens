"""
Trained-model wrapper for PhishLens.

Loads the Random Forest saved by scripts/train.py (joblib) together with
its metrics and tuned thresholds. Falls back to rule-based-only operation
when no model artifact is present, and says so in the result.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import joblib

from . import explain, features, rules

BASE_DIR = Path(__file__).resolve().parent
ARTIFACT_DIR = BASE_DIR / "model_artifacts"
MODEL_PATH = ARTIFACT_DIR / "model.joblib"
METRICS_PATH = ARTIFACT_DIR / "metrics.json"

_lock = threading.Lock()
_model = None
_metrics = None
_explainer = None
_model_error: str | None = None


def _load_metrics() -> dict:
    global _metrics
    if _metrics is None:
        try:
            _metrics = json.loads(METRICS_PATH.read_text())
        except Exception:
            _metrics = {}
    return _metrics


def model_available() -> bool:
    return MODEL_PATH.exists()


def model_error() -> str | None:
    return _model_error


def load_model():
    """Load (once per process) the trained Random Forest."""
    global _model, _model_error
    if _model is not None:
        return _model
    with _lock:
        if _model is not None:
            return _model
        if not MODEL_PATH.exists():
            _model_error = "No trained model found — rule-based check only."
            return None
        try:
            _model = joblib.load(MODEL_PATH)
        except Exception as exc:  # corrupt / incompatible artifact
            _model_error = f"Trained model could not be loaded: {exc}"
            return None
        return _model


def get_thresholds() -> tuple[int, int]:
    """(low_max, medium_max) — tuned values if present, else defaults."""
    m = _load_metrics()
    t = m.get("thresholds", {})
    return (
        int(t.get("low_max", rules.DEFAULT_LOW_MAX)),
        int(t.get("medium_max", rules.DEFAULT_MEDIUM_MAX)),
    )


def get_metrics() -> dict:
    return _load_metrics()


def _shap_values(model, vector: list[float]):
    """SHAP values for the phishing class (index 1) for one sample."""
    global _explainer
    import numpy as np
    import shap

    if _explainer is None:
        with _lock:
            if _explainer is None:
                _explainer = shap.TreeExplainer(model)
    X = np.array([vector], dtype=float)
    explanation = _explainer(X)
    values = explanation.values
    # shap >= 0.44: values shape (n_samples, n_features, n_classes)
    # older / single-output: (n_samples, n_features)
    if values.ndim == 3:
        return values[0, :, 1]
    return values[0]


def check_url(raw_url: str) -> dict:
    """Full analysis of one URL. Returns everything the UI and API need.

    Never raises for a bad URL — validation errors are returned as a dict
    with "error" set, so views stay simple.
    """
    try:
        feats = features.extract_features(raw_url)
    except features.URLValidationError as exc:
        return {"error": str(exc)}

    meta = feats.pop("_meta")
    vector = [float(feats[name]) for name in features.FEATURE_NAMES]

    # Details for dynamic rule messages: the confusable analysis plus
    # the deep-trick findings, so a triggered rule can name the exact
    # trick ("the 'a' in 'paypal' is actually a Cyrillic letter").
    details = dict(meta["confusable"])
    details.update({
        "at_decoy": (meta["at_trick"] or {}).get("decoy", ""),
        "at_real_host": (meta["at_trick"] or {}).get("real_host", ""),
        "typosquat_brand": meta["typosquat_brand"],
        "typosquat_label": meta["typosquat_label"],
        "typosquat_distance": meta["typosquat_distance"],
        "redirect_host": meta["registered_domain"],
        "redirect_target": meta["redirect_target"],
        "file_ext_tld": meta["tld"],
        "invisible_kinds": meta["invisible_kinds"],
        "free_host": meta["free_host"],
    })
    rule_result = rules.evaluate_rules(feats, details)
    low_max, medium_max = get_thresholds()
    rule_level = rules.level_for_score(rule_result["score"], low_max, medium_max)

    model = load_model()
    model_prob = None
    model_level = None
    shap_reasons = {"raised": [], "lowered": []}
    shap_top: list[dict] = []
    if model is not None:
        try:
            import numpy as np

            proba = model.predict_proba(np.array([vector], dtype=float))[0]
            # class order is [0, 1]; take index of class 1
            idx = list(model.classes_).index(1)
            model_prob = round(float(proba[idx]) * 100, 1)
            model_level = rules.level_for_score(int(round(model_prob)), low_max, medium_max)
            try:
                sv = _shap_values(model, vector)
                shap_top = explain.top_contributions(
                    sv, features.FEATURE_NAMES, vector, top_n=6
                )
                shap_reasons = explain.shap_to_sentences(shap_top)
            except Exception:
                shap_reasons = {"raised": [], "lowered": []}
                shap_top = []
        except Exception:
            model_prob = None
            model_level = None

    # Headline score: average of the two detectors when both exist,
    # otherwise whichever exists. Weights are documented in the README.
    if model_prob is not None:
        final_score = int(round(0.5 * rule_result["score"] + 0.5 * model_prob))
    else:
        final_score = rule_result["score"]
    final_level = rules.level_for_score(final_score, low_max, medium_max)

    feature_rows = [
        {
            "name": name,
            "description": features.FEATURE_DESCRIPTIONS.get(name, name),
            "value": feats[name],
        }
        for name in features.FEATURE_NAMES
    ]

    advice = {
        "Low": "This address shows few warning signs, but stay alert: a "
               "clean-looking link can still be unsafe if it arrived "
               "unexpectedly. When in doubt, type the site's address "
               "yourself instead of clicking.",
        "Medium": "This address has several warning signs. Do not enter "
                  "passwords, card details or codes on it. If you were "
                  "expecting this link, reach the site by typing its "
                  "address yourself or through its official app.",
        "High": "Do not open this link, and do not enter any personal "
                "information on it. If you received it by email or "
                "message, report it as phishing and delete it.",
    }[final_level]

    return {
        "error": None,
        "url": meta["url"],
        "scheme_assumed": meta["scheme_assumed"],
        "host": meta["host"],
        "registered_domain": meta["registered_domain"],
        "final_score": final_score,
        "final_level": final_level,
        "rule_score": rule_result["score"],
        "rule_level": rule_level,
        "rule_triggered": rule_result["triggered"],
        "model_probability": model_prob,
        "model_level": model_level,
        "model_available": model is not None,
        "model_error": _model_error,
        "shap_reasons": shap_reasons,
        "shap_top": shap_top,
        "features": feature_rows,
        "tricks": {
            "at_trick": meta["at_trick"],
            "typosquat_brand": meta["typosquat_brand"],
            "typosquat_label": meta["typosquat_label"],
            "redirect_target": meta["redirect_target"],
            "invisible_kinds": meta["invisible_kinds"],
            "free_host": meta["free_host"],
            "confusable": meta["confusable"],
            "keyword_hits": meta["keyword_hits"],
        },
        "advice": advice,
    }
