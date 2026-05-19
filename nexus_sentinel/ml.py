from __future__ import annotations

from functools import lru_cache

import numpy as np


_FEATURE_SPECS = (
    (
        "url_length",
        "Link length",
        "Longer links can hide the real destination inside extra text.",
        lambda features, _content, _redirect: min(
            float(features.get("url_length", 0)) / 120.0, 1.0
        ),
    ),
    (
        "no_https",
        "No HTTPS",
        "Pages without HTTPS can expose anything you type, including passwords.",
        lambda features, _content, _redirect: 0.0
        if features.get("uses_https", False)
        else 1.0,
    ),
    (
        "ip_hostname",
        "Raw IP address",
        "Legitimate services usually use readable names instead of raw server IPs.",
        lambda features, _content, _redirect: 1.0
        if features.get("is_ip_hostname", False)
        else 0.0,
    ),
    (
        "subdomain_count",
        "Extra subdomains",
        "A pile of subdomains can be used to mimic a trusted brand name.",
        lambda features, _content, _redirect: min(
            float(features.get("subdomain_count", 0)) / 5.0, 1.0
        ),
    ),
    (
        "hostname_hyphen_count",
        "Hyphen-heavy hostname",
        "Attackers often stuff fake brand wording into long hyphenated domains.",
        lambda features, _content, _redirect: min(
            float(features.get("hostname_hyphen_count", 0)) / 4.0, 1.0
        ),
    ),
    (
        "path_depth",
        "Deep path",
        "Deep paths can make a suspicious link look messier and harder to inspect.",
        lambda features, _content, _redirect: min(
            float(features.get("path_depth", 0)) / 6.0, 1.0
        ),
    ),
    (
        "encoded_characters",
        "Encoded characters",
        "Encoded text can disguise what a link really points to.",
        lambda features, _content, _redirect: 1.0
        if features.get("has_encoded_characters", False)
        else 0.0,
    ),
    (
        "high_risk_tld",
        "Unusual website ending",
        "Cheap and disposable website endings are used heavily in phishing campaigns.",
        lambda features, _content, _redirect: 1.0
        if features.get("has_suspicious_tld", False)
        else 0.0,
    ),
    (
        "suspicious_keywords",
        "Suspicious words",
        "Words like secure, verify, or login are common social-engineering bait.",
        lambda features, _content, _redirect: min(
            float(len(features.get("suspicious_keywords", ()))) / 3.0, 1.0
        ),
    ),
    (
        "many_query_parameters",
        "Many query items",
        "Very busy links can be used to hide tracking or disguise the destination.",
        lambda features, _content, _redirect: min(
            float(features.get("query_parameter_count", 0)) / 6.0, 1.0
        ),
    ),
    (
        "login_form",
        "Login form detected",
        "A login prompt on a suspicious page can be there to steal credentials.",
        lambda _features, content, _redirect: 1.0
        if content.get("login_form_detected") is True
        else 0.0,
    ),
    (
        "password_field",
        "Password field detected",
        "A password field on a suspicious page is a major credential theft signal.",
        lambda _features, content, _redirect: 1.0
        if content.get("password_field_detected") is True
        else 0.0,
    ),
    (
        "urgency_language",
        "Urgent wording",
        "Phishing pages often create panic so people stop thinking carefully.",
        lambda _features, content, _redirect: 1.0
        if content.get("urgency_language_detected") is True
        else 0.0,
    ),
    (
        "external_scripts",
        "Outside scripts",
        "Code pulled from other sites can be a sign of a hastily assembled page.",
        lambda _features, content, _redirect: 1.0
        if content.get("external_scripts_detected") is True
        else 0.0,
    ),
    (
        "cross_domain_redirect",
        "Cross-site redirect",
        "A redirect to another domain can hide where the link really ends up.",
        lambda _features, _content, redirect: 1.0
        if redirect.get("cross_domain_redirect_detected") is True
        else 0.0,
    ),
    (
        "suspicious_redirect_chain",
        "Suspicious redirect chain",
        "Multiple redirects are often used to obscure the final destination.",
        lambda _features, _content, redirect: 1.0
        if redirect.get("suspicious_redirect_chain") is True
        else 0.0,
    ),
)


def build_ml_analysis(
    extracted_features: dict[str, object],
    content_analysis: dict[str, object],
    redirect_analysis: dict[str, object],
) -> dict[str, object]:
    vector = _feature_vector(extracted_features, content_analysis, redirect_analysis)
    model_bundle = _get_model_bundle()

    if model_bundle is None:
        return {
            "status": "unavailable",
            "model_name": "RandomForestClassifier",
            "prediction_probability": None,
            "predicted_classification": None,
            "explanation_method": None,
            "top_signals": [],
            "notes": "The optional machine learning model is unavailable in this environment.",
        }

    model, training_means = model_bundle
    probability = float(model.predict_proba(vector.reshape(1, -1))[0][1])
    predicted_classification = _classify_probability(probability)
    explanation = _build_explanation(model, vector, training_means)

    return {
        "status": "available",
        "model_name": "RandomForestClassifier",
        "prediction_probability": round(probability * 100, 1),
        "predicted_classification": predicted_classification,
        "explanation_method": explanation["method"],
        "top_signals": explanation["signals"],
        "notes": explanation["notes"],
    }


def _feature_vector(
    extracted_features: dict[str, object],
    content_analysis: dict[str, object],
    redirect_analysis: dict[str, object],
) -> np.ndarray:
    values = [
        transform(extracted_features, content_analysis, redirect_analysis)
        for _name, _label, _description, transform in _FEATURE_SPECS
    ]
    return np.asarray(values, dtype=float)


@lru_cache(maxsize=1)
def _get_model_bundle():
    try:
        from sklearn.ensemble import RandomForestClassifier
    except ImportError:
        return None

    rng = np.random.default_rng(42)
    training_rows = 700
    training_vectors = rng.random((training_rows, len(_FEATURE_SPECS)))
    weights = np.asarray(
        [
            0.55,
            1.25,
            1.2,
            0.7,
            0.55,
            0.45,
            0.45,
            0.8,
            0.95,
            0.5,
            0.6,
            1.15,
            0.75,
            0.35,
            0.85,
            0.95,
        ],
        dtype=float,
    )

    interaction_bonus = (
        0.55 * (training_vectors[:, 1] * training_vectors[:, 11])
        + 0.45 * (training_vectors[:, 7] * training_vectors[:, 8])
        + 0.35 * (training_vectors[:, 14] * training_vectors[:, 15])
    )
    raw_scores = training_vectors @ weights + interaction_bonus
    labels = (raw_scores >= 4.65).astype(int)

    model = RandomForestClassifier(
        n_estimators=120,
        max_depth=6,
        random_state=42,
    )
    model.fit(training_vectors, labels)
    return model, training_vectors.mean(axis=0)


def _build_explanation(model, vector: np.ndarray, training_means: np.ndarray) -> dict[str, object]:
    try:
        import shap
    except ImportError:
        return _build_fallback_explanation(model, vector, training_means)

    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(vector.reshape(1, -1))

    if isinstance(shap_values, list):
        positive_class_values = np.asarray(shap_values[-1][0], dtype=float)
    else:
        values = np.asarray(shap_values, dtype=float)
        if values.ndim == 3:
            positive_class_values = values[0, :, -1]
        else:
            positive_class_values = values[0]

    signals = _top_signals_from_scores(positive_class_values, vector)
    return {
        "method": "shap",
        "signals": signals,
        "notes": "This model explanation uses SHAP values from the fitted Random Forest model.",
    }


def _build_fallback_explanation(model, vector: np.ndarray, training_means: np.ndarray) -> dict[str, object]:
    importances = np.asarray(model.feature_importances_, dtype=float)
    proxy_scores = (vector - training_means) * importances
    signals = _top_signals_from_scores(proxy_scores, vector)
    return {
        "method": "fallback_proxy",
        "signals": signals,
        "notes": "SHAP is not installed here yet, so these are approximate model signals based on feature importance and how unusual the link looks.",
    }


def _top_signals_from_scores(scores: np.ndarray, vector: np.ndarray) -> list[dict[str, object]]:
    ranked = sorted(
        enumerate(scores.tolist()),
        key=lambda item: abs(item[1]),
        reverse=True,
    )
    signals: list[dict[str, object]] = []

    for index, contribution in ranked[:4]:
        if vector[index] <= 0:
            continue

        name, label, description, _transform = _FEATURE_SPECS[index]
        signals.append(
            {
                "feature": name,
                "label": label,
                "description": description,
                "direction": "raises risk" if contribution >= 0 else "lowers risk",
                "strength": round(abs(float(contribution)), 4),
            }
        )

    return signals


def _classify_probability(probability: float) -> str:
    if probability >= 0.7:
        return "phishing"
    if probability >= 0.35:
        return "suspicious"
    return "safe"
