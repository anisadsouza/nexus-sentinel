from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import math
import random


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


@dataclass(frozen=True)
class _NaiveBayesModel:
    safe_means: tuple[float, ...]
    safe_variances: tuple[float, ...]
    risky_means: tuple[float, ...]
    risky_variances: tuple[float, ...]
    safe_prior: float
    risky_prior: float

    def predict_probability(self, vector: tuple[float, ...]) -> float:
        safe_log = math.log(self.safe_prior)
        risky_log = math.log(self.risky_prior)

        for index, value in enumerate(vector):
            safe_log += _gaussian_log_pdf(
                value,
                self.safe_means[index],
                self.safe_variances[index],
            )
            risky_log += _gaussian_log_pdf(
                value,
                self.risky_means[index],
                self.risky_variances[index],
            )

        margin = risky_log - safe_log
        return 1.0 / (1.0 + math.exp(-margin))


def build_ml_analysis(
    extracted_features: dict[str, object],
    content_analysis: dict[str, object],
    redirect_analysis: dict[str, object],
) -> dict[str, object]:
    vector = _feature_vector(extracted_features, content_analysis, redirect_analysis)
    model = _get_model()
    probability = model.predict_probability(vector)
    predicted_classification = _classify_probability(probability)

    return {
        "status": "available",
        "model_name": "SyntheticGaussianNaiveBayes",
        "prediction_probability": round(probability * 100, 1),
        "predicted_classification": predicted_classification,
        "explanation_method": "feature_gap_proxy",
        "shap_status": _shap_status(),
        "top_signals": _build_proxy_explanation(model, vector),
        "notes": _model_notes(),
    }


def _feature_vector(
    extracted_features: dict[str, object],
    content_analysis: dict[str, object],
    redirect_analysis: dict[str, object],
) -> tuple[float, ...]:
    return tuple(
        transform(extracted_features, content_analysis, redirect_analysis)
        for _name, _label, _description, transform in _FEATURE_SPECS
    )


@lru_cache(maxsize=1)
def _get_model() -> _NaiveBayesModel:
    rng = random.Random(42)
    safe_rows: list[tuple[float, ...]] = []
    risky_rows: list[tuple[float, ...]] = []
    weights = (
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
    )

    for _index in range(850):
        row = tuple(rng.random() for _unused in _FEATURE_SPECS)
        score = sum(value * weight for value, weight in zip(row, weights))
        score += 0.55 * row[1] * row[11]
        score += 0.45 * row[7] * row[8]
        score += 0.35 * row[14] * row[15]

        if score >= 4.65:
            risky_rows.append(row)
        else:
            safe_rows.append(row)

    return _NaiveBayesModel(
        safe_means=_column_stats(safe_rows)[0],
        safe_variances=_column_stats(safe_rows)[1],
        risky_means=_column_stats(risky_rows)[0],
        risky_variances=_column_stats(risky_rows)[1],
        safe_prior=len(safe_rows) / float(len(safe_rows) + len(risky_rows)),
        risky_prior=len(risky_rows) / float(len(safe_rows) + len(risky_rows)),
    )


def _column_stats(rows: list[tuple[float, ...]]) -> tuple[tuple[float, ...], tuple[float, ...]]:
    means: list[float] = []
    variances: list[float] = []

    for column_index in range(len(_FEATURE_SPECS)):
        values = [row[column_index] for row in rows]
        mean = sum(values) / float(len(values))
        variance = sum((value - mean) ** 2 for value in values) / float(len(values))
        means.append(mean)
        variances.append(max(variance, 1e-4))

    return tuple(means), tuple(variances)


def _gaussian_log_pdf(value: float, mean: float, variance: float) -> float:
    return -0.5 * math.log(2.0 * math.pi * variance) - ((value - mean) ** 2) / (
        2.0 * variance
    )


def _build_proxy_explanation(
    model: _NaiveBayesModel,
    vector: tuple[float, ...],
) -> list[dict[str, object]]:
    scored_signals: list[tuple[float, dict[str, object]]] = []

    for index, value in enumerate(vector):
        if value <= 0:
            continue

        name, label, description, _transform = _FEATURE_SPECS[index]
        risk_gap = model.risky_means[index] - model.safe_means[index]
        local_strength = (value - model.safe_means[index]) * risk_gap
        scored_signals.append(
            (
                abs(local_strength),
                {
                    "feature": name,
                    "label": label,
                    "description": description,
                    "direction": "raises risk" if local_strength >= 0 else "lowers risk",
                    "strength": round(abs(local_strength), 4),
                },
            )
        )

    scored_signals.sort(key=lambda item: item[0], reverse=True)
    return [signal for _score, signal in scored_signals[:4]]


def _classify_probability(probability: float) -> str:
    if probability >= 0.7:
        return "phishing"
    if probability >= 0.35:
        return "suspicious"
    return "safe"


def _shap_status() -> str:
    try:
        import shap  # noqa: F401
    except Exception:
        return "unavailable"
    return "available"


def _model_notes() -> str:
    if _shap_status() == "available":
        return "A lightweight local model is active. SHAP is available in this environment for future deeper explanation work."
    return "A lightweight local model is active. SHAP is not available in this environment yet, so the explanation below uses a simpler feature-gap proxy."
