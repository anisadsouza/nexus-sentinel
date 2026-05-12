from dataclasses import asdict, dataclass

from nexus_sentinel.url_features import UrlFeatures, extract_url_features


@dataclass(frozen=True)
class DetectionResult:
    risk_score: int
    classification: str
    risk_factors: tuple[str, ...]
    extracted_features: dict[str, object]
    score_breakdown: tuple[dict[str, object], ...]
    content_analysis: dict[str, object]
    redirect_analysis: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def analyze_url(url: str) -> DetectionResult:
    features = extract_url_features(url)
    score, factors, breakdown = _score_features(features)

    return DetectionResult(
        risk_score=score,
        classification=_classify(score),
        risk_factors=tuple(factors),
        extracted_features=_serialize_features(features),
        score_breakdown=tuple(breakdown),
        content_analysis=_build_content_analysis_placeholder(),
        redirect_analysis=_build_redirect_analysis_placeholder(),
    )


def _score_features(
    features: UrlFeatures,
) -> tuple[int, list[str], list[dict[str, object]]]:
    score = 0
    factors: list[str] = []
    breakdown: list[dict[str, object]] = []

    def add_rule(triggered: bool, points: int, label: str, reason: str) -> None:
        nonlocal score
        if triggered:
            score += points
            factors.append(reason)
            breakdown.append({"rule": label, "points": points, "reason": reason})

    add_rule(
        features.url_length >= 100,
        15,
        "long_url",
        "URL is unusually long",
    )

    add_rule(
        features.has_at_symbol,
        20,
        "at_symbol",
        "URL contains @ symbol",
    )

    add_rule(
        not features.uses_https,
        12,
        "no_https",
        "URL does not use HTTPS",
    )

    add_rule(
        features.is_ip_hostname,
        20,
        "ip_hostname",
        "Hostname is an IP address",
    )

    add_rule(
        features.subdomain_count >= 3,
        10,
        "many_subdomains",
        "URL has many subdomains",
    )

    add_rule(
        features.hostname_hyphen_count >= 2,
        8,
        "many_hyphens",
        "Hostname uses many hyphens",
    )

    add_rule(
        features.path_depth >= 4,
        6,
        "deep_path",
        "URL path is unusually deep",
    )

    add_rule(
        features.has_encoded_characters,
        6,
        "encoded_characters",
        "URL contains encoded characters",
    )

    add_rule(
        features.has_suspicious_tld,
        10,
        "high_risk_tld",
        "URL uses a high-risk top-level domain",
    )

    if features.suspicious_keywords:
        keyword_points = min(len(features.suspicious_keywords) * 8, 24)
        keyword_reason = "Suspicious keywords found: " + ", ".join(
            features.suspicious_keywords
        )
        score += keyword_points
        factors.append(keyword_reason)
        breakdown.append(
            {
                "rule": "suspicious_keywords",
                "points": keyword_points,
                "reason": keyword_reason,
            }
        )

    add_rule(
        features.query_parameter_count >= 5,
        8,
        "many_query_parameters",
        "URL has many query parameters",
    )

    return min(score, 100), factors, breakdown


def _classify(score: int) -> str:
    if score >= 70:
        return "phishing"
    if score >= 35:
        return "suspicious"
    return "safe"


def _serialize_features(features: UrlFeatures) -> dict[str, object]:
    return {
        "url_length": features.url_length,
        "uses_https": features.uses_https,
        "hostname": features.hostname,
        "is_ip_hostname": features.is_ip_hostname,
        "subdomain_count": features.subdomain_count,
        "hostname_hyphen_count": features.hostname_hyphen_count,
        "path_depth": features.path_depth,
        "has_encoded_characters": features.has_encoded_characters,
        "has_suspicious_tld": features.has_suspicious_tld,
        "suspicious_keywords": list(features.suspicious_keywords),
        "query_parameter_count": features.query_parameter_count,
    }


def _build_content_analysis_placeholder() -> dict[str, object]:
    return {
        "status": "not_fetched",
        "page_title": None,
        "login_form_detected": None,
        "password_field_detected": None,
        "urgency_language_detected": None,
        "external_scripts_detected": None,
        "notes": "Live webpage content analysis has not been enabled yet.",
    }


def _build_redirect_analysis_placeholder() -> dict[str, object]:
    return {
        "status": "not_fetched",
        "redirect_count": None,
        "final_url": None,
        "cross_domain_redirect_detected": None,
        "suspicious_redirect_chain": None,
        "notes": "Live redirect tracing has not been enabled yet.",
    }
