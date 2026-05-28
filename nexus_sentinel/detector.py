from __future__ import annotations

from dataclasses import asdict, dataclass

from nexus_sentinel.ml import build_ml_analysis
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
    ml_analysis: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def analyze_url(url: str) -> DetectionResult:
    return analyze_url_with_live_checks(url)


def analyze_url_with_live_checks(
    url: str,
    live_fetcher=None,
) -> DetectionResult:
    features = extract_url_features(url)
    content_analysis, redirect_analysis = _collect_live_checks(url, live_fetcher)
    score, factors, breakdown = _score_features(
        features, content_analysis, redirect_analysis
    )
    serialized_features = _serialize_features(features)
    ml_analysis = build_ml_analysis(
        serialized_features,
        content_analysis,
        redirect_analysis,
    )

    return DetectionResult(
        risk_score=score,
        classification=_classify(score),
        risk_factors=tuple(factors),
        extracted_features=serialized_features,
        score_breakdown=tuple(breakdown),
        content_analysis=content_analysis,
        redirect_analysis=redirect_analysis,
        ml_analysis=ml_analysis,
    )


def _score_features(
    features: UrlFeatures,
    content_analysis: dict[str, object],
    redirect_analysis: dict[str, object],
) -> tuple[int, list[str], list[dict[str, object]]]:
    score = 0
    factors: list[str] = []
    breakdown: list[dict[str, object]] = []

    def add_rule(triggered: bool, points: int, label: str, reason: str) -> None:
        nonlocal score
        if triggered:
            score += points
            factors.append(reason)
            title, impact = _rule_explanation(label)
            breakdown.append({"rule": label, "points": points, "reason": reason})
            breakdown[-1]["title"] = title
            breakdown[-1]["impact"] = impact

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
        title, impact = _rule_explanation("suspicious_keywords")
        breakdown.append(
            {
                "rule": "suspicious_keywords",
                "points": keyword_points,
                "reason": keyword_reason,
                "title": title,
                "impact": impact,
            }
        )

    add_rule(
        features.query_parameter_count >= 5,
        8,
        "many_query_parameters",
        "URL has many query parameters",
    )

    add_rule(
        bool(content_analysis.get("login_form_detected")),
        8,
        "login_form",
        "Page contains a login form",
    )

    add_rule(
        bool(content_analysis.get("password_field_detected")),
        10,
        "password_field",
        "Page asks for a password",
    )

    add_rule(
        bool(content_analysis.get("urgency_language_detected")),
        8,
        "urgency_language",
        "Page uses urgent or fear-based wording",
    )

    add_rule(
        bool(content_analysis.get("external_scripts_detected")),
        6,
        "external_scripts",
        "Page loads scripts from another site",
    )

    add_rule(
        bool(content_analysis.get("form_action_external_detected")),
        8,
        "form_action_external",
        "Login form sends data to another website",
    )

    add_rule(
        bool(content_analysis.get("brand_impersonation_clues_detected")),
        6,
        "brand_impersonation",
        "Page mentions a brand that does not match the website name",
    )

    add_rule(
        bool(content_analysis.get("iframe_detected")),
        4,
        "iframe_detected",
        "Page uses an embedded frame",
    )

    add_rule(
        bool(redirect_analysis.get("cross_domain_redirect_detected")),
        10,
        "cross_domain_redirect",
        "Link redirects to a different website",
    )

    add_rule(
        bool(redirect_analysis.get("suspicious_redirect_chain")),
        12,
        "suspicious_redirect_chain",
        "Link uses a suspicious redirect chain",
    )

    add_rule(
        bool(redirect_analysis.get("downgrade_to_http_detected")),
        8,
        "downgrade_to_http",
        "Link redirects from HTTPS to HTTP",
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
        "form_action_external_detected": None,
        "brand_impersonation_clues_detected": None,
        "brand_keywords_detected": [],
        "iframe_detected": None,
        "form_count": None,
        "notes": "Live webpage content analysis has not been enabled yet.",
    }


def _build_redirect_analysis_placeholder() -> dict[str, object]:
    return {
        "status": "not_fetched",
        "redirect_count": None,
        "redirect_chain": [],
        "final_url": None,
        "final_scheme": None,
        "status_code": None,
        "cross_domain_redirect_detected": None,
        "cross_domain_hops": None,
        "downgrade_to_http_detected": None,
        "suspicious_redirect_chain": None,
        "notes": "Live redirect tracing has not been enabled yet.",
    }


def _collect_live_checks(
    url: str,
    live_fetcher,
) -> tuple[dict[str, object], dict[str, object]]:
    if live_fetcher is None:
        return _build_content_analysis_placeholder(), _build_redirect_analysis_placeholder()
    return live_fetcher(url)


def _rule_explanation(label: str) -> tuple[str, str]:
    explanations = {
        "long_url": (
            "Very long link",
            "Long links can hide the real destination and make phishing pages harder to spot.",
        ),
        "at_symbol": (
            "@ symbol in the link",
            "Attackers can use @ to make a link look familiar while sending you somewhere else.",
        ),
        "no_https": (
            "No HTTPS",
            "Any data you type into a page without HTTPS can be intercepted, including passwords.",
        ),
        "ip_hostname": (
            "Raw IP address",
            "Legitimate brands usually use readable names, not raw server addresses.",
        ),
        "many_subdomains": (
            "Too many subdomains",
            "Extra subdomains are often used to mimic trusted brands and confuse readers.",
        ),
        "many_hyphens": (
            "Hyphen-heavy website name",
            "Attackers often stuff brand-like words into long hyphenated domains because they are cheap to register.",
        ),
        "deep_path": (
            "Unusually deep link path",
            "Overly deep paths can be used to hide suspicious pages inside messy-looking links.",
        ),
        "encoded_characters": (
            "Encoded characters in the link",
            "Encoded text can disguise what a link really points to.",
        ),
        "high_risk_tld": (
            "Unusual website ending",
            "Less familiar endings like .top or .xyz are often used by attackers because they are cheap and disposable.",
        ),
        "suspicious_keywords": (
            "Suspicious words in the link",
            "Words like login, verify, or secure are commonly used to pressure people into trusting a fake page.",
        ),
        "many_query_parameters": (
            "Too many query items",
            "Messy links with lots of query items can be used to hide tracking or disguise the real destination.",
        ),
        "login_form": (
            "Login form detected",
            "A page asking you to log in may be trying to capture your credentials.",
        ),
        "password_field": (
            "Password field detected",
            "If a suspicious page asks for your password, entering it could hand your account to an attacker.",
        ),
        "urgency_language": (
            "Urgent wording detected",
            "Phishing pages often create panic so people act before they stop to verify the link.",
        ),
        "external_scripts": (
            "Outside scripts detected",
            "Loading code from other sites can be a sign of a hastily assembled or unsafe page.",
        ),
        "form_action_external": (
            "Form sends data elsewhere",
            "A login form that sends your data to another site can be a sign of credential theft.",
        ),
        "brand_impersonation": (
            "Brand wording mismatch",
            "If the page mentions a known brand but the website name does not match, it may be impersonating that brand.",
        ),
        "iframe_detected": (
            "Embedded frame detected",
            "Embedded frames can be used to hide content from another site inside a suspicious page.",
        ),
        "cross_domain_redirect": (
            "Redirect to another site",
            "A link that bounces you to a different site can hide the real destination until after you click.",
        ),
        "suspicious_redirect_chain": (
            "Suspicious redirect chain",
            "Multiple redirects are often used to hide where a link ends up and bypass simple checks.",
        ),
        "downgrade_to_http": (
            "Redirect downgrades security",
            "A redirect from HTTPS to HTTP drops transport protection and is unusual for a trustworthy service.",
        ),
    }
    return explanations.get(
        label,
        ("Risk signal detected", "This pattern is often seen in malicious or misleading links."),
    )
