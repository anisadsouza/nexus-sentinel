from dataclasses import asdict, dataclass

from nexus_sentinel.fingerprint import generate_threat_fingerprint
from nexus_sentinel.url_features import UrlFeatures, extract_url_features


@dataclass(frozen=True)
class DetectionResult:
    risk_score: int
    classification: str
    risk_factors: tuple[str, ...]
    threat_fingerprint_id: str
    extracted_features: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def analyze_url(url: str) -> DetectionResult:
    features = extract_url_features(url)
    score, factors = _score_features(features)

    return DetectionResult(
        risk_score=score,
        classification=_classify(score),
        risk_factors=tuple(factors),
        threat_fingerprint_id=generate_threat_fingerprint(features),
        extracted_features=_serialize_features(features),
    )


def _score_features(features: UrlFeatures) -> tuple[int, list[str]]:
    score = 0
    factors: list[str] = []

    if features.url_length >= 100:
        score += 15
        factors.append("URL is unusually long")

    if features.has_at_symbol:
        score += 20
        factors.append("URL contains @ symbol")

    if not features.uses_https:
        score += 12
        factors.append("URL does not use HTTPS")

    if features.is_ip_hostname:
        score += 20
        factors.append("Hostname is an IP address")

    if features.subdomain_count >= 3:
        score += 10
        factors.append("URL has many subdomains")

    if features.hostname_hyphen_count >= 2:
        score += 8
        factors.append("Hostname uses many hyphens")

    if features.path_depth >= 4:
        score += 6
        factors.append("URL path is unusually deep")

    if features.has_encoded_characters:
        score += 6
        factors.append("URL contains encoded characters")

    if features.has_suspicious_tld:
        score += 10
        factors.append("URL uses a high-risk top-level domain")

    if features.suspicious_keywords:
        score += min(len(features.suspicious_keywords) * 8, 24)
        factors.append(
            "Suspicious keywords found: " + ", ".join(features.suspicious_keywords)
        )

    if features.query_parameter_count >= 5:
        score += 8
        factors.append("URL has many query parameters")

    return min(score, 100), factors


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
