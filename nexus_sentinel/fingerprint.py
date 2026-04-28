import hashlib
import json

from nexus_sentinel.url_features import UrlFeatures


def generate_threat_fingerprint(features: UrlFeatures) -> str:
    pattern = {
        "has_at_symbol": features.has_at_symbol,
        "has_encoded_characters": features.has_encoded_characters,
        "has_suspicious_tld": features.has_suspicious_tld,
        "hostname_hyphen_count": _bucket(features.hostname_hyphen_count),
        "is_ip_hostname": features.is_ip_hostname,
        "keyword_count": len(features.suspicious_keywords),
        "keywords": features.suspicious_keywords,
        "path_depth": _bucket(features.path_depth),
        "query_parameter_count": _bucket(features.query_parameter_count),
        "subdomain_count": _bucket(features.subdomain_count),
        "url_length": _bucket(features.url_length),
        "uses_https": features.uses_https,
    }
    encoded = json.dumps(pattern, sort_keys=True).encode("utf-8")
    return "fp_" + hashlib.sha256(encoded).hexdigest()[:12]


def _bucket(value: int) -> str:
    if value == 0:
        return "none"
    if value <= 2:
        return "low"
    if value <= 5:
        return "medium"
    return "high"
