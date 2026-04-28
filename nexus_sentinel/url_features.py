from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = {
    "account",
    "bank",
    "confirm",
    "login",
    "password",
    "secure",
    "update",
    "verify",
}

SUSPICIOUS_TLDS = {"click", "icu", "link", "ru", "shop", "top", "work", "xyz"}


@dataclass(frozen=True)
class UrlFeatures:
    url_length: int
    has_at_symbol: bool
    uses_https: bool
    hostname: str
    is_ip_hostname: bool
    subdomain_count: int
    hostname_hyphen_count: int
    path_depth: int
    has_encoded_characters: bool
    has_suspicious_tld: bool
    suspicious_keywords: tuple[str, ...]
    query_parameter_count: int


def extract_url_features(url: str) -> UrlFeatures:
    parsed = urlparse(url if "://" in url else f"//{url}")
    hostname = parsed.hostname or ""
    hostname_parts = [part for part in hostname.split(".") if part]
    subdomain_count = max(len(hostname_parts) - 2, 0)
    lowered_url = url.lower()
    path_segments = [segment for segment in parsed.path.split("/") if segment]

    return UrlFeatures(
        url_length=len(url),
        has_at_symbol="@" in url,
        uses_https=parsed.scheme == "https",
        hostname=hostname,
        is_ip_hostname=_is_ip_address(hostname),
        subdomain_count=subdomain_count,
        hostname_hyphen_count=hostname.count("-"),
        path_depth=len(path_segments),
        has_encoded_characters="%" in url,
        has_suspicious_tld=_has_suspicious_tld(hostname_parts),
        suspicious_keywords=tuple(
            keyword for keyword in sorted(SUSPICIOUS_KEYWORDS) if keyword in lowered_url
        ),
        query_parameter_count=_count_query_parameters(parsed.query),
    )


def _is_ip_address(hostname: str) -> bool:
    try:
        ip_address(hostname)
    except ValueError:
        return False
    return True


def _count_query_parameters(query: str) -> int:
    if not query:
        return 0
    return len([part for part in query.split("&") if part])


def _has_suspicious_tld(hostname_parts: list[str]) -> bool:
    if len(hostname_parts) < 2:
        return False
    return hostname_parts[-1] in SUSPICIOUS_TLDS
