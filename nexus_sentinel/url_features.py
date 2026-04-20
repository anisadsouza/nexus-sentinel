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


@dataclass(frozen=True)
class UrlFeatures:
    url_length: int
    has_at_symbol: bool
    uses_https: bool
    hostname: str
    is_ip_hostname: bool
    subdomain_count: int
    suspicious_keywords: tuple[str, ...]
    query_parameter_count: int


def extract_url_features(url: str) -> UrlFeatures:
    parsed = urlparse(url if "://" in url else f"//{url}")
    hostname = parsed.hostname or ""
    hostname_parts = [part for part in hostname.split(".") if part]
    subdomain_count = max(len(hostname_parts) - 2, 0)
    lowered_url = url.lower()

    return UrlFeatures(
        url_length=len(url),
        has_at_symbol="@" in url,
        uses_https=parsed.scheme == "https",
        hostname=hostname,
        is_ip_hostname=_is_ip_address(hostname),
        subdomain_count=subdomain_count,
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
