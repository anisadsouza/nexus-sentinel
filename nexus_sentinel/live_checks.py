from __future__ import annotations

import re
from html import unescape
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


USER_AGENT = "NexusSentinel/0.1"
URGENCY_PATTERNS = (
    "urgent",
    "immediately",
    "verify now",
    "account suspended",
    "payment failed",
    "action required",
    "limited time",
    "confirm now",
    "security alert",
)


class _TrackingRedirectHandler(HTTPRedirectHandler):
    def __init__(self) -> None:
        super().__init__()
        self.redirect_chain: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirect_chain.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def run_live_checks(
    url: str, timeout: float = 5.0
) -> tuple[dict[str, object], dict[str, object]]:
    redirect_handler = _TrackingRedirectHandler()
    opener = build_opener(redirect_handler)
    request = Request(url, headers={"User-Agent": USER_AGENT})

    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as error:
        response = error
    except URLError as error:
        return _unavailable_content(str(error.reason)), _unavailable_redirect(
            str(error.reason)
        )
    except Exception as error:  # pragma: no cover - defensive runtime fallback
        return _unavailable_content(str(error)), _unavailable_redirect(str(error))

    try:
        raw_bytes = response.read(500_000)
    except Exception as error:  # pragma: no cover - defensive runtime fallback
        return _unavailable_content(str(error)), _unavailable_redirect(str(error))

    html = _decode_body(raw_bytes, getattr(response, "headers", None))
    final_url = response.geturl()
    initial_host = urlparse(url).hostname or ""
    final_host = urlparse(final_url).hostname or ""
    redirect_count = len(redirect_handler.redirect_chain)
    cross_domain_redirect_detected = bool(
        initial_host and final_host and initial_host != final_host
    )
    suspicious_redirect_chain = bool(
        redirect_count >= 3 or (redirect_count >= 1 and cross_domain_redirect_detected)
    )

    content_analysis = {
        "status": "fetched",
        "page_title": _extract_title(html),
        "login_form_detected": _has_login_form(html),
        "password_field_detected": _has_password_field(html),
        "urgency_language_detected": _has_urgency_language(html),
        "external_scripts_detected": _has_external_scripts(html, final_host),
        "notes": "Live webpage content was fetched successfully.",
    }
    redirect_analysis = {
        "status": "fetched",
        "redirect_count": redirect_count,
        "final_url": final_url,
        "cross_domain_redirect_detected": cross_domain_redirect_detected,
        "suspicious_redirect_chain": suspicious_redirect_chain,
        "notes": "Live redirect tracing completed successfully.",
    }
    return content_analysis, redirect_analysis


def _decode_body(raw_bytes: bytes, headers) -> str:
    charset = None
    if headers is not None:
        try:
            charset = headers.get_content_charset()
        except Exception:  # pragma: no cover - header implementations vary
            charset = None

    for encoding in filter(None, (charset, "utf-8", "latin-1")):
        try:
            return raw_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode("utf-8", errors="ignore")


def _extract_title(html: str) -> str | None:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return _clean_text(match.group(1)) or None


def _has_login_form(html: str) -> bool:
    lower_html = html.lower()
    return "<form" in lower_html and any(
        marker in lower_html
        for marker in ("login", "sign in", "signin", "email", "username", "account")
    )


def _has_password_field(html: str) -> bool:
    return bool(
        re.search(
            r'type\s*=\s*["\']?password["\']?', html, re.IGNORECASE | re.DOTALL
        )
    )


def _has_urgency_language(html: str) -> bool:
    lower_html = html.lower()
    return any(pattern in lower_html for pattern in URGENCY_PATTERNS)


def _has_external_scripts(html: str, final_host: str) -> bool:
    for script_url in _extract_script_urls(html):
        script_host = urlparse(script_url).hostname or ""
        if script_host and final_host and script_host != final_host:
            return True
    return False


def _extract_script_urls(html: str) -> Iterable[str]:
    return re.findall(
        r"<script[^>]+src\s*=\s*[\"']([^\"']+)[\"']",
        html,
        flags=re.IGNORECASE,
    )


def _clean_text(value: str) -> str:
    return re.sub(r"\s+", " ", unescape(value)).strip()


def _unavailable_content(reason: str) -> dict[str, object]:
    return {
        "status": "unavailable",
        "page_title": None,
        "login_form_detected": None,
        "password_field_detected": None,
        "urgency_language_detected": None,
        "external_scripts_detected": None,
        "notes": f"Live webpage content could not be fetched: {reason}.",
    }


def _unavailable_redirect(reason: str) -> dict[str, object]:
    return {
        "status": "unavailable",
        "redirect_count": None,
        "final_url": None,
        "cross_domain_redirect_detected": None,
        "suspicious_redirect_chain": None,
        "notes": f"Live redirect tracing could not be completed: {reason}.",
    }
