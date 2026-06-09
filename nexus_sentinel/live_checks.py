from __future__ import annotations

from html import unescape
from html.parser import HTMLParser
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


USER_AGENT = "NexusSentinel/0.2"
MAX_BODY_BYTES = 500_000
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
    "act now",
    "your account will be closed",
)
LOGIN_MARKERS = (
    "login",
    "log in",
    "sign in",
    "signin",
    "account",
    "username",
    "email",
    "password",
)
KNOWN_BRANDS = (
    "amazon",
    "apple",
    "bank",
    "dropbox",
    "google",
    "microsoft",
    "office365",
    "outlook",
    "paypal",
)


class _TrackingRedirectHandler(HTTPRedirectHandler):
    def __init__(self) -> None:
        super().__init__()
        self.redirect_chain: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirect_chain.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _SignalHTMLParser(HTMLParser):
    def __init__(self, base_url: str, final_host: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.final_host = final_host
        self.page_title_parts: list[str] = []
        self.visible_text_parts: list[str] = []
        self.form_count = 0
        self.login_form_detected = False
        self.password_field_detected = False
        self.external_scripts_detected = False
        self.form_action_external_detected = False
        self.iframe_detected = False
        self.hidden_input_count = 0
        self.meta_refresh_detected = False
        self.external_link_count = 0
        self._in_title = False

    def handle_starttag(self, tag: str, attrs) -> None:
        attrs_map = {key.lower(): value for key, value in attrs if key}
        tag_lower = tag.lower()

        if tag_lower == "title":
            self._in_title = True
            return

        if tag_lower == "form":
            self.form_count += 1
            self.login_form_detected = True
            action = attrs_map.get("action", "")
            if action:
                action_url = urljoin(self.base_url, action)
                action_host = urlparse(action_url).hostname or ""
                if action_host and self.final_host and action_host != self.final_host:
                    self.form_action_external_detected = True
            if _attrs_contain_marker(attrs_map, LOGIN_MARKERS):
                self.login_form_detected = True
            return

        if tag_lower == "input":
            field_type = (attrs_map.get("type") or "").strip().lower()
            if field_type == "hidden":
                self.hidden_input_count += 1
            if field_type == "password":
                self.password_field_detected = True
                self.login_form_detected = True
            if field_type in {"email", "text"} and _attrs_contain_marker(
                attrs_map, LOGIN_MARKERS
            ):
                self.login_form_detected = True
            return

        if tag_lower == "button" and _attrs_contain_marker(attrs_map, LOGIN_MARKERS):
            self.login_form_detected = True
            return

        if tag_lower == "script":
            script_url = attrs_map.get("src", "")
            if script_url:
                resolved = urljoin(self.base_url, script_url)
                script_host = urlparse(resolved).hostname or ""
                if script_host and self.final_host and script_host != self.final_host:
                    self.external_scripts_detected = True
            return

        if tag_lower == "iframe":
            self.iframe_detected = True
            return

        if tag_lower == "meta":
            http_equiv = (attrs_map.get("http-equiv") or "").strip().lower()
            content = (attrs_map.get("content") or "").strip().lower()
            if http_equiv == "refresh" and content:
                self.meta_refresh_detected = True
            return

        if tag_lower == "a":
            href = attrs_map.get("href", "")
            if href:
                resolved = urljoin(self.base_url, href)
                link_host = urlparse(resolved).hostname or ""
                if link_host and self.final_host and link_host != self.final_host:
                    self.external_link_count += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        cleaned = _clean_text(data)
        if not cleaned:
            return
        if self._in_title:
            self.page_title_parts.append(cleaned)
        self.visible_text_parts.append(cleaned)


def run_live_checks(
    url: str, timeout: float = 5.0
) -> tuple[dict[str, object], dict[str, object]]:
    redirect_handler = _TrackingRedirectHandler()
    opener = build_opener(redirect_handler)
    request = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept-Language": "en-US,en;q=0.8",
        },
    )

    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as error:
        response = error
    except URLError as error:
        reason = str(getattr(error, "reason", error))
        return _unavailable_content(reason), _unavailable_redirect(reason)
    except TimeoutError:
        return _unavailable_content("request timed out"), _unavailable_redirect(
            "request timed out"
        )
    except Exception as error:  # pragma: no cover - defensive runtime fallback
        return _unavailable_content(str(error)), _unavailable_redirect(str(error))

    try:
        raw_bytes = response.read(MAX_BODY_BYTES)
    except Exception as error:  # pragma: no cover - defensive runtime fallback
        return _unavailable_content(str(error)), _unavailable_redirect(str(error))

    html = _decode_body(raw_bytes, getattr(response, "headers", None))
    final_url = response.geturl()
    initial_parts = urlparse(url)
    final_parts = urlparse(final_url)
    initial_host = initial_parts.hostname or ""
    final_host = final_parts.hostname or ""
    redirect_count = len(redirect_handler.redirect_chain)
    cross_domain_redirect_detected = bool(
        initial_host and final_host and initial_host != final_host
    )
    cross_domain_hops = _count_cross_domain_hops(url, redirect_handler.redirect_chain)
    downgrade_to_http_detected = (
        initial_parts.scheme == "https" and final_parts.scheme == "http"
    )
    suspicious_redirect_chain = bool(
        redirect_count >= 3
        or cross_domain_hops >= 2
        or downgrade_to_http_detected
        or (redirect_count >= 1 and cross_domain_redirect_detected)
    )

    parser = _SignalHTMLParser(base_url=final_url, final_host=final_host)
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # pragma: no cover - HTML can be malformed in the wild
        pass

    page_title = " ".join(parser.page_title_parts) or None
    visible_text = " ".join(parser.visible_text_parts)
    brand_keywords = _detect_brand_keywords(visible_text)
    urgency_language_detected = _has_urgency_language(visible_text)
    brand_impersonation_clues_detected = bool(
        brand_keywords and not _hostname_matches_brand(final_host, brand_keywords)
    )

    content_analysis = {
        "status": "fetched",
        "page_title": page_title,
        "login_form_detected": parser.login_form_detected,
        "password_field_detected": parser.password_field_detected,
        "urgency_language_detected": urgency_language_detected,
        "external_scripts_detected": parser.external_scripts_detected,
        "form_action_external_detected": parser.form_action_external_detected,
        "brand_impersonation_clues_detected": brand_impersonation_clues_detected,
        "brand_keywords_detected": brand_keywords,
        "iframe_detected": parser.iframe_detected,
        "hidden_input_count": parser.hidden_input_count,
        "meta_refresh_detected": parser.meta_refresh_detected,
        "external_link_count": parser.external_link_count,
        "form_count": parser.form_count,
        "notes": _build_content_note(
            parser=parser,
            urgency_language_detected=urgency_language_detected,
            brand_impersonation_clues_detected=brand_impersonation_clues_detected,
        ),
    }
    redirect_analysis = {
        "status": "fetched",
        "redirect_count": redirect_count,
        "redirect_chain": list(redirect_handler.redirect_chain),
        "final_url": final_url,
        "final_scheme": final_parts.scheme,
        "status_code": getattr(response, "status", None) or response.getcode(),
        "cross_domain_redirect_detected": cross_domain_redirect_detected,
        "cross_domain_hops": cross_domain_hops,
        "downgrade_to_http_detected": downgrade_to_http_detected,
        "suspicious_redirect_chain": suspicious_redirect_chain,
        "notes": _build_redirect_note(
            redirect_count=redirect_count,
            cross_domain_hops=cross_domain_hops,
            downgrade_to_http_detected=downgrade_to_http_detected,
        ),
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


def _attrs_contain_marker(attrs_map: dict[str, str], markers: tuple[str, ...]) -> bool:
    haystack = " ".join(
        (value or "") for key, value in attrs_map.items() if key in {"id", "name", "class", "placeholder", "aria-label"}
    ).lower()
    return any(marker in haystack for marker in markers)


def _detect_brand_keywords(visible_text: str) -> list[str]:
    lower_text = visible_text.lower()
    return [brand for brand in KNOWN_BRANDS if brand in lower_text]


def _hostname_matches_brand(hostname: str, brands: list[str]) -> bool:
    lower_host = hostname.lower()
    return any(brand in lower_host for brand in brands)


def _has_urgency_language(visible_text: str) -> bool:
    lower_text = visible_text.lower()
    return any(pattern in lower_text for pattern in URGENCY_PATTERNS)


def _count_cross_domain_hops(initial_url: str, redirect_chain: list[str]) -> int:
    hosts = [urlparse(initial_url).hostname or ""]
    hosts.extend(urlparse(item).hostname or "" for item in redirect_chain)
    hops = 0

    for previous, current in zip(hosts, hosts[1:]):
        if previous and current and previous != current:
            hops += 1
    return hops


def _build_content_note(
    parser: _SignalHTMLParser,
    urgency_language_detected: bool,
    brand_impersonation_clues_detected: bool,
) -> str:
    highlights: list[str] = []
    if parser.password_field_detected:
        highlights.append("password field detected")
    if parser.form_action_external_detected:
        highlights.append("form posts to another site")
    if urgency_language_detected:
        highlights.append("urgent wording detected")
    if brand_impersonation_clues_detected:
        highlights.append("brand wording does not match the hostname")
    if parser.iframe_detected:
        highlights.append("embedded frame detected")
    if parser.meta_refresh_detected:
        highlights.append("meta refresh redirect detected")
    if parser.hidden_input_count >= 5:
        highlights.append("many hidden fields detected")

    if not highlights:
        return "Live webpage content was fetched successfully."
    return "Live webpage content was fetched successfully: " + ", ".join(highlights) + "."


def _build_redirect_note(
    redirect_count: int,
    cross_domain_hops: int,
    downgrade_to_http_detected: bool,
) -> str:
    highlights: list[str] = []
    if redirect_count:
        highlights.append(f"{redirect_count} redirect(s)")
    if cross_domain_hops:
        highlights.append(f"{cross_domain_hops} cross-domain hop(s)")
    if downgrade_to_http_detected:
        highlights.append("downgraded from HTTPS to HTTP")

    if not highlights:
        return "Live redirect tracing completed successfully."
    return "Live redirect tracing completed successfully: " + ", ".join(highlights) + "."


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
        "form_action_external_detected": None,
        "brand_impersonation_clues_detected": None,
        "brand_keywords_detected": [],
        "iframe_detected": None,
        "hidden_input_count": None,
        "meta_refresh_detected": None,
        "external_link_count": None,
        "form_count": None,
        "notes": f"Live webpage content could not be fetched: {reason}.",
    }


def _unavailable_redirect(reason: str) -> dict[str, object]:
    return {
        "status": "unavailable",
        "redirect_count": None,
        "redirect_chain": [],
        "final_url": None,
        "final_scheme": None,
        "status_code": None,
        "cross_domain_redirect_detected": None,
        "cross_domain_hops": None,
        "downgrade_to_http_detected": None,
        "suspicious_redirect_chain": None,
        "notes": f"Live redirect tracing could not be completed: {reason}.",
    }
