import csv
from io import StringIO
import json
from ipaddress import ip_address
import socket
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from wsgiref.simple_server import make_server

from nexus_sentinel.live_checks import run_live_checks
from nexus_sentinel.ml import get_model_report
from nexus_sentinel.service import AnalysisService


ASSET_DIR = Path(__file__).parent / "webapp"
DEFAULT_STORAGE_PATH = Path("data") / "analysis_history.json"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9010


class DashboardApp:
    def __init__(
        self,
        storage_path: str | Path | None = None,
        live_fetcher=None,
    ) -> None:
        self._service = AnalysisService(
            storage_path=storage_path,
            live_fetcher=live_fetcher,
        )

    def __call__(self, environ: dict, start_response) -> list[bytes]:
        path = environ.get("PATH_INFO", "/")
        method = environ.get("REQUEST_METHOD", "GET")

        if method not in {"GET", "POST"}:
            return self._json_response(
                start_response,
                405,
                {"error": "Only GET and POST requests are supported right now."},
            )

        if path == "/":
            return self._file_response(start_response, "index.html", "text/html")
        if path == "/app.js":
            return self._file_response(
                start_response, "app.js", "application/javascript"
            )
        if path == "/styles.css":
            return self._file_response(start_response, "styles.css", "text/css")
        if path == "/api/analyze":
            return self._handle_analyze(environ, start_response)
        if path == "/api/analyze-batch":
            return self._handle_analyze_batch(environ, start_response)
        if path == "/api/similar-groups":
            return self._json_response(
                start_response,
                200,
                {
                    "similar_groups": self._service.list_similar_groups(),
                    "overview": self._service.overview(),
                },
            )
        if path == "/api/threatlens":
            query = parse_qs(environ.get("QUERY_STRING", ""))
            return self._json_response(
                start_response,
                200,
                {"threatlens": self._service.threatlens_summary(_parse_range_days(query))},
            )
        if path == "/api/threatlens/download":
            query = parse_qs(environ.get("QUERY_STRING", ""))
            return self._json_download_response(
                start_response,
                200,
                {"threatlens": self._service.threatlens_summary(_parse_range_days(query))},
                filename="nexus-sentinel-threatlens-report.json",
            )
        if path == "/api/model-report":
            return self._json_response(
                start_response,
                200,
                {"model_report": get_model_report()},
            )
        if path == "/api/model-report/download":
            return self._json_download_response(
                start_response,
                200,
                {"model_report": get_model_report()},
                filename="nexus-sentinel-model-report.json",
            )
        return self._json_response(start_response, 404, {"error": "Not found"})

    def _handle_analyze(self, environ: dict, start_response) -> list[bytes]:
        query = parse_qs(environ.get("QUERY_STRING", ""))
        raw_url = (query.get("url") or [""])[0].strip()
        private_scan = (query.get("private") or ["1"])[0].strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

        if not raw_url:
            return self._json_response(
                start_response, 400, {"error": "A url query parameter is required."}
            )

        url = _normalize_submitted_url(raw_url)
        if not url:
            return self._json_response(
                start_response,
                400,
                {"error": "Enter a full URL or link, such as https://example.com"},
            )

        record = self._service.analyze(url, save=not private_scan)
        return self._json_response(start_response, 200, record.to_dict())

    def _handle_analyze_batch(self, environ: dict, start_response) -> list[bytes]:
        if environ.get("REQUEST_METHOD", "GET") != "POST":
            return self._json_response(
                start_response,
                405,
                {"error": "Batch analysis requires a POST request."},
            )

        try:
            payload = self._read_json_body(environ)
        except ValueError as error:
            return self._json_response(start_response, 400, {"error": str(error)})

        csv_text = str(payload.get("csv_text", "")).strip()
        private_scan = bool(payload.get("private", True))

        if not csv_text:
            return self._json_response(
                start_response,
                400,
                {"error": "Upload a CSV file with at least one URL."},
            )

        try:
            urls = _extract_urls_from_csv_text(csv_text)
        except ValueError as error:
            return self._json_response(start_response, 400, {"error": str(error)})

        results = self._service.analyze_batch(urls, save=not private_scan)
        summary = {
            "total_urls": len(results),
            "safe": sum(1 for result in results if result.classification == "safe"),
            "suspicious": sum(
                1 for result in results if result.classification == "suspicious"
            ),
            "phishing": sum(
                1 for result in results if result.classification == "phishing"
            ),
            "saved_to_history": not private_scan,
        }
        return self._json_response(
            start_response,
            200,
            {
                "results": [record.to_dict() for record in results],
                "summary": summary,
                "overview": self._service.overview(),
            },
        )

    def _file_response(
        self, start_response, filename: str, content_type: str
    ) -> list[bytes]:
        body = (ASSET_DIR / filename).read_bytes()
        start_response("200 OK", [("Content-Type", content_type)])
        return [body]

    def _json_response(
        self, start_response, status_code: int, payload: dict[str, object]
    ) -> list[bytes]:
        return self._json_download_response(
            start_response,
            status_code,
            payload,
            filename=None,
        )

    def _json_download_response(
        self,
        start_response,
        status_code: int,
        payload: dict[str, object],
        filename: str | None,
    ) -> list[bytes]:
        body = json.dumps(payload).encode("utf-8")
        status_text = {
            200: "200 OK",
            400: "400 Bad Request",
            404: "404 Not Found",
            405: "405 Method Not Allowed",
        }[status_code]
        headers = [("Content-Type", "application/json")]
        if filename:
            headers.append(
                ("Content-Disposition", f'attachment; filename="{filename}"')
            )
        start_response(status_text, headers)
        return [body]

    def _read_json_body(self, environ: dict) -> dict[str, object]:
        raw_length = environ.get("CONTENT_LENGTH", "")
        try:
            content_length = int(raw_length) if raw_length else 0
        except (TypeError, ValueError):
            content_length = 0

        body = environ["wsgi.input"].read(content_length or None)
        if not body:
            raise ValueError("Request body is required.")

        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("Request body must be valid JSON.") from error

        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object.")
        return payload


def main() -> None:
    app = DashboardApp(storage_path=DEFAULT_STORAGE_PATH, live_fetcher=run_live_checks)
    host, port = _pick_available_address(DEFAULT_HOST, DEFAULT_PORT)
    with make_server(host, port, app) as server:
        print(f"Nexus Sentinel dashboard running on http://{host}:{port}")
        server.serve_forever()


def _pick_available_address(host: str, starting_port: int) -> tuple[str, int]:
    for port in range(starting_port, starting_port + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if sock.connect_ex((host, port)) != 0:
                return host, port
    raise RuntimeError("No open port found between 9010 and 9029.")


def _normalize_submitted_url(url: str) -> str | None:
    trimmed = url.strip()
    if not trimmed:
        return None

    try:
        parsed = urlparse(trimmed if "://" in trimmed else f"https://{trimmed}")
    except ValueError:
        return None

    hostname = parsed.hostname or ""
    if not hostname:
        return None
    if parsed.scheme not in {"http", "https"}:
        return None
    if hostname == "localhost" or "." in hostname:
        return parsed.geturl()
    try:
        ip_address(hostname)
    except ValueError:
        return None
    return parsed.geturl()


def _extract_urls_from_csv_text(csv_text: str) -> list[str]:
    reader = csv.reader(StringIO(csv_text))
    urls: list[str] = []

    for row in reader:
        for cell in row:
            normalized = _normalize_submitted_url(cell)
            if normalized:
                urls.append(normalized)
                if len(urls) > 100:
                    raise ValueError("Upload up to 100 URLs at a time.")

    if not urls:
        raise ValueError("No valid URLs were found in the CSV file.")

    return urls


def _parse_range_days(query: dict[str, list[str]]) -> int | None:
    raw_value = (query.get("range") or ["all"])[0].strip().lower()
    if raw_value in {"", "all"}:
        return None
    if raw_value not in {"7", "30"}:
        return None
    return int(raw_value)


if __name__ == "__main__":
    main()
