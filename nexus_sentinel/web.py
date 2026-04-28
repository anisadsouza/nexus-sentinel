import json
import socket
from pathlib import Path
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

from nexus_sentinel.service import AnalysisService


ASSET_DIR = Path(__file__).parent / "webapp"
DEFAULT_STORAGE_PATH = Path("data") / "analysis_history.json"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9010


class DashboardApp:
    def __init__(self, storage_path: str | Path | None = None) -> None:
        self._service = AnalysisService(storage_path=storage_path)

    def __call__(self, environ: dict, start_response) -> list[bytes]:
        path = environ.get("PATH_INFO", "/")
        method = environ.get("REQUEST_METHOD", "GET")

        if method != "GET":
            return self._json_response(
                start_response,
                405,
                {"error": "Only GET requests are supported right now."},
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
        if path == "/api/campaigns":
            return self._json_response(
                start_response,
                200,
                {
                    "campaigns": self._service.list_campaigns(),
                    "recent_scans": self._service.recent_scans(),
                },
            )

        return self._json_response(start_response, 404, {"error": "Not found"})

    def _handle_analyze(self, environ: dict, start_response) -> list[bytes]:
        query = parse_qs(environ.get("QUERY_STRING", ""))
        url = (query.get("url") or [""])[0].strip()

        if not url:
            return self._json_response(
                start_response, 400, {"error": "A url query parameter is required."}
            )

        record = self._service.analyze(url)
        return self._json_response(start_response, 200, record.to_dict())

    def _file_response(
        self, start_response, filename: str, content_type: str
    ) -> list[bytes]:
        body = (ASSET_DIR / filename).read_bytes()
        start_response("200 OK", [("Content-Type", content_type)])
        return [body]

    def _json_response(
        self, start_response, status_code: int, payload: dict[str, object]
    ) -> list[bytes]:
        body = json.dumps(payload).encode("utf-8")
        status_text = {
            200: "200 OK",
            400: "400 Bad Request",
            404: "404 Not Found",
            405: "405 Method Not Allowed",
        }[status_code]
        start_response(status_text, [("Content-Type", "application/json")])
        return [body]


def main() -> None:
    app = DashboardApp(storage_path=DEFAULT_STORAGE_PATH)
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


if __name__ == "__main__":
    main()
