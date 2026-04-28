import json
from tempfile import TemporaryDirectory
import unittest
from wsgiref.util import setup_testing_defaults

from nexus_sentinel.web import DashboardApp


class DashboardAppTests(unittest.TestCase):
    def test_analyze_endpoint_returns_json_record(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            app = DashboardApp(storage_path=f"{tmp_dir}/history.json")

            status, headers, body = _run_app(
                app,
                path="/api/analyze",
                query_string="url=https%3A%2F%2Fexample.com%2Flogin",
            )

        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Content-Type"], "application/json")
        payload = json.loads(body)
        self.assertEqual(payload["url"], "https://example.com/login")
        self.assertIn("risk_score", payload)
        self.assertIn("campaign_id", payload)

    def test_analyze_endpoint_rejects_missing_url(self) -> None:
        app = DashboardApp()

        status, headers, body = _run_app(app, path="/api/analyze")

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(headers["Content-Type"], "application/json")
        payload = json.loads(body)
        self.assertIn("required", payload["error"])


def _run_app(
    app: DashboardApp, path: str, query_string: str = "", method: str = "GET"
) -> tuple[str, dict[str, str], str]:
    environ: dict[str, object] = {}
    setup_testing_defaults(environ)
    environ["PATH_INFO"] = path
    environ["QUERY_STRING"] = query_string
    environ["REQUEST_METHOD"] = method

    result: dict[str, object] = {}

    def start_response(
        status: str, headers: list[tuple[str, str]], exc_info=None
    ) -> None:
        result["status"] = status
        result["headers"] = dict(headers)

    body = b"".join(app(environ, start_response)).decode("utf-8")
    return result["status"], result["headers"], body


if __name__ == "__main__":
    unittest.main()
