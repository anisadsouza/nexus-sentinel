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
        self.assertIn("extracted_features", payload)
        self.assertIn("score_breakdown", payload)
        self.assertIn("content_analysis", payload)
        self.assertIn("redirect_analysis", payload)

    def test_analyze_endpoint_rejects_missing_url(self) -> None:
        app = DashboardApp()

        status, headers, body = _run_app(app, path="/api/analyze")

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(headers["Content-Type"], "application/json")
        payload = json.loads(body)
        self.assertIn("required", payload["error"])

    def test_campaigns_endpoint_returns_campaign_summary_fields(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            app = DashboardApp(storage_path=f"{tmp_dir}/history.json")
            _run_app(
                app,
                path="/api/analyze",
                query_string=(
                    "url=http%3A%2F%2Fsecure-login.example.com.verify-account.test"
                    "%2Freset%3Fuser%3D1%26a%3D2%26b%3D3%26c%3D4%26d%3D5"
                ),
            )

            status, headers, body = _run_app(app, path="/api/campaigns")

        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Content-Type"], "application/json")
        payload = json.loads(body)
        self.assertEqual(len(payload["campaigns"]), 1)
        self.assertIn("overview", payload)
        self.assertIn("total_scans", payload["overview"])
        self.assertIn("first_seen", payload["campaigns"][0])
        self.assertIn("latest_seen", payload["campaigns"][0])
        self.assertIn("grouping_reason", payload["campaigns"][0])

    def test_private_analyze_request_does_not_persist_scan(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            app = DashboardApp(storage_path=f"{tmp_dir}/history.json")

            status, headers, body = _run_app(
                app,
                path="/api/analyze",
                query_string="url=https%3A%2F%2Fexample.com%2Flogin&private=1",
            )
            campaign_status, _campaign_headers, campaign_body = _run_app(
                app, path="/api/campaigns"
            )

        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Content-Type"], "application/json")
        payload = json.loads(body)
        self.assertFalse(payload["saved_to_history"])

        self.assertEqual(campaign_status, "200 OK")
        campaign_payload = json.loads(campaign_body)
        self.assertEqual(campaign_payload["overview"]["total_scans"], 0)


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
