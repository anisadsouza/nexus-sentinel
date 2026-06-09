import json
from io import BytesIO
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
        self.assertFalse(payload["saved_to_history"])
        self.assertIn("risk_score", payload)
        self.assertIn("similar_group_id", payload)
        self.assertIn("extracted_features", payload)
        self.assertIn("score_breakdown", payload)
        self.assertIn("content_analysis", payload)
        self.assertIn("redirect_analysis", payload)
        self.assertIn("ml_analysis", payload)

    def test_analyze_endpoint_rejects_missing_url(self) -> None:
        app = DashboardApp()

        status, headers, body = _run_app(app, path="/api/analyze")

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(headers["Content-Type"], "application/json")
        payload = json.loads(body)
        self.assertIn("required", payload["error"])

    def test_analyze_endpoint_rejects_plain_text_instead_of_url(self) -> None:
        app = DashboardApp()

        status, headers, body = _run_app(
            app,
            path="/api/analyze",
            query_string="url=hello",
        )

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(headers["Content-Type"], "application/json")
        payload = json.loads(body)
        self.assertIn("Enter a full URL or link", payload["error"])

    def test_similar_groups_endpoint_returns_summary_fields(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            app = DashboardApp(storage_path=f"{tmp_dir}/history.json")
            _run_app(
                app,
                path="/api/analyze",
                query_string=(
                    "url=http%3A%2F%2Fsecure-login.example.com.verify-account.test"
                    "%2Freset%3Fuser%3D1%26a%3D2%26b%3D3%26c%3D4%26d%3D5"
                    "&private=0"
                ),
            )

            status, headers, body = _run_app(app, path="/api/similar-groups")

        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Content-Type"], "application/json")
        payload = json.loads(body)
        self.assertEqual(len(payload["similar_groups"]), 1)
        self.assertIn("overview", payload)
        self.assertIn("total_scans", payload["overview"])
        self.assertIn("active_similar_groups", payload["overview"])
        self.assertIn("first_seen", payload["similar_groups"][0])
        self.assertIn("latest_seen", payload["similar_groups"][0])
        self.assertIn("grouping_reason", payload["similar_groups"][0])

    def test_private_analyze_request_does_not_persist_scan(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            app = DashboardApp(storage_path=f"{tmp_dir}/history.json")

            status, headers, body = _run_app(
                app,
                path="/api/analyze",
                query_string="url=https%3A%2F%2Fexample.com%2Flogin&private=1",
            )
            campaign_status, _campaign_headers, campaign_body = _run_app(
                app, path="/api/similar-groups"
            )

        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Content-Type"], "application/json")
        payload = json.loads(body)
        self.assertFalse(payload["saved_to_history"])

        self.assertEqual(campaign_status, "200 OK")
        campaign_payload = json.loads(campaign_body)
        self.assertEqual(campaign_payload["overview"]["total_scans"], 0)

    def test_batch_analyze_endpoint_returns_table_data(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            app = DashboardApp(storage_path=f"{tmp_dir}/history.json")

            status, headers, body = _run_app(
                app,
                path="/api/analyze-batch",
                method="POST",
                body=json.dumps(
                    {
                        "csv_text": "url\nhttps://example.com\nhttp://192.168.1.5/login\n",
                        "private": True,
                    }
                ),
            )

        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Content-Type"], "application/json")
        payload = json.loads(body)
        self.assertEqual(payload["summary"]["total_urls"], 2)
        self.assertEqual(len(payload["results"]), 2)
        self.assertFalse(payload["summary"]["saved_to_history"])

    def test_batch_analyze_endpoint_rejects_csv_without_valid_urls(self) -> None:
        app = DashboardApp()

        status, headers, body = _run_app(
            app,
            path="/api/analyze-batch",
            method="POST",
            body=json.dumps({"csv_text": "name\nhello\nworld\n", "private": True}),
        )

        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(headers["Content-Type"], "application/json")
        payload = json.loads(body)
        self.assertIn("No valid URLs", payload["error"])

    def test_model_report_endpoint_returns_report_payload(self) -> None:
        app = DashboardApp()

        status, headers, body = _run_app(app, path="/api/model-report")

        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Content-Type"], "application/json")
        payload = json.loads(body)
        self.assertIn("model_report", payload)
        self.assertIn("status", payload["model_report"])
        self.assertIn("training_source", payload["model_report"])
        self.assertIn("dataset_paths", payload["model_report"])
        self.assertIn("decision_thresholds", payload["model_report"])

    def test_model_report_download_endpoint_returns_attachment(self) -> None:
        app = DashboardApp()

        status, headers, body = _run_app(app, path="/api/model-report/download")

        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertIn("attachment;", headers["Content-Disposition"])
        payload = json.loads(body)
        self.assertIn("model_report", payload)

    def test_clear_history_endpoint_is_not_available(self) -> None:
        app = DashboardApp()

        status, headers, body = _run_app(
            app, path="/api/history/clear", method="POST"
        )

        self.assertEqual(status, "404 Not Found")
        self.assertEqual(headers["Content-Type"], "application/json")
        payload = json.loads(body)
        self.assertIn("Not found", payload["error"])


def _run_app(
    app: DashboardApp,
    path: str,
    query_string: str = "",
    method: str = "GET",
    body: str = "",
) -> tuple[str, dict[str, str], str]:
    environ: dict[str, object] = {}
    setup_testing_defaults(environ)
    environ["PATH_INFO"] = path
    environ["QUERY_STRING"] = query_string
    environ["REQUEST_METHOD"] = method
    encoded_body = body.encode("utf-8")
    environ["wsgi.input"] = BytesIO(encoded_body)
    environ["CONTENT_LENGTH"] = str(len(encoded_body))

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
