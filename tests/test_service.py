from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from nexus_sentinel.service import AnalysisService


class AnalysisServiceTests(unittest.TestCase):
    def test_matching_urls_share_a_campaign(self) -> None:
        service = AnalysisService()

        first = service.analyze(
            "http://secure-login.example.com.verify-account.test/reset"
            "?user=1&a=2&b=3&c=4&d=5"
        )
        second = service.analyze(
            "http://secure-login.example.com.verify-account.test/reset"
            "?user=2&a=2&b=3&c=4&d=5"
        )

        self.assertEqual(first.campaign_id, second.campaign_id)
        self.assertEqual(second.campaign_size, 2)
        self.assertTrue(first.analyzed_at)

        campaigns = service.list_campaigns()
        self.assertEqual(len(campaigns), 1)
        self.assertEqual(campaigns[0]["size"], 2)
        self.assertTrue(campaigns[0]["common_risk_factors"])
        self.assertIn("first_seen", campaigns[0])
        self.assertIn("latest_seen", campaigns[0])
        self.assertTrue(campaigns[0]["grouping_reason"])

    def test_recent_scans_returns_latest_first(self) -> None:
        service = AnalysisService()

        service.analyze("https://example.com")
        latest = service.analyze("http://192.168.1.5/login")

        scans = service.recent_scans()

        self.assertEqual(scans[0]["url"], latest.url)
        self.assertEqual(scans[0]["classification"], latest.classification)

    def test_overview_summarizes_scan_history(self) -> None:
        service = AnalysisService()

        service.analyze("https://example.com")
        service.analyze("http://192.168.1.5/login")

        overview = service.overview()

        self.assertEqual(overview["total_scans"], 2)
        self.assertEqual(overview["active_campaigns"], 2)
        self.assertGreaterEqual(overview["highest_risk"], 1)

    def test_private_scan_is_not_saved_to_history(self) -> None:
        service = AnalysisService()

        record = service.analyze("http://192.168.1.5/login", save=False)

        self.assertFalse(record.saved_to_history)
        self.assertEqual(service.overview()["total_scans"], 0)
        self.assertEqual(service.recent_scans(), [])

    def test_records_persist_when_storage_path_is_used(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            storage_path = Path(tmp_dir) / "history.json"
            first_service = AnalysisService(storage_path=storage_path)

            saved = first_service.analyze("http://192.168.1.5/login")

            second_service = AnalysisService(storage_path=storage_path)
            scans = second_service.recent_scans()

            self.assertEqual(len(scans), 1)
            self.assertEqual(scans[0]["url"], saved.url)
            self.assertEqual(scans[0]["campaign_id"], saved.campaign_id)
            self.assertTrue(scans[0]["saved_to_history"])
            self.assertIn("extracted_features", scans[0])
            self.assertIn("score_breakdown", scans[0])
            self.assertIn("content_analysis", scans[0])
            self.assertIn("redirect_analysis", scans[0])
            self.assertIn("analyzed_at", scans[0])


if __name__ == "__main__":
    unittest.main()
