from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from nexus_sentinel.service import AnalysisService


class AnalysisServiceTests(unittest.TestCase):
    def test_matching_urls_share_a_similar_group(self) -> None:
        service = AnalysisService()

        first = service.analyze(
            "http://secure-login.example.com.verify-account.test/reset"
            "?user=1&a=2&b=3&c=4&d=5"
        )
        second = service.analyze(
            "http://secure-login.example.com.verify-account.test/reset"
            "?user=2&a=2&b=3&c=4&d=5"
        )

        self.assertEqual(first.similar_group_id, second.similar_group_id)
        self.assertEqual(second.similar_group_size, 2)
        self.assertTrue(first.analyzed_at)

        similar_groups = service.list_similar_groups()
        self.assertEqual(len(similar_groups), 1)
        self.assertEqual(similar_groups[0]["size"], 2)
        self.assertTrue(similar_groups[0]["common_risk_factors"])
        self.assertIn("first_seen", similar_groups[0])
        self.assertIn("latest_seen", similar_groups[0])
        self.assertTrue(similar_groups[0]["grouping_reason"])

    def test_overview_summarizes_scan_history(self) -> None:
        service = AnalysisService()

        service.analyze("https://example.com")
        service.analyze("http://192.168.1.5/login")

        overview = service.overview()

        self.assertEqual(overview["total_scans"], 2)
        self.assertEqual(overview["active_similar_groups"], 2)
        self.assertGreaterEqual(overview["highest_risk"], 1)

    def test_private_scan_is_not_saved_to_history(self) -> None:
        service = AnalysisService()

        record = service.analyze("http://192.168.1.5/login", save=False)

        self.assertFalse(record.saved_to_history)
        self.assertEqual(service.overview()["total_scans"], 0)
        self.assertEqual(service.list_similar_groups(), [])

    def test_batch_analysis_returns_results_for_each_url(self) -> None:
        service = AnalysisService()

        results = service.analyze_batch(
            [
                "https://example.com",
                "http://192.168.1.5/login",
                "https://pay-update-secure-login.top/a/b/c/d/%2Freset?next=home",
            ],
            save=False,
        )

        self.assertEqual(len(results), 3)
        self.assertTrue(all(result.saved_to_history is False for result in results))
        self.assertEqual(service.overview()["total_scans"], 0)
        self.assertEqual(results[0].url, "https://example.com")
        self.assertTrue(all("status" in result.ml_analysis for result in results))
        self.assertTrue(all("feature_vector" in result.ml_analysis for result in results))

    def test_records_persist_when_storage_path_is_used(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            storage_path = Path(tmp_dir) / "history.json"
            first_service = AnalysisService(storage_path=storage_path)

            saved = first_service.analyze("http://192.168.1.5/login")

            second_service = AnalysisService(storage_path=storage_path)
            similar_groups = second_service.list_similar_groups()
            overview = second_service.overview()

            self.assertEqual(overview["total_scans"], 1)
            self.assertEqual(len(similar_groups), 1)
            self.assertEqual(similar_groups[0]["example_urls"][0], saved.url)
            self.assertIn("prediction_probability", second_service._records[0].ml_analysis)

    def test_threatlens_summary_rolls_up_saved_history(self) -> None:
        service = AnalysisService()

        service.analyze(
            "http://secure-login.example.com.verify-account.test/reset"
            "?user=1&a=2&b=3&c=4&d=5"
        )
        service.analyze("https://example.com")

        summary = service.threatlens_summary()

        self.assertIn("overview", summary)
        self.assertIn("classification_breakdown", summary)
        self.assertIn("top_similar_groups", summary)
        self.assertIn("top_risk_signals", summary)
        self.assertIn("top_themes", summary)
        self.assertIn("top_categories", summary)
        self.assertIn("classification_shares", summary)
        self.assertIn("top_brand_targets", summary)
        self.assertIn("top_risk_insights", summary)
        self.assertIn("campaign_spotlights", summary)
        self.assertIn("daily_trend", summary)
        self.assertIn("trend_change", summary)
        self.assertIn("weekly_briefing", summary)
        self.assertIn("generated_summary", summary)
        self.assertEqual(summary["overview"]["total_scans"], 2)
        self.assertTrue(summary["daily_trend"])

    def test_threatlens_summary_can_filter_by_recent_days(self) -> None:
        service = AnalysisService()

        with patch("nexus_sentinel.service._timestamp_now", side_effect=[
            "2026-06-01T00:00:00+00:00",
            "2026-06-29T00:00:00+00:00",
        ]):
            service.analyze("http://192.168.1.5/login")
            service.analyze("https://example.com")

        summary = service.threatlens_summary(days=7)

        self.assertEqual(summary["range_days"], 7)
        self.assertEqual(summary["overview"]["total_scans"], 1)
        self.assertEqual(summary["range_label"], "Last 7 days")
        self.assertIn("theme_groups", summary)


if __name__ == "__main__":
    unittest.main()
