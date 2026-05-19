import unittest

from nexus_sentinel.detector import analyze_url, analyze_url_with_live_checks


class DetectorTests(unittest.TestCase):
    def test_safe_https_url_scores_low(self) -> None:
        result = analyze_url("https://example.com")

        self.assertEqual(result.classification, "safe")
        self.assertLess(result.risk_score, 35)
        self.assertEqual(result.risk_factors, ())
        self.assertTrue(result.extracted_features["uses_https"])
        self.assertEqual(result.extracted_features["hostname"], "example.com")
        self.assertEqual(result.score_breakdown, ())
        self.assertEqual(result.content_analysis["status"], "not_fetched")
        self.assertEqual(result.redirect_analysis["status"], "not_fetched")
        self.assertEqual(result.ml_analysis["status"], "available")
        self.assertIn("prediction_probability", result.ml_analysis)
        self.assertIn("shap_status", result.ml_analysis)
        self.assertIn("feature_vector", result.ml_analysis)

    def test_suspicious_url_accumulates_risk_factors(self) -> None:
        result = analyze_url(
            "http://secure-login.example.com.verify-account.test/reset"
            "?user=1&a=2&b=3&c=4&d=5"
        )

        self.assertEqual(result.classification, "suspicious")
        self.assertGreaterEqual(result.risk_score, 35)
        self.assertIn("URL does not use HTTPS", result.risk_factors)
        self.assertTrue(any(item["rule"] == "no_https" for item in result.score_breakdown))

    def test_high_risk_tld_and_encoded_path_raise_score(self) -> None:
        result = analyze_url(
            "https://pay-update-secure-login.top/a/b/c/d/%2Freset?next=home"
        )

        self.assertIn("URL uses a high-risk top-level domain", result.risk_factors)
        self.assertIn("URL contains encoded characters", result.risk_factors)
        self.assertIn("Hostname uses many hyphens", result.risk_factors)
        self.assertGreater(result.risk_score, 20)
        self.assertTrue(result.extracted_features["has_suspicious_tld"])
        self.assertTrue(result.extracted_features["has_encoded_characters"])
        self.assertTrue(
            any(item["rule"] == "high_risk_tld" for item in result.score_breakdown)
        )
        self.assertIn("notes", result.content_analysis)
        self.assertIn("notes", result.redirect_analysis)

    def test_live_checks_add_page_and_redirect_risk_signals(self) -> None:
        def fake_live_fetcher(_url: str) -> tuple[dict[str, object], dict[str, object]]:
            return (
                {
                    "status": "fetched",
                    "page_title": "Verify your account now",
                    "login_form_detected": True,
                    "password_field_detected": True,
                    "urgency_language_detected": True,
                    "external_scripts_detected": True,
                    "notes": "Fetched test page.",
                },
                {
                    "status": "fetched",
                    "redirect_count": 2,
                    "final_url": "https://secure-check.top/login",
                    "cross_domain_redirect_detected": True,
                    "suspicious_redirect_chain": True,
                    "notes": "Fetched test redirect chain.",
                },
            )

        result = analyze_url_with_live_checks(
            "http://secure-check.top/login",
            live_fetcher=fake_live_fetcher,
        )

        self.assertEqual(result.content_analysis["status"], "fetched")
        self.assertEqual(result.redirect_analysis["status"], "fetched")
        self.assertEqual(result.ml_analysis["status"], "available")
        self.assertIn("Page asks for a password", result.risk_factors)
        self.assertIn("Link uses a suspicious redirect chain", result.risk_factors)
        self.assertTrue(
            any(item["rule"] == "password_field" for item in result.score_breakdown)
        )
        self.assertTrue(
            any(
                item["title"] == "No HTTPS" and "passwords" in item["impact"]
                for item in result.score_breakdown
            )
        )
        self.assertIn(
            result.ml_analysis["explanation_method"],
            {"shap", "fallback_proxy", "feature_gap_proxy"},
        )


if __name__ == "__main__":
    unittest.main()
