import unittest

from nexus_sentinel.detector import analyze_url


class DetectorTests(unittest.TestCase):
    def test_safe_https_url_scores_low(self) -> None:
        result = analyze_url("https://example.com")

        self.assertEqual(result.classification, "safe")
        self.assertLess(result.risk_score, 35)
        self.assertEqual(result.risk_factors, ())
        self.assertTrue(result.extracted_features["uses_https"])
        self.assertEqual(result.extracted_features["hostname"], "example.com")
        self.assertEqual(result.score_breakdown, ())

    def test_suspicious_url_accumulates_risk_factors(self) -> None:
        result = analyze_url(
            "http://secure-login.example.com.verify-account.test/reset"
            "?user=1&a=2&b=3&c=4&d=5"
        )

        self.assertEqual(result.classification, "suspicious")
        self.assertGreaterEqual(result.risk_score, 35)
        self.assertIn("URL does not use HTTPS", result.risk_factors)
        self.assertTrue(result.threat_fingerprint_id.startswith("fp_"))
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


if __name__ == "__main__":
    unittest.main()
