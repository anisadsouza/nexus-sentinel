import unittest

from nexus_sentinel.detector import analyze_url


class DetectorTests(unittest.TestCase):
    def test_safe_https_url_scores_low(self) -> None:
        result = analyze_url("https://example.com")

        self.assertEqual(result.classification, "safe")
        self.assertLess(result.risk_score, 35)
        self.assertEqual(result.risk_factors, ())

    def test_suspicious_url_accumulates_risk_factors(self) -> None:
        result = analyze_url(
            "http://secure-login.example.com.verify-account.test/reset"
            "?user=1&a=2&b=3&c=4&d=5"
        )

        self.assertEqual(result.classification, "suspicious")
        self.assertGreaterEqual(result.risk_score, 35)
        self.assertIn("URL does not use HTTPS", result.risk_factors)
        self.assertTrue(result.threat_fingerprint_id.startswith("fp_"))


if __name__ == "__main__":
    unittest.main()
