import unittest

from detector import analyze_email


class AnalyzeEmailTests(unittest.TestCase):
    def test_suspicious_language_and_risky_url_raise_score_with_reasons(self):
        result = analyze_email(
            "alerts@training.example",
            "Urgent action required",
            "Verify your account at http://192.0.2.4/login",
        )

        self.assertEqual(result["verdict"], "Suspicious")
        self.assertGreaterEqual(result["score"], 25)
        self.assertTrue(any("social-engineering language" in reason for reason in result["reasons"]))
        self.assertTrue(any("literal IP address" in reason for reason in result["reasons"]))

    def test_lookalike_sender_domain_is_reported(self):
        result = analyze_email(
            "security@micros0ft-login.example",
            "Synthetic notice",
            "This is a synthetic message.",
        )

        self.assertEqual(result["verdict"], "Suspicious")
        self.assertTrue(any("imitates Microsoft" in reason for reason in result["reasons"]))

    def test_coordinated_sender_url_and_credential_impersonation_is_phishing(self):
        result = analyze_email(
            "security@micros0ft-login.example",
            "URGENT: Verify Your Microsoft 365 Account",
            "This synthetic message requests immediate password verification at "
            "https://micros0ft-login.example/verify",
        )

        self.assertEqual(result["verdict"], "Phishing")
        self.assertGreaterEqual(result["score"], 60)
        self.assertLessEqual(result["score"], 100)
        self.assertTrue(any("Sender domain" in reason and "imitates Microsoft" in reason for reason in result["reasons"]))
        self.assertTrue(any("URL host" in reason and "imitates Microsoft" in reason for reason in result["reasons"]))
        self.assertTrue(any("password or credential" in reason for reason in result["reasons"]))
        self.assertTrue(any("coordinated impersonation" in reason for reason in result["reasons"]))

    def test_lookalike_url_is_flagged_without_fetching_it(self):
        result = analyze_email(
            "alerts@training.example",
            "Synthetic account notice",
            "Review this training link: https://micros0ft-login.example/verify",
        )

        self.assertEqual(result["verdict"], "Suspicious")
        self.assertTrue(any("URL host" in reason and "imitates Microsoft" in reason for reason in result["reasons"]))

    def test_credential_request_is_reported_without_automatically_calling_phishing(self):
        result = analyze_email(
            "helpdesk@company.example",
            "Synthetic account review",
            "This synthetic message asks the user to verify their password.",
        )

        self.assertEqual(result["verdict"], "Suspicious")
        self.assertTrue(any("password or credential" in reason for reason in result["reasons"]))

    def test_legitimate_urgent_message_and_official_url_are_not_phishing(self):
        result = analyze_email(
            "events@company.example",
            "URGENT: Updated meeting schedule",
            "Please review the agenda before noon at https://calendar.google.com/",
        )

        self.assertEqual(result["verdict"], "Clean")
        self.assertEqual(result["score"], 0)

    def test_benign_synthetic_email_is_clean_and_score_is_bounded(self):
        result = analyze_email(
            "team@company.example",
            "Synthetic meeting notes",
            "Here are the notes from our planning meeting.",
        )

        self.assertEqual(result["verdict"], "Clean")
        self.assertEqual(result["score"], 0)
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)


if __name__ == "__main__":
    unittest.main()
