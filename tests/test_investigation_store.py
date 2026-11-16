import unittest
from unittest.mock import patch

from investigation_store import (
    PUBLIC_DEMO_SESSION_KEY,
    get_dashboard_data,
    initialize_storage,
    is_public_demo,
    save_investigation,
)


class PublicDemoStorageTests(unittest.TestCase):
    def test_public_demo_data_is_isolated_between_sessions(self):
        first_session = {}
        second_session = {}
        initialize_storage(True, first_session)
        initialize_storage(True, second_session)

        initial_counts, initial_rows = get_dashboard_data(True, first_session)
        self.assertEqual(initial_counts["total"], 3)
        self.assertTrue(all(row["synthetic"] for row in initial_rows))

        save_investigation(
            True,
            first_session,
            "analyst@training.example",
            "Synthetic private submission",
            "Private synthetic body for the first session.",
            {
                "score": 0,
                "verdict": "Clean",
                "reasons": ["No configured warning rules matched."],
            },
        )

        first_counts, first_rows = get_dashboard_data(True, first_session)
        second_counts, second_rows = get_dashboard_data(True, second_session)
        self.assertEqual(first_counts["total"], 4)
        self.assertEqual(second_counts["total"], 3)
        self.assertIn("Private synthetic body for the first session.", first_session[PUBLIC_DEMO_SESSION_KEY][-1]["body"])
        self.assertNotIn(
            "Synthetic private submission",
            [row["subject"] for row in second_rows],
        )
        self.assertEqual(len(first_rows), 4)

    def test_public_mode_does_not_initialize_read_or_write_sqlite(self):
        session_state = {}
        result = {"score": 0, "verdict": "Clean", "reasons": []}

        with (
            patch("database.initialize_database") as initialize_database,
            patch("database.get_dashboard_data") as read_database,
            patch("database.save_investigation") as write_database,
        ):
            initialize_storage(True, session_state)
            get_dashboard_data(True, session_state)
            save_investigation(
                True,
                session_state,
                "analyst@training.example",
                "Synthetic message",
                "Synthetic body",
                result,
            )

        initialize_database.assert_not_called()
        read_database.assert_not_called()
        write_database.assert_not_called()

    def test_public_mode_requires_exact_explicit_setting(self):
        self.assertTrue(is_public_demo({"CYBERSHIELD_PUBLIC_DEMO": "1"}))
        self.assertFalse(is_public_demo({"CYBERSHIELD_PUBLIC_DEMO": "true"}))
        self.assertFalse(is_public_demo({"CYBERSHIELD_PUBLIC_DEMO": "0"}))
        self.assertTrue(is_public_demo({}, cloud_secret="1"))
        self.assertFalse(is_public_demo({}, cloud_secret="true"))


if __name__ == "__main__":
    unittest.main()
