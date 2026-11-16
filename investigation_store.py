"""Select local SQLite persistence or session-isolated public demo storage."""

from __future__ import annotations

import os
from collections.abc import Mapping, MutableMapping
from datetime import datetime, timezone
from typing import Any

PUBLIC_DEMO_SESSION_KEY = "cybershield_public_demo_investigations"
SessionState = MutableMapping[str, Any]


def is_public_demo(
    environment: Mapping[str, str] | None = None,
    cloud_secret: str | None = None,
) -> bool:
    """Enable public mode only when explicitly set to ``1``."""
    settings = os.environ if environment is None else environment
    if "CYBERSHIELD_PUBLIC_DEMO" in settings:
        return settings["CYBERSHIELD_PUBLIC_DEMO"] == "1"
    return cloud_secret == "1"


def _session_investigations(session_state: SessionState | None) -> list[dict]:
    if session_state is None:
        raise ValueError("Public demo mode requires a per-session state mapping.")

    investigations = session_state.get(PUBLIC_DEMO_SESSION_KEY)
    if investigations is None:
        from database import SYNTHETIC_EMAILS
        from detector import analyze_email

        investigations = []
        for index, email in enumerate(SYNTHETIC_EMAILS, start=1):
            result = analyze_email(email["sender"], email["subject"], email["body"])
            investigations.append(
                {
                    "id": index,
                    "analyzed_at": f"2026-01-01T00:{index:02d}:00+00:00",
                    **email,
                    **result,
                    "synthetic": True,
                }
            )
        session_state[PUBLIC_DEMO_SESSION_KEY] = investigations
    return investigations


def initialize_storage(
    public_demo: bool, session_state: SessionState | None = None
) -> None:
    if public_demo:
        _session_investigations(session_state)
        return

    from database import initialize_database

    initialize_database()


def get_dashboard_data(
    public_demo: bool, session_state: SessionState | None = None
) -> tuple[dict, list[dict]]:
    if not public_demo:
        from database import get_dashboard_data as get_local_dashboard_data

        return get_local_dashboard_data()

    investigations = _session_investigations(session_state)
    counts = {"total": len(investigations), "Phishing": 0, "Suspicious": 0, "Clean": 0}
    for investigation in investigations:
        counts[investigation["verdict"]] += 1
    return counts, investigations


def save_investigation(
    public_demo: bool,
    session_state: SessionState | None,
    sender: str,
    subject: str,
    body: str,
    result: dict,
) -> None:
    if not public_demo:
        from database import save_investigation as save_local_investigation

        save_local_investigation(sender, subject, result)
        return

    investigations = _session_investigations(session_state)
    investigations.append(
        {
            "id": len(investigations) + 1,
            "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "sender": sender.strip(),
            "subject": subject.strip(),
            "body": body,
            **result,
            "synthetic": True,
        }
    )
