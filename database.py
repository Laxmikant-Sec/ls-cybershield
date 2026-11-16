"""Local SQLite storage for synthetic training investigations."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from detector import analyze_email

DB_PATH = Path(__file__).with_name("cybershield.sqlite3")

SYNTHETIC_EMAILS = (
    {
        "sender": "Security Team <security@micros0ft-login.example>",
        "subject": "Urgent action required: verify your account",
        "body": "Synthetic training message. Verify your account at http://192.0.2.10/login",
    },
    {
        "sender": "Parcel Updates <tracking@delivery-notice.example>",
        "subject": "Your package delivery update",
        "body": "Synthetic training message. No action is required; this is a benign notice.",
    },
    {
        "sender": "Payroll Desk <payroll@company.example>",
        "subject": "Synthetic payroll review",
        "body": "Review the synthetic payroll summary at http://links.training.example/payroll",
    },
)


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database() -> None:
    with _connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analyzed_at TEXT NOT NULL,
                sender TEXT NOT NULL,
                subject TEXT NOT NULL,
                score INTEGER NOT NULL CHECK(score BETWEEN 0 AND 100),
                verdict TEXT NOT NULL CHECK(verdict IN ('Phishing', 'Suspicious', 'Clean')),
                reasons_json TEXT NOT NULL,
                synthetic INTEGER NOT NULL DEFAULT 1 CHECK(synthetic = 1)
            )
            """
        )
        count = connection.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]
        if count == 0:
            for email in SYNTHETIC_EMAILS:
                result = analyze_email(email["sender"], email["subject"], email["body"])
                _insert_result(connection, email["sender"], email["subject"], result)


def _insert_result(
    connection: sqlite3.Connection, sender: str, subject: str, result: dict
) -> None:
    connection.execute(
        """
        INSERT INTO investigations
            (analyzed_at, sender, subject, score, verdict, reasons_json, synthetic)
        VALUES (?, ?, ?, ?, ?, ?, 1)
        """,
        (
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            sender.strip(),
            subject.strip(),
            result["score"],
            result["verdict"],
            json.dumps(result["reasons"]),
        ),
    )


def save_investigation(sender: str, subject: str, result: dict) -> None:
    with _connect() as connection:
        _insert_result(connection, sender, subject, result)


def get_dashboard_data() -> tuple[dict, list[dict]]:
    with _connect() as connection:
        rows = connection.execute(
            """
            SELECT id, analyzed_at, sender, subject, score, verdict, reasons_json
            FROM investigations
            ORDER BY id DESC
            """
        ).fetchall()

    investigations = [
        {
            **dict(row),
            "reasons": json.loads(row["reasons_json"]),
            "synthetic": True,
        }
        for row in rows
    ]
    counts = {"total": len(rows), "Phishing": 0, "Suspicious": 0, "Clean": 0}
    for row in rows:
        counts[row["verdict"]] += 1
    return counts, investigations
