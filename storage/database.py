import sqlite3
from pathlib import Path

import pandas as pd


DB_PATH = Path(__file__).parent / "nhi_trust.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cycle INTEGER,
            timestamp TEXT,
            identity_name TEXT,
            resource TEXT,
            action TEXT,
            bytes_transferred INTEGER,
            source_ip TEXT,
            success INTEGER,
            scenario TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cycle INTEGER,
            timestamp TEXT,
            identity_name TEXT,
            state TEXT,
            rule_score REAL,
            ml_score REAL,
            risk_score REAL,
            evidence_score REAL,
            baseline_updated TEXT,
            latency_ms REAL,
            scenario TEXT,
            reason TEXT
        )
        """
    )

    connection.commit()
    connection.close()


def save_event(cycle, event):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO events (
            cycle,
            timestamp,
            identity_name,
            resource,
            action,
            bytes_transferred,
            source_ip,
            success,
            scenario
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            cycle,
            event["timestamp"],
            event["identity"],
            event["resource"],
            event["action"],
            event["bytes_transferred"],
            event["source_ip"],
            int(event["success"]),
            event["scenario"],
        ),
    )

    connection.commit()
    connection.close()


def save_decision(cycle, decision):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO decisions (
            cycle,
            timestamp,
            identity_name,
            state,
            rule_score,
            ml_score,
            risk_score,
            evidence_score,
            baseline_updated,
            latency_ms,
            scenario,
            reason
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            cycle,
            decision["Time"],
            decision["Identity"],
            decision["State"],
            decision["Rule Score"],
            decision["ML Anomaly Score"],
            decision["Risk Score"],
            decision["Evidence Score"],
            decision["Baseline Updated"],
            decision["Latency (ms)"],
            decision["Scenario"],
            decision["Reason"],
        ),
    )

    connection.commit()
    connection.close()


def load_recent_decisions(limit=100):
    connection = get_connection()

    query = """
        SELECT
            cycle AS "Cycle",
            timestamp AS "Time",
            identity_name AS "Identity",
            state AS "State",
            rule_score AS "Rule Score",
            ml_score AS "ML Anomaly Score",
            risk_score AS "Risk Score",
            evidence_score AS "Evidence Score",
            baseline_updated AS "Baseline Updated",
            latency_ms AS "Latency (ms)",
            scenario AS "Scenario",
            reason AS "Reason"
        FROM decisions
        ORDER BY id DESC
        LIMIT ?
    """

    dataframe = pd.read_sql_query(
        query,
        connection,
        params=(limit,),
    )

    connection.close()
    return dataframe