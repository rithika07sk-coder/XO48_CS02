import streamlit as st
import pandas as pd
from pathlib import Path
import sqlite3


DB_PATH = Path(__file__).parent.parent / "storage" / "nhi_trust.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


st.set_page_config(page_title="Audit Log", page_icon="📜")
st.title("📜 Audit Log")


if not DB_PATH.exists():
    st.warning("No database file found. Run the main app first to generate data.")
    st.stop()


# Load all events and decisions without filters first to test
connection = get_connection()

# Simple query without parameters
events_query = """
    SELECT
        cycle AS "Cycle",
        timestamp AS "Time",
        identity_name AS "Identity",
        resource AS "Resource",
        action AS "Action",
        bytes_transferred AS "Bytes",
        source_ip AS "Source IP",
        success AS "Success",
        scenario AS "Scenario"
    FROM events
    ORDER BY id DESC
    LIMIT 200
"""

events_df = pd.read_sql_query(events_query, connection)


decisions_query = """
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
    LIMIT 200
"""

decisions_df = pd.read_sql_query(decisions_query, connection)

connection.close()


# Summary metrics
st.header("Summary")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Events", len(events_df))
col2.metric("Total Decisions", len(decisions_df))

if not decisions_df.empty:
    avg_risk = decisions_df["Risk Score"].mean()
else:
    avg_risk = 0.0

col3.metric("Avg Risk Score", f"{avg_risk:.2f}")

if not events_df.empty:
    success_rate = events_df["Success"].mean() * 100
else:
    success_rate = 0.0

col4.metric("Success Rate (%)", f"{success_rate:.1f}")


# Events table
st.header("Recent Events")
if not events_df.empty:
    st.dataframe(events_df, use_container_width=True)
else:
    st.warning("No events found in the database.")


# Decisions table
st.header("Recent Decisions")
if not decisions_df.empty:
    st.dataframe(decisions_df, use_container_width=True)
else:
    st.warning("No decisions found in the database.")