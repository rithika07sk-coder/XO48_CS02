import random
import time
from collections import Counter, deque
from datetime import datetime

import pandas as pd
import streamlit as st


st.set_page_config(
    page_title="NHI Adaptive Trust",
    page_icon="🛡️",
    layout="wide",
)


IDENTITIES = [
    "service_alpha",
    "worker_beta",
    "deploy_gamma",
    "api_delta",
]


NORMAL_RESOURCES = [
    "customer_db",
    "orders_db",
    "logs_bucket",
    "metrics_api",
]


SENSITIVE_RESOURCES = [
    "secrets_vault",
    "admin_console",
    "production_backup",
]


STATES = [
    "NORMAL",
    "DRIFTING",
    "SUSPICIOUS",
    "HIGH_RISK",
]


ICONS = {
    "NORMAL": "🟢",
    "DRIFTING": "🟡",
    "SUSPICIOUS": "🟠",
    "HIGH_RISK": "🔴",
}


def create_profile():
    return {
        "trusted_resources": Counter(),
        "trusted_actions": Counter(),
        "trusted_ips": Counter(),
        "total_events": 0,
        "average_bytes": 0.0,
        "quarantine": Counter(),
        "recent_scores": deque(maxlen=5),
        "state": "NORMAL",
        "last_reason": "Waiting for the first event.",
        "baseline_updated": False,
        "state_changes": 0,
        "last_event": None,
    }


def create_event(identity, scenario):
    event = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "identity": identity,
        "resource": random.choice(NORMAL_RESOURCES),
        "action": random.choice(["READ", "WRITE"]),
        "bytes_transferred": random.randint(700, 2800),
        "source_ip": f"10.0.0.{random.randint(2, 20)}",
        "success": True,
        "scenario": scenario,
    }

    if scenario == "DRIFTING":
        event["resource"] = "reporting_api"
        event["bytes_transferred"] = random.randint(1200, 4000)

    elif scenario == "SUSPICIOUS":
        event["resource"] = random.choice(
            NORMAL_RESOURCES + ["analytics_db"]
        )
        event["action"] = random.choice(
            ["READ", "WRITE", "EXECUTE"]
        )
        event["bytes_transferred"] = random.randint(4000, 10000)
        event["source_ip"] = f"172.16.10.{random.randint(2, 200)}"

    elif scenario == "HIGH_RISK":
        event["resource"] = random.choice(SENSITIVE_RESOURCES)
        event["action"] = random.choice(
            ["READ", "DELETE", "EXECUTE"]
        )
        event["bytes_transferred"] = random.randint(10000, 50000)
        event["source_ip"] = f"203.0.113.{random.randint(2, 200)}"
        event["success"] = random.choice([True, True, False])

    return event


def update_baseline(profile, event):
    previous_count = profile["total_events"]

    profile["total_events"] += 1
    profile["trusted_resources"][event["resource"]] += 1
    profile["trusted_actions"][event["action"]] += 1
    profile["trusted_ips"][event["source_ip"]] += 1

    profile["average_bytes"] = (
        profile["average_bytes"] * previous_count
        + event["bytes_transferred"]
    ) / profile["total_events"]


def analyze_event(profile, event):
    if profile["total_events"] < 5:
        update_baseline(profile, event)

        return {
            "state": "NORMAL",
            "risk_score": 0.0,
            "reasons": [
                "Warm-up: collecting trusted baseline behavior."
            ],
            "baseline_updated": True,
        }

    score = 0.0
    reasons = []

    if event["resource"] not in profile["trusted_resources"]:
        score += 0.30
        reasons.append(
            f"New resource: {event['resource']}"
        )

    if event["action"] not in profile["trusted_actions"]:
        score += 0.20
        reasons.append(
            f"New action: {event['action']}"
        )

    if event["source_ip"] not in profile["trusted_ips"]:
        score += 0.20
        reasons.append(
            f"New source IP: {event['source_ip']}"
        )

    average_bytes = max(profile["average_bytes"], 1)

    if event["bytes_transferred"] > average_bytes * 3:
        score += 0.25
        reasons.append(
            "Data volume exceeds 3x baseline average."
        )

    if not event["success"]:
        score += 0.15
        reasons.append("Operation failed.")

    if event["resource"] in SENSITIVE_RESOURCES:
        score += 0.35
        reasons.append(
            f"Sensitive resource: {event['resource']}"
        )

    score = min(score, 1.0)

    profile["recent_scores"].append(score)

    recent_average = sum(
        profile["recent_scores"]
    ) / len(profile["recent_scores"])

    if score >= 0.80:
        state = "HIGH_RISK"

    elif (
        event["resource"] in SENSITIVE_RESOURCES
        and score >= 0.50
    ):
        state = "HIGH_RISK"

    elif score >= 0.55 or recent_average >= 0.50:
        state = "SUSPICIOUS"

    elif score >= 0.25:
        state = "DRIFTING"

    else:
        state = "NORMAL"

    baseline_updated = False

    if state == "NORMAL":
        update_baseline(profile, event)
        baseline_updated = True

        reasons.append(
            "Matches trusted baseline; profile updated."
        )

    elif state == "DRIFTING":
        resource = event["resource"]
        profile["quarantine"][resource] += 1

        observed_count = profile["quarantine"][resource]

        if observed_count >= 3:
            update_baseline(profile, event)
            baseline_updated = True

            reasons.append(
                f"Verified legitimate drift: {resource} "
                f"observed {observed_count} times and promoted "
                "to trusted baseline."
            )
        else:
            reasons.append(
                f"Low-risk drift quarantined: {resource} "
                f"observed {observed_count}/3 times."
            )

    else:
        profile["quarantine"][event["resource"]] += 1

        reasons.append(
            "Excluded from trusted learning to prevent "
            "baseline poisoning."
        )

    if not reasons:
        reasons.append("No meaningful deviation detected.")

    return {
        "state": state,
        "risk_score": round(score, 2),
        "reasons": reasons,
        "baseline_updated": baseline_updated,
    }


def reset_demo():
    st.session_state.profiles = {
        identity: create_profile()
        for identity in IDENTITIES
    }

    st.session_state.events = []
    st.session_state.decisions = []
    st.session_state.cycle = 0


def get_scenarios(cycle):
    scenarios = {
        "service_alpha": "NORMAL",
        "worker_beta": "NORMAL",
        "deploy_gamma": "NORMAL",
        "api_delta": "NORMAL",
    }

    if 6 <= cycle < 12:
        scenarios["worker_beta"] = "DRIFTING"

    elif 12 <= cycle < 18:
        scenarios["deploy_gamma"] = "SUSPICIOUS"

    elif cycle >= 18:
        scenarios["api_delta"] = "HIGH_RISK"

    return scenarios


def generate_cycle():
    st.session_state.cycle += 1
    cycle = st.session_state.cycle

    scenarios = get_scenarios(cycle)

    for identity, scenario in scenarios.items():
        event = create_event(identity, scenario)
        profile = st.session_state.profiles[identity]

        previous_state = profile["state"]

        started = time.perf_counter()
        decision = analyze_event(profile, event)

        latency_ms = round(
            (time.perf_counter() - started) * 1000,
            3,
        )

        new_state = decision["state"]

        if previous_state != new_state:
            profile["state_changes"] += 1

        profile["state"] = new_state
        profile["last_reason"] = " | ".join(
            decision["reasons"]
        )
        profile["baseline_updated"] = (
            decision["baseline_updated"]
        )
        profile["last_event"] = event

        st.session_state.events.append(event)

        st.session_state.decisions.append(
            {
                "Cycle": cycle,
                "Time": event["timestamp"],
                "Identity": identity,
                "State": new_state,
                "Risk Score": decision["risk_score"],
                "Baseline Updated": (
                    "Yes"
                    if decision["baseline_updated"]
                    else "No"
                ),
                "Latency (ms)": latency_ms,
                "Scenario": scenario,
                "Reason": " | ".join(
                    decision["reasons"]
                ),
            }
        )

    st.session_state.events = (
        st.session_state.events[-100:]
    )

    st.session_state.decisions = (
        st.session_state.decisions[-100:]
    )


def decisions_dataframe():
    if not st.session_state.decisions:
        return pd.DataFrame()

    return pd.DataFrame(st.session_state.decisions)


def events_dataframe():
    if not st.session_state.events:
        return pd.DataFrame()

    return pd.DataFrame(st.session_state.events)


def calculate_metrics(decisions):
    if decisions.empty:
        return {
            "total_events": 0,
            "baseline_updates": 0,
            "baseline_protected": 0,
            "suspicious_events": 0,
            "high_risk_events": 0,
            "poisoning_blocked": 0,
            "average_latency": 0.0,
            "drift_events": 0,
            "drift_promotions": 0,
            "drift_promotion_rate": 0.0,
        }

    total_events = len(decisions)

    baseline_updates = int(
        (
            decisions["Baseline Updated"] == "Yes"
        ).sum()
    )

    baseline_protected = (
        total_events - baseline_updates
    )

    suspicious_events = int(
        (
            decisions["State"] == "SUSPICIOUS"
        ).sum()
    )

    high_risk_events = int(
        (
            decisions["State"] == "HIGH_RISK"
        ).sum()
    )

    poisoning_rows = decisions[
        decisions["State"].isin(
            ["SUSPICIOUS", "HIGH_RISK"]
        )
    ]

    poisoning_blocked = int(
        (
            poisoning_rows["Baseline Updated"] == "No"
        ).sum()
    )

    drift_rows = decisions[
        decisions["State"] == "DRIFTING"
    ]

    drift_events = len(drift_rows)

    drift_promotions = int(
        (
            drift_rows["Baseline Updated"] == "Yes"
        ).sum()
    )

    if drift_events:
        drift_promotion_rate = round(
            drift_promotions / drift_events,
            3,
        )
    else:
        drift_promotion_rate = 0.0

    average_latency = round(
        decisions["Latency (ms)"].mean(),
        3,
    )

    return {
        "total_events": total_events,
        "baseline_updates": baseline_updates,
        "baseline_protected": baseline_protected,
        "suspicious_events": suspicious_events,
        "high_risk_events": high_risk_events,
        "poisoning_blocked": poisoning_blocked,
        "average_latency": average_latency,
        "drift_events": drift_events,
        "drift_promotions": drift_promotions,
        "drift_promotion_rate": drift_promotion_rate,
    }


def render_overview():
    st.title(
        "🛡️ Adaptive Behavioral Trust "
        "for Non-Human Identities"
    )

    st.caption(
        "Cyber Security PS-02 | Real-time behavioral "
        "monitoring, controlled adaptation, and "
        "baseline-poisoning protection."
    )

    st.subheader(
        "Baseline Poisoning Resistance Challenge"
    )

    st.info(
        "Unknown low-risk behavior is quarantined and "
        "promoted only after repeated safe observations. "
        "Suspicious and high-risk behavior is excluded "
        "from trusted learning."
    )

    challenge_left, challenge_right = st.columns(2)

    with challenge_left:
        st.markdown(
            "### Legitimate Drift\n"
            "A new reporting resource is quarantined "
            "and promoted only after three safe "
            "observations."
        )

    with challenge_right:
        st.markdown(
            "### Poisoning Attempt\n"
            "Suspicious or high-risk activity is "
            "quarantined and never becomes trusted "
            "baseline behavior."
        )

    st.divider()

    control1, control2, control3, control4 = st.columns(
        [1, 1, 1, 3]
    )

    with control1:
        if st.button(
            "Generate One Cycle",
            width="stretch",
        ):
            generate_cycle()

    with control2:
        st.checkbox(
            "Auto-run simulation",
            key="auto_run",
        )

    with control3:
        if st.button(
            "Reset Demo",
            width="stretch",
        ):
            reset_demo()

    with control4:
        st.info(
            f"Simulation cycle: "
            f"{st.session_state.cycle}. "
            "Cycles 1-5: baseline; cycles 6-11: "
            "drift; cycles 12-17: suspicious; "
            "cycle 18+: high risk."
        )

    state_columns = st.columns(4)

    for column, state in zip(
        state_columns,
        STATES,
    ):
        count = sum(
            profile["state"] == state
            for profile in st.session_state.profiles.values()
        )

        column.metric(
            f"{ICONS[state]} {state}",
            count,
        )

    decisions = decisions_dataframe()
    metrics = calculate_metrics(decisions)

    st.subheader("Live Evaluation Metrics")

    metric1, metric2, metric3, metric4 = st.columns(4)

    metric1.metric(
        "Events Processed",
        metrics["total_events"],
    )

    metric2.metric(
        "Baseline Updates",
        metrics["baseline_updates"],
    )

    metric3.metric(
        "Baseline Protected",
        metrics["baseline_protected"],
    )

    metric4.metric(
        "Avg Decision Latency",
        f"{metrics['average_latency']} ms",
    )

    metric5, metric6, metric7, metric8 = st.columns(4)

    metric5.metric(
        "Suspicious Events",
        metrics["suspicious_events"],
    )

    metric6.metric(
        "High-Risk Events",
        metrics["high_risk_events"],
    )

    metric7.metric(
        "Poisoning Attempts Blocked",
        metrics["poisoning_blocked"],
    )

    metric8.metric(
        "Drift Promotion Rate",
        f"{metrics['drift_promotion_rate'] * 100:.1f}%",
    )

    st.subheader("Identity Trust Overview")

    overview = []

    for identity, profile in (
        st.session_state.profiles.items()
    ):
        if profile["recent_scores"]:
            recent_risk = round(
                sum(profile["recent_scores"])
                / len(profile["recent_scores"]),
                2,
            )
        else:
            recent_risk = 0.0

        overview.append(
            {
                "Identity": identity,
                "State": (
                    f"{ICONS[profile['state']]} "
                    f"{profile['state']}"
                ),
                "Recent Risk": recent_risk,
                "Trusted Events": profile[
                    "total_events"
                ],
                "Quarantined Resources": len(
                    profile["quarantine"]
                ),
                "State Changes": profile[
                    "state_changes"
                ],
                "Baseline Updated": (
                    "Yes"
                    if profile["baseline_updated"]
                    else "No"
                ),
            }
        )

    st.dataframe(
        pd.DataFrame(overview),
        width="stretch",
        hide_index=True,
    )

    st.subheader("Latest Decisions")

    if not decisions.empty:
        st.dataframe(
            decisions.iloc[::-1],
            width="stretch",
            hide_index=True,
        )

        csv_data = decisions.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            "Download Decision Log",
            data=csv_data,
            file_name="decision_log.csv",
            mime="text/csv",
            width="stretch",
        )
    else:
        st.warning(
            "No events available. Click Generate One "
            "Cycle to begin."
        )

    st.subheader("Risk Score Over Time")

    if not decisions.empty:
        chart_data = decisions.copy()
        chart_data["Event"] = range(
            1,
            len(chart_data) + 1,
        )

        chart = chart_data.pivot(
            index="Event",
            columns="Identity",
            values="Risk Score",
        )

        st.line_chart(
            chart,
            width="stretch",
            height=350,
        )
    else:
        st.write(
            "Generate events to display risk trends."
        )

    st.subheader("State Distribution")

    if not decisions.empty:
        state_counts = (
            decisions["State"]
            .value_counts()
            .reindex(STATES, fill_value=0)
        )

        st.bar_chart(
            state_counts,
            width="stretch",
            height=300,
        )

    st.subheader("Identity Explanation")

    selected_identity = st.selectbox(
        "Select an identity",
        IDENTITIES,
    )

    profile = st.session_state.profiles[
        selected_identity
    ]

    st.markdown(
        f"### {ICONS[profile['state']]} "
        f"{selected_identity}"
    )

    st.write(
        f"**Current state:** {profile['state']}"
    )

    st.write(
        f"**Trusted baseline events:** "
        f"{profile['total_events']}"
    )

    st.write(
        "**Trusted average data volume:** "
        f"{round(profile['average_bytes'], 2)} bytes"
    )

    st.write(
        f"**State changes:** "
        f"{profile['state_changes']}"
    )

    st.write(
        f"**Latest explanation:** "
        f"{profile['last_reason']}"
    )

    if profile["baseline_updated"]:
        st.success(
            "Baseline decision: trusted behavior "
            "updated the identity profile."
        )
    else:
        st.warning(
            "Baseline decision: behavior was "
            "quarantined or excluded; baseline protected."
        )

    trusted_column, quarantined_column = st.columns(2)

    with trusted_column:
        st.write("#### Trusted Resources")

        if profile["trusted_resources"]:
            st.json(
                dict(profile["trusted_resources"])
            )
        else:
            st.write("No trusted resources yet.")

    with quarantined_column:
        st.write("#### Quarantined Resources")

        if profile["quarantine"]:
            st.json(
                dict(profile["quarantine"])
            )
        else:
            st.write("No quarantined resources yet.")

    st.subheader("Recent Event Stream")

    events = events_dataframe()

    if not events.empty:
        st.dataframe(
            events.iloc[::-1],
            width="stretch",
            hide_index=True,
        )

        event_csv = events.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            "Download Event Log",
            data=event_csv,
            file_name="event_log.csv",
            mime="text/csv",
            width="stretch",
        )

    if st.session_state.auto_run:
        time.sleep(1)
        generate_cycle()
        st.rerun()


def render_explore():
    st.title("🔎 Explore the Trust Engine")

    st.caption(
        "Use this page to understand the threat model, "
        "behavioral features, adaptation policy, and "
        "evaluation methodology."
    )

    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        [
            "Threat Model",
            "Trust States",
            "Adaptation Logic",
            "Evaluation",
            "Limitations",
        ]
    )

    with tab1:
        st.subheader("Threat Model")

        st.markdown(
            """
            The system monitors synthetic Non-Human Identities
            such as service accounts, workload identities, API
            identities, and deployment identities.

            The main threat is a compromised identity using valid
            credentials while gradually changing its behavior.

            The attacker may access unfamiliar resources, use
            unfamiliar actions, connect from a new source IP,
            transfer unusually large data volumes, or access
            sensitive resources.

            The system does not access real credentials, production
            systems, customer data, or external infrastructure.
            """
        )

        st.warning(
            "This demonstration uses simulated identities and "
            "sandboxed resources only."
        )

    with tab2:
        st.subheader("Trust-State Definitions")

        state_table = pd.DataFrame(
            [
                {
                    "State": "NORMAL",
                    "Meaning": (
                        "Behavior matches the trusted baseline."
                    ),
                    "Learning": "Baseline may be updated.",
                },
                {
                    "State": "DRIFTING",
                    "Meaning": (
                        "Low-risk behavior differs from baseline."
                    ),
                    "Learning": (
                        "Quarantined until repeated safely."
                    ),
                },
                {
                    "State": "SUSPICIOUS",
                    "Meaning": (
                        "Several unusual signals are present."
                    ),
                    "Learning": (
                        "Excluded from trusted learning."
                    ),
                },
                {
                    "State": "HIGH_RISK",
                    "Meaning": (
                        "Severe deviation or sensitive access."
                    ),
                    "Learning": (
                        "Excluded from trusted learning."
                    ),
                },
            ]
        )

        st.dataframe(
            state_table,
            width="stretch",
            hide_index=True,
        )

    with tab3:
        st.subheader("Controlled Adaptation")

        st.markdown(
            """
            The system first collects five warm-up events for
            each identity.

            Normal behavior updates the trusted profile
            immediately.

            Low-risk unfamiliar behavior enters quarantine.
            It must be observed at least three times before
            it can influence the trusted baseline.

            Suspicious and high-risk observations are recorded
            for investigation but are not trusted for learning.

            This prevents a compromised identity from immediately
            poisoning its own baseline.
            """
        )

        st.code(
            """
Warm-up event
      |
      v
Compare with identity baseline
      |
      +-- Normal ------> Update baseline
      |
      +-- Low-risk ----> Quarantine
      |                   |
      |                   +-- 3 safe observations
      |                       -> Promote to baseline
      |
      +-- Suspicious ---> Exclude from learning
      |
      +-- High-risk ----> Exclude from learning
            """,
            language="text",
        )

    with tab4:
        st.subheader("Evaluation Metrics")

        evaluation_table = pd.DataFrame(
            [
                {
                    "Metric": "Decision latency",
                    "Purpose": (
                        "Measures runtime responsiveness."
                    ),
                },
                {
                    "Metric": "Baseline protection",
                    "Purpose": (
                        "Counts observations excluded from learning."
                    ),
                },
                {
                    "Metric": "Poisoning blocked",
                    "Purpose": (
                        "Measures suspicious and high-risk events "
                        "kept out of the baseline."
                    ),
                },
                {
                    "Metric": "Drift promotion rate",
                    "Purpose": (
                        "Measures controlled adaptation to repeated "
                        "legitimate change."
                    ),
                },
                {
                    "Metric": "State distribution",
                    "Purpose": (
                        "Shows normal, drift, suspicious, and "
                        "high-risk outcomes."
                    ),
                },
            ]
        )

        st.dataframe(
            evaluation_table,
            width="stretch",
            hide_index=True,
        )

        st.info(
            "For final evaluation, capture screenshots showing "
            "baseline learning, drift quarantine, drift promotion, "
            "suspicious detection, and high-risk exclusion."
        )

    with tab5:
        st.subheader("Known Limitations")

        st.markdown(
            """
            - The current demonstration uses synthetic events.
            - Risk weights are rule-based and manually selected.
            - The baseline is stored in Streamlit session state.
            - Data is lost when the application is restarted.
            - No real SIEM, EDR, IAM, database, or production
              integration is included.
            - The system demonstrates adaptive trust logic but is
              not a complete enterprise security product.
            """
        )


if "profiles" not in st.session_state:
    reset_demo()

if "auto_run" not in st.session_state:
    st.session_state.auto_run = False

if "page" not in st.session_state:
    st.session_state.page = "Dashboard"


with st.sidebar:
    st.title("🛡️ NHI Trust")

    st.session_state.page = st.radio(
        "Navigate",
        ["Dashboard", "Explore"],
        index=(
            0
            if st.session_state.page == "Dashboard"
            else 1
        ),
    )

    st.divider()

    st.markdown(
        """
        **Project:** Adaptive Behavioral Trust

        **Problem:** Cyber Security PS-02

        **Purpose:** Detect behavioral change while
        preventing baseline poisoning.
        """
    )


if st.session_state.page == "Dashboard":
    render_overview()
else:
    render_explore()