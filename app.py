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
        reasons.append(f"New resource: {event['resource']}")

    if event["action"] not in profile["trusted_actions"]:
        score += 0.20
        reasons.append(f"New action: {event['action']}")

    if event["source_ip"] not in profile["trusted_ips"]:
        score += 0.20
        reasons.append(f"New source IP: {event['source_ip']}")

    average_bytes = max(profile["average_bytes"], 1)

    if event["bytes_transferred"] > average_bytes * 3:
        score += 0.25
        reasons.append("Data volume exceeds 3x baseline average.")

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

    recent_average = sum(profile["recent_scores"]) / len(
        profile["recent_scores"]
    )

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
                f"Verified legitimate drift: {resource} observed "
                f"{observed_count} times and promoted to trusted baseline."
            )

        else:
            reasons.append(
                f"Low-risk drift quarantined: {resource} observed "
                f"{observed_count}/3 times."
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


def generate_cycle():
    st.session_state.cycle += 1
    cycle = st.session_state.cycle

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

    for identity, scenario in scenarios.items():
        event = create_event(identity, scenario)
        profile = st.session_state.profiles[identity]

        started = time.perf_counter()

        decision = analyze_event(profile, event)

        latency_ms = round(
            (time.perf_counter() - started) * 1000,
            3,
        )

        profile["state"] = decision["state"]
        profile["last_reason"] = " | ".join(
            decision["reasons"]
        )
        profile["baseline_updated"] = decision[
            "baseline_updated"
        ]

        st.session_state.events.append(event)

        st.session_state.decisions.append(
            {
                "Time": event["timestamp"],
                "Identity": identity,
                "State": decision["state"],
                "Risk Score": decision["risk_score"],
                "Baseline Updated": (
                    "Yes"
                    if decision["baseline_updated"]
                    else "No"
                ),
                "Latency (ms)": latency_ms,
                "Reason": " | ".join(decision["reasons"]),
            }
        )

    st.session_state.events = st.session_state.events[-100:]
    st.session_state.decisions = st.session_state.decisions[-100:]


if "profiles" not in st.session_state:
    reset_demo()

if "auto_run" not in st.session_state:
    st.session_state.auto_run = False


ICONS = {
    "NORMAL": "🟢",
    "DRIFTING": "🟡",
    "SUSPICIOUS": "🟠",
    "HIGH_RISK": "🔴",
}


st.title("🛡️ Adaptive Behavioral Trust for Non-Human Identities")

st.caption(
    "Cyber Security PS-02 | Real-time behavior monitoring, "
    "drift detection, controlled adaptation, and baseline protection."
)


st.subheader("Baseline Poisoning Resistance Challenge")

st.info(
    "Unknown low-risk behavior is quarantined and promoted only "
    "after repeated safe observations. Suspicious and high-risk "
    "behavior is excluded from trusted learning."
)

challenge_left, challenge_right = st.columns(2)

with challenge_left:
    st.markdown(
        "### Legitimate Drift\n"
        "A new reporting resource is quarantined and promoted "
        "only after three safe observations."
    )

with challenge_right:
    st.markdown(
        "### Poisoning Attempt\n"
        "Suspicious or high-risk activity is quarantined or blocked "
        "and never becomes trusted baseline behavior."
    )


st.divider()


control1, control2, control3, control4 = st.columns([1, 1, 1, 3])

with control1:
    if st.button("Generate One Cycle", use_container_width=True):
        generate_cycle()

with control2:
    st.checkbox("Auto-run simulation", key="auto_run")

with control3:
    if st.button("Reset Demo", use_container_width=True):
        reset_demo()

with control4:
    st.info(
        f"Simulation cycle: {st.session_state.cycle}. "
        "Cycles 1-5: baseline; cycles 6-11: drift; "
        "cycles 12-17: suspicious; cycle 18+: high risk."
    )


state_columns = st.columns(4)

for column, state in zip(state_columns, ICONS):
    count = sum(
        profile["state"] == state
        for profile in st.session_state.profiles.values()
    )

    column.metric(
        f"{ICONS[state]} {state}",
        count,
    )


st.subheader("Live Evaluation Metrics")

decisions = st.session_state.decisions
total_events = len(decisions)

baseline_updates = sum(
    item["Baseline Updated"] == "Yes"
    for item in decisions
)

if total_events:
    average_latency = round(
        sum(
            item["Latency (ms)"]
            for item in decisions
        ) / total_events,
        3,
    )
else:
    average_latency = 0.0

metric1, metric2, metric3, metric4 = st.columns(4)

metric1.metric("Events Processed", total_events)
metric2.metric("Baseline Updates", baseline_updates)
metric3.metric(
    "Baseline Protected",
    total_events - baseline_updates,
)
metric4.metric(
    "Avg Decision Latency",
    f"{average_latency} ms",
)


st.subheader("Identity Trust Overview")

overview = []

for identity, profile in st.session_state.profiles.items():
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
            "Trusted Events": profile["total_events"],
            "Quarantined Resources": len(
                profile["quarantine"]
            ),
            "Baseline Updated": (
                "Yes"
                if profile["baseline_updated"]
                else "No"
            ),
        }
    )

st.dataframe(
    pd.DataFrame(overview),
    use_container_width=True,
    hide_index=True,
)


st.subheader("Latest Decisions")

if decisions:
    st.dataframe(
        pd.DataFrame(decisions[::-1]),
        use_container_width=True,
        hide_index=True,
    )
else:
    st.warning(
        "No events available. Click Generate One Cycle to begin."
    )


st.subheader("Identity Explanation")

selected_identity = st.selectbox(
    "Select an identity",
    IDENTITIES,
)

profile = st.session_state.profiles[selected_identity]

st.markdown(
    f"### {ICONS[profile['state']]} {selected_identity}"
)

st.write(f"**Current state:** {profile['state']}")
st.write(
    f"**Trusted baseline events:** {profile['total_events']}"
)
st.write(
    "**Trusted average data volume:** "
    f"{round(profile['average_bytes'], 2)} bytes"
)
st.write(
    f"**Latest explanation:** {profile['last_reason']}"
)

if profile["baseline_updated"]:
    st.success(
        "Baseline decision: trusted behavior updated the "
        "identity profile."
    )
else:
    st.warning(
        "Baseline decision: behavior was quarantined or excluded; "
        "baseline protected."
    )


trusted_column, quarantined_column = st.columns(2)

with trusted_column:
    st.write("#### Trusted Resources")

    if profile["trusted_resources"]:
        st.json(dict(profile["trusted_resources"]))
    else:
        st.write("No trusted resources yet.")

with quarantined_column:
    st.write("#### Quarantined Resources")

    if profile["quarantine"]:
        st.json(dict(profile["quarantine"]))
    else:
        st.write("No quarantined resources.")


st.subheader("Recent Event Stream")

if st.session_state.events:
    st.dataframe(
        pd.DataFrame(st.session_state.events[::-1]),
        use_container_width=True,
        hide_index=True,
    )


if st.session_state.auto_run:
    time.sleep(1)
    generate_cycle()
    st.rerun()