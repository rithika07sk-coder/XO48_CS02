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

DRIFT_RESOURCES = [
    "reporting_api",
    "analytics_db",
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
    resource = random.choice(NORMAL_RESOURCES)
    action = random.choice(["READ", "WRITE"])
    bytes_transferred = random.randint(700, 2800)
    source_ip = f"10.0.0.{random.randint(2, 20)}"
    success = True

    if scenario == "DRIFTING":
        resource = random.choice(DRIFT_RESOURCES)
        bytes_transferred = random.randint(1200, 4000)

    elif scenario == "SUSPICIOUS":
        resource = random.choice(NORMAL_RESOURCES + DRIFT_RESOURCES)
        action = random.choice(["READ", "WRITE", "EXECUTE"])
        bytes_transferred = random.randint(4000, 10000)
        source_ip = f"172.16.10.{random.randint(2, 200)}"

    elif scenario == "HIGH_RISK":
        resource = random.choice(SENSITIVE_RESOURCES)
        action = random.choice(["READ", "DELETE", "EXECUTE"])
        bytes_transferred = random.randint(10000, 50000)
        source_ip = f"203.0.113.{random.randint(2, 200)}"
        success = random.choice([True, True, False])

    return {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "identity": identity,
        "resource": resource,
        "action": action,
        "bytes_transferred": bytes_transferred,
        "source_ip": source_ip,
        "success": success,
        "scenario": scenario,
    }


def update_baseline(profile, event):
    previous_total = profile["total_events"]

    profile["total_events"] += 1
    profile["trusted_resources"][event["resource"]] += 1
    profile["trusted_actions"][event["action"]] += 1
    profile["trusted_ips"][event["source_ip"]] += 1

    profile["average_bytes"] = (
        (profile["average_bytes"] * previous_total)
        + event["bytes_transferred"]
    ) / profile["total_events"]


def analyze_event(profile, event):
    reasons = []
    score = 0.0

    if profile["total_events"] < 5:
        update_baseline(profile, event)

        return {
            "state": "NORMAL",
            "risk_score": 0.0,
            "reasons": [
                "Warm-up phase: collecting trusted baseline behavior."
            ],
            "baseline_updated": True,
        }

    if event["resource"] not in profile["trusted_resources"]:
        score += 0.30
        reasons.append(f"New resource accessed: {event['resource']}")

    if event["action"] not in profile["trusted_actions"]:
        score += 0.20
        reasons.append(f"New action observed: {event['action']}")

    if event["source_ip"] not in profile["trusted_ips"]:
        score += 0.20
        reasons.append(f"New source IP observed: {event['source_ip']}")

    average_bytes = max(profile["average_bytes"], 1)

    if event["bytes_transferred"] > average_bytes * 3:
        score += 0.25
        reasons.append(
            f"High data volume: {event['bytes_transferred']} bytes "
            f"vs normal average {round(average_bytes)} bytes"
        )

    if not event["success"]:
        score += 0.15
        reasons.append("Operation failed.")

    if event["resource"] in SENSITIVE_RESOURCES:
        score += 0.35
        reasons.append(
            f"Sensitive resource accessed: {event['resource']}"
        )

    score = min(score, 1.0)

    profile["recent_scores"].append(score)
    recent_average = sum(profile["recent_scores"]) / len(
        profile["recent_scores"]
    )

    if score >= 0.80 or (
        event["resource"] in SENSITIVE_RESOURCES and score >= 0.50
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
        reasons.append("Matches the trusted baseline. Profile updated.")

    elif state == "DRIFTING":
        resource = event["resource"]
        profile["quarantine"][resource] += 1

        quarantine_count = profile["quarantine"][resource]

        if quarantine_count >= 3:
            update_baseline(profile, event)
            baseline_updated = True

            reasons.append(
                f"New resource '{resource}' was observed "
                f"{quarantine_count} times with low risk. "
                "It is now verified as legitimate drift and added "
                "to the trusted baseline."
            )
        else:
            reasons.append(
                f"New low-risk behavior is quarantined "
                f"({quarantine_count}/3 observations). "
                "It will not update the trusted baseline yet."
            )

    else:
        profile["quarantine"][event["resource"]] += 1
        reasons.append(
            "Suspicious or high-risk behavior was excluded from "
            "the trusted baseline to prevent baseline poisoning."
        )
        
    if not reasons:
        reasons.append("No meaningful deviation was detected.")

    return {
        "state": state,
        "risk_score": round(score, 2),
        "reasons": reasons,
        "baseline_updated": baseline_updated,
    }


def initialize_demo():
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
        decision = analyze_event(profile, event)

        profile["state"] = decision["state"]
        profile["last_reason"] = " | ".join(decision["reasons"])
        profile["baseline_updated"] = decision["baseline_updated"]

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
                "Reason": " | ".join(decision["reasons"]),
            }
        )

    st.session_state.events = st.session_state.events[-100:]
    st.session_state.decisions = st.session_state.decisions[-100:]


if "profiles" not in st.session_state:
    initialize_demo()


st.title("🛡️ Adaptive Behavioral Trust for Non-Human Identities")
st.caption(
    "Cyber Security PS-02 | Real-time behavior monitoring, "
    "trust assessment, drift detection, and baseline protection."
)

button_col, auto_col, reset_col, info_col = st.columns([1, 1, 1, 3])

with button_col:
    if st.button("Generate One Cycle", use_container_width=True):
        generate_cycle()

with auto_col:
    auto_run = st.checkbox("Auto-run simulation")

with reset_col:
    if st.button("Reset Demo", use_container_width=True):
        initialize_demo()

with info_col:
    st.info(
        f"Simulation cycle: {st.session_state.cycle}. "
        "Cycles 1–5 establish baseline behavior, cycles 6–11 demonstrate "
        "drift, cycles 12–17 demonstrate suspicious activity, and cycle 18+ "
        "demonstrates high-risk behavior."
    )

st.divider()

state_icons = {
    "NORMAL": "🟢",
    "DRIFTING": "🟡",
    "SUSPICIOUS": "🟠",
    "HIGH_RISK": "🔴",
}

metric_columns = st.columns(4)

for index, state in enumerate(
    ["NORMAL", "DRIFTING", "SUSPICIOUS", "HIGH_RISK"]
):
    count = sum(
        1
        for profile in st.session_state.profiles.values()
        if profile["state"] == state
    )
    metric_columns[index].metric(
        f"{state_icons[state]} {state}",
        count,
    )

st.subheader("Identity Trust Overview")

overview = []

for identity, profile in st.session_state.profiles.items():
    recent_risk = 0.0

    if profile["recent_scores"]:
        recent_risk = round(
            sum(profile["recent_scores"])
            / len(profile["recent_scores"]),
            2,
        )

    overview.append(
        {
            "Identity": identity,
            "State": f"{state_icons[profile['state']]} {profile['state']}",
            "Recent Risk": recent_risk,
            "Trusted Events": profile["total_events"],
            "Quarantined Resources": len(profile["quarantine"]),
            "Baseline Updated": (
                "Yes" if profile["baseline_updated"] else "No"
            ),
        }
    )

st.dataframe(
    pd.DataFrame(overview),
    use_container_width=True,
    hide_index=True,
)

st.subheader("Latest Decisions")

if st.session_state.decisions:
    st.dataframe(
        pd.DataFrame(st.session_state.decisions[::-1]),
        use_container_width=True,
        hide_index=True,
    )
else:
    st.warning(
        "No events available. Click Generate Activity Cycle to begin."
    )

st.subheader("Identity Explanation")

selected_identity = st.selectbox("Select an identity", IDENTITIES)
selected_profile = st.session_state.profiles[selected_identity]

st.write(f"### {state_icons[selected_profile['state']]} {selected_identity}")
st.write(f"**Current state:** {selected_profile['state']}")
st.write(
    f"**Trusted baseline events:** {selected_profile['total_events']}"
)
st.write(
    "**Trusted average data volume:** "
    f"{round(selected_profile['average_bytes'], 2)} bytes"
)
st.write(f"**Latest explanation:** {selected_profile['last_reason']}")

trusted_col, quarantine_col = st.columns(2)

with trusted_col:
    st.write("#### Trusted Resources")
    if selected_profile["trusted_resources"]:
        st.json(dict(selected_profile["trusted_resources"]))
    else:
        st.write("No trusted resources collected yet.")

with quarantine_col:
    st.write("#### Quarantined Resources")
    if selected_profile["quarantine"]:
        st.json(dict(selected_profile["quarantine"]))
    else:
        st.write("No quarantined resources.")

st.subheader("Recent Event Stream")

if st.session_state.events:
    st.dataframe(
        pd.DataFrame(st.session_state.events[::-1]),
        use_container_width=True,
        hide_index=True,
    )

if auto_run:
    generate_cycle()
    time.sleep(1)
    st.rerun()