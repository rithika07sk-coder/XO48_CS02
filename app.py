import random
import time
from collections import Counter, deque
from datetime import datetime

import pandas as pd
import streamlit as st
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


st.set_page_config(
    page_title="NHI Adaptive Trust",
    page_icon="🛡️",
    layout="wide",
)


st.markdown(
    """
    <style>
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    header { background: transparent !important; }

    .stApp {
        background:
            radial-gradient(
                circle at 12% 5%,
                rgba(0, 229, 255, 0.12),
                transparent 28%
            ),
            radial-gradient(
                circle at 88% 12%,
                rgba(147, 51, 234, 0.14),
                transparent 30%
            ),
            linear-gradient(
                135deg,
                #040A13 0%,
                #07111F 50%,
                #0A1830 100%
            );
    }

    .block-container {
        max-width: 1450px;
        padding-top: 1.8rem;
        padding-bottom: 3rem;
    }

    h1 {
        color: #EAFBFF !important;
        font-weight: 800 !important;
        letter-spacing: -0.7px;
        text-shadow: 0 0 22px rgba(0, 229, 255, 0.24);
    }

    h2 {
        color: #72EEFF !important;
        font-weight: 750 !important;
        border-left: 4px solid #00E5FF;
        padding-left: 12px;
        margin-top: 2rem !important;
    }

    h3 {
        color: #DDF9FF !important;
        font-weight: 700 !important;
    }

    div[data-testid="stMetric"] {
        background:
            linear-gradient(
                135deg,
                rgba(15, 42, 67, 0.92),
                rgba(7, 23, 40, 0.94)
            );
        border: 1px solid rgba(0, 229, 255, 0.25);
        border-radius: 14px;
        padding: 15px 16px;
        box-shadow:
            0 8px 22px rgba(0, 0, 0, 0.20),
            inset 0 1px 0 rgba(255, 255, 255, 0.05);
    }

    div[data-testid="stMetricLabel"] {
        color: #A5CBD8 !important;
        font-size: 0.82rem !important;
        font-weight: 650 !important;
    }

    div[data-testid="stMetricValue"] {
        color: #F0FCFF !important;
        font-size: 1.6rem !important;
        font-weight: 800 !important;
    }

    div[data-testid="stDataFrame"] {
        border: 1px solid rgba(0, 229, 255, 0.18);
        border-radius: 12px;
        overflow: hidden;
        box-shadow: 0 8px 22px rgba(0, 0, 0, 0.17);
    }

    div[data-testid="stAlert"] {
        border-radius: 12px;
        border: 1px solid rgba(0, 229, 255, 0.24);
        background-color: rgba(10, 31, 50, 0.76);
    }

    .stButton > button {
        min-height: 43px;
        color: #EFFFFF !important;
        font-weight: 750;
        border-radius: 10px;
        border: 1px solid rgba(0, 229, 255, 0.55);
        background:
            linear-gradient(
                135deg,
                #0C6A83 0%,
                #063C59 100%
            );
        box-shadow: 0 6px 16px rgba(0, 229, 255, 0.13);
        transition: all 0.2s ease;
    }

    .stButton > button:hover {
        border-color: #7CF5FF;
        background:
            linear-gradient(
                135deg,
                #1096B1 0%,
                #075E7B 100%
            );
        transform: translateY(-1px);
        box-shadow: 0 10px 22px rgba(0, 229, 255, 0.24);
    }

    div[data-testid="stDownloadButton"] > button {
        min-height: 42px;
        color: #F8F2FF !important;
        font-weight: 700;
        border-radius: 10px;
        border: 1px solid rgba(168, 85, 247, 0.62);
        background:
            linear-gradient(
                135deg,
                #54209D 0%,
                #2E1065 100%
            );
    }

    div[data-testid="stSidebar"] {
        background:
            linear-gradient(
                180deg,
                #061422 0%,
                #091D31 100%
            );
        border-right: 1px solid rgba(0, 229, 255, 0.18);
    }

    div[data-testid="stSidebar"] h1 {
        color: #6DEEFF !important;
        font-size: 1.5rem !important;
    }

    div[data-testid="stTabs"] button {
        color: #ACC9D7;
        font-weight: 650;
    }

    div[data-testid="stTabs"] button[aria-selected="true"] {
        color: #71EEFF !important;
        border-bottom-color: #00E5FF !important;
    }

    hr {
        border-color: rgba(0, 229, 255, 0.18);
    }

    code {
        color: #83F7FF !important;
        background-color: rgba(0, 229, 255, 0.09);
    }
    </style>
    """,
    unsafe_allow_html=True,
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

ML_MIN_SAMPLES = 5
ML_BUFFER_SIZE = 40
ML_RETRAIN_INTERVAL = 3
ML_WEIGHT = 0.25


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
        "deviation_evidence": 0.0,
        "deviation_events": 0,
        "last_evidence_reason": "No accumulated deviation evidence.",
        "ml_feature_buffer": deque(maxlen=ML_BUFFER_SIZE),
        "ml_model": None,
        "ml_scaler": None,
        "ml_score": 0.0,
        "ml_status": "Collecting trusted warm-up events.",
        "ml_trusted_samples": 0,
        "ml_last_trained": 0,
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

    elif scenario == "SLOW_BURN":
        event["resource"] = random.choice(
            NORMAL_RESOURCES + ["partner_api"]
        )
        event["action"] = random.choice(["READ", "WRITE"])
        event["bytes_transferred"] = random.randint(2800, 5000)
        event["source_ip"] = f"10.10.5.{random.randint(2, 50)}"

    return event


def update_baseline(profile, event):
    old_count = profile["total_events"]

    profile["total_events"] += 1
    profile["trusted_resources"][event["resource"]] += 1
    profile["trusted_actions"][event["action"]] += 1
    profile["trusted_ips"][event["source_ip"]] += 1

    profile["average_bytes"] = (
        profile["average_bytes"] * old_count
        + event["bytes_transferred"]
    ) / profile["total_events"]


def calculate_event_score(profile, event):
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

    return min(score, 1.0), reasons


def extract_ml_features(profile, event):
    average_bytes = max(profile["average_bytes"], 1)

    new_resource = int(
        event["resource"] not in profile["trusted_resources"]
    )

    new_action = int(
        event["action"] not in profile["trusted_actions"]
    )

    new_ip = int(
        event["source_ip"] not in profile["trusted_ips"]
    )

    sensitive = int(
        event["resource"] in SENSITIVE_RESOURCES
    )

    dangerous_action = int(
        event["action"] in ["DELETE", "EXECUTE"]
    )

    failed = int(not event["success"])

    volume_ratio = min(
        event["bytes_transferred"] / average_bytes,
        15.0,
    )

    return [
        float(volume_ratio),
        float(new_resource),
        float(new_action),
        float(new_ip),
        float(sensitive),
        float(dangerous_action),
        float(failed),
    ]


def train_ml_model(profile):
    buffer = list(profile["ml_feature_buffer"])

    if len(buffer) < ML_MIN_SAMPLES:
        profile["ml_status"] = (
            f"Collecting trusted samples: "
            f"{len(buffer)}/{ML_MIN_SAMPLES}."
        )
        return

    scaler = StandardScaler()
    scaled_buffer = scaler.fit_transform(buffer)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.15,
        random_state=42,
    )

    model.fit(scaled_buffer)

    profile["ml_model"] = model
    profile["ml_scaler"] = scaler
    profile["ml_last_trained"] = len(buffer)
    profile["ml_status"] = (
        f"Trained on {len(buffer)} trusted samples."
    )


def learn_trusted_ml_behavior(profile, event):
    features = extract_ml_features(profile, event)

    profile["ml_feature_buffer"].append(features)
    profile["ml_trusted_samples"] += 1

    buffer_size = len(profile["ml_feature_buffer"])

    should_train = (
        buffer_size >= ML_MIN_SAMPLES
        and (
            profile["ml_model"] is None
            or (
                buffer_size
                - profile["ml_last_trained"]
                >= ML_RETRAIN_INTERVAL
            )
        )
    )

    if should_train:
        train_ml_model(profile)
    elif profile["ml_model"] is None:
        profile["ml_status"] = (
            f"Collecting trusted samples: "
            f"{buffer_size}/{ML_MIN_SAMPLES}."
        )


def calculate_ml_score(profile, event):
    if (
        profile["ml_model"] is None
        or profile["ml_scaler"] is None
    ):
        profile["ml_score"] = 0.0
        return 0.0

    features = extract_ml_features(profile, event)
    scaled = profile["ml_scaler"].transform([features])

    raw_score = -profile["ml_model"].decision_function(
        scaled
    )[0]

    ml_score = max(0.0, min(raw_score * 2.5, 1.0))
    profile["ml_score"] = round(ml_score, 2)

    return profile["ml_score"]


def update_evidence(profile, score):
    evidence = profile["deviation_evidence"]

    if score >= 0.25:
        evidence += score
        profile["deviation_events"] += 1

        profile["last_evidence_reason"] = (
            f"Evidence increased by {score:.2f}. "
            f"Current accumulated evidence: {evidence:.2f} "
            f"across {profile['deviation_events']} deviations."
        )
    else:
        evidence = max(0.0, evidence - 0.10)

        profile["last_evidence_reason"] = (
            f"No major deviation in this event. "
            f"Evidence decayed by 0.10 to {evidence:.2f}."
        )

    profile["deviation_evidence"] = round(evidence, 2)


def choose_state(profile, score, event):
    evidence = profile["deviation_evidence"]

    if (
        score >= 0.80
        or evidence >= 2.60
        or (
            event["resource"] in SENSITIVE_RESOURCES
            and score >= 0.50
        )
    ):
        return "HIGH_RISK"

    if score >= 0.55 or evidence >= 1.20:
        return "SUSPICIOUS"

    if score >= 0.25 or evidence >= 0.40:
        return "DRIFTING"

    return "NORMAL"


def analyze_event(profile, event):
    if profile["total_events"] < 5:
        update_baseline(profile, event)
        learn_trusted_ml_behavior(profile, event)

        return {
            "state": "NORMAL",
            "risk_score": 0.0,
            "rule_score": 0.0,
            "ml_score": 0.0,
            "reasons": [
                "Warm-up: collecting trusted baseline behavior."
            ],
            "baseline_updated": True,
        }

    rule_score, reasons = calculate_event_score(profile, event)
    ml_score = calculate_ml_score(profile, event)

    final_score = min(
        1.0,
        rule_score + (ml_score * ML_WEIGHT),
    )

    reasons.append(
        f"Isolation Forest ML anomaly score: {ml_score:.2f}"
    )

    profile["recent_scores"].append(final_score)
    update_evidence(profile, final_score)

    state = choose_state(profile, final_score, event)
    baseline_updated = False

    if state == "NORMAL":
        update_baseline(profile, event)
        learn_trusted_ml_behavior(profile, event)
        baseline_updated = True

        reasons.append(
            "Matches trusted baseline; profile updated."
        )

    elif state == "DRIFTING":
        resource = event["resource"]
        profile["quarantine"][resource] += 1
        observed = profile["quarantine"][resource]

        safe_to_promote = (
            observed >= 3
            and profile["deviation_evidence"] < 1.20
            and resource not in SENSITIVE_RESOURCES
        )

        if safe_to_promote:
            update_baseline(profile, event)
            learn_trusted_ml_behavior(profile, event)
            baseline_updated = True

            reasons.append(
                f"Verified legitimate drift: {resource} "
                f"observed {observed} times and promoted "
                "to trusted baseline."
            )
        else:
            reasons.append(
                f"Low-risk drift quarantined: {resource} "
                f"observed {observed}/3 times."
            )

            if profile["deviation_evidence"] >= 1.20:
                reasons.append(
                    "Promotion blocked due to accumulated "
                    "deviation evidence."
                )

    else:
        profile["quarantine"][event["resource"]] += 1

        reasons.append(
            "Excluded from trusted learning to prevent "
            "baseline poisoning."
        )

    return {
        "state": state,
        "risk_score": round(final_score, 2),
        "rule_score": round(rule_score, 2),
        "ml_score": round(ml_score, 2),
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

    elif 18 <= cycle < 24:
        scenarios["api_delta"] = "HIGH_RISK"

    elif cycle >= 24:
        scenarios["service_alpha"] = "SLOW_BURN"

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
        profile["last_event"] = event
        profile["baseline_updated"] = decision["baseline_updated"]
        profile["last_reason"] = " | ".join(
            decision["reasons"]
        )

        st.session_state.events.append(event)

        st.session_state.decisions.append(
            {
                "Cycle": cycle,
                "Time": event["timestamp"],
                "Identity": identity,
                "State": new_state,
                "Rule Score": decision["rule_score"],
                "ML Anomaly Score": decision["ml_score"],
                "Risk Score": decision["risk_score"],
                "Evidence Score": round(
                    profile["deviation_evidence"],
                    2,
                ),
                "Baseline Updated": (
                    "Yes"
                    if decision["baseline_updated"]
                    else "No"
                ),
                "Latency (ms)": latency_ms,
                "Scenario": scenario,
                "Reason": profile["last_reason"],
            }
        )

    st.session_state.events = st.session_state.events[-120:]
    st.session_state.decisions = (
        st.session_state.decisions[-120:]
    )


def decisions_dataframe():
    return pd.DataFrame(st.session_state.decisions)


def events_dataframe():
    return pd.DataFrame(st.session_state.events)


def calculate_metrics(decisions):
    if decisions.empty:
        return {
            "total": 0,
            "updates": 0,
            "protected": 0,
            "suspicious": 0,
            "high_risk": 0,
            "blocked": 0,
            "latency": 0.0,
            "ml_average": 0.0,
        }

    total = len(decisions)
    updates = int(
        (decisions["Baseline Updated"] == "Yes").sum()
    )
    suspicious = int(
        (decisions["State"] == "SUSPICIOUS").sum()
    )
    high_risk = int(
        (decisions["State"] == "HIGH_RISK").sum()
    )

    blocked = int(
        (
            decisions[
                decisions["State"].isin(
                    ["SUSPICIOUS", "HIGH_RISK"]
                )
            ]["Baseline Updated"]
            == "No"
        ).sum()
    )

    return {
        "total": total,
        "updates": updates,
        "protected": total - updates,
        "suspicious": suspicious,
        "high_risk": high_risk,
        "blocked": blocked,
        "latency": round(
            decisions["Latency (ms)"].mean(),
            3,
        ),
        "ml_average": round(
            decisions["ML Anomaly Score"].mean(),
            2,
        ),
    }


def render_banner():
    st.markdown(
        """
        <div style="
            padding: 28px 30px;
            margin-bottom: 16px;
            border-radius: 18px;
            border: 1px solid rgba(0, 229, 255, 0.34);
            background:
                linear-gradient(
                    135deg,
                    rgba(5, 29, 48, 0.96),
                    rgba(17, 24, 67, 0.93)
                );
            box-shadow:
                0 14px 34px rgba(0, 0, 0, 0.28),
                inset 0 1px 0 rgba(255, 255, 255, 0.05);
        ">
            <div style="
                color: #66E8FF;
                font-size: 0.86rem;
                font-weight: 800;
                letter-spacing: 2px;
                margin-bottom: 8px;
            ">
                CYBER SECURITY PS-02 · HYBRID ML TRUST MONITOR
            </div>
            <div style="
                color: #F0FCFF;
                font-size: 2.2rem;
                font-weight: 850;
                line-height: 1.15;
            ">
                🛡️ Adaptive Behavioral Trust
            </div>
            <div style="
                color: #A9CBD8;
                font-size: 1.02rem;
                margin-top: 8px;
            ">
                Isolation Forest ML + security rules + cumulative
                evidence for continuous NHI monitoring.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_status_strip():
    st.markdown(
        """
        <div style="
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 18px;
        ">
            <span style="
                padding: 7px 12px;
                border-radius: 999px;
                background: rgba(0, 229, 255, 0.10);
                border: 1px solid rgba(0, 229, 255, 0.28);
                color: #88F4FF;
                font-size: 0.80rem;
                font-weight: 700;
            ">
                ● STREAM MONITORING ACTIVE
            </span>
            <span style="
                padding: 7px 12px;
                border-radius: 999px;
                background: rgba(168, 85, 247, 0.10);
                border: 1px solid rgba(168, 85, 247, 0.30);
                color: #D8B4FE;
                font-size: 0.80rem;
                font-weight: 700;
            ">
                ◈ ISOLATION FOREST ML ENABLED
            </span>
            <span style="
                padding: 7px 12px;
                border-radius: 999px;
                background: rgba(34, 197, 94, 0.10);
                border: 1px solid rgba(34, 197, 94, 0.30);
                color: #86EFAC;
                font-size: 0.80rem;
                font-weight: 700;
            ">
                ✓ BASELINE PROTECTION ACTIVE
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_dashboard():
    render_banner()
    render_status_strip()

    st.info(
        "The system uses a hybrid backend: explicit security "
        "rules detect known dangerous signals, while Isolation "
        "Forest learns trusted behavioral patterns and scores "
        "unusual event combinations."
    )

    left, right = st.columns(2)

    with left:
        st.markdown(
            "### Challenge 1: Poisoning Resistance\n"
            "A new resource is promoted only after repeated "
            "safe observations."
        )

    with right:
        st.markdown(
            "### Challenge 2: Slow-Burn Detection\n"
            "Repeated mild deviations accumulate evidence "
            "until an appropriate risk state is reached."
        )

    st.divider()

    c1, c2, c3, c4 = st.columns([1, 1, 1, 3])

    with c1:
        if st.button("Generate One Cycle", width="stretch"):
            generate_cycle()

    with c2:
        st.checkbox(
            "Auto-run simulation",
            key="auto_run",
        )

    with c3:
        if st.button("Reset Demo", width="stretch"):
            reset_demo()

    with c4:
        st.info(
            f"Cycle: {st.session_state.cycle}. "
            "1-5 baseline | 6-11 drift | 12-17 suspicious | "
            "18-23 high risk | 24+ slow burn."
        )

    state_columns = st.columns(4)

    for column, state in zip(state_columns, STATES):
        count = sum(
            profile["state"] == state
            for profile in st.session_state.profiles.values()
        )
        column.metric(f"{ICONS[state]} {state}", count)

    decisions = decisions_dataframe()
    metrics = calculate_metrics(decisions)

    st.subheader("Live Evaluation Metrics")

    m1, m2, m3, m4 = st.columns(4)

    m1.metric("Events Processed", metrics["total"])
    m2.metric("Baseline Updates", metrics["updates"])
    m3.metric("Baseline Protected", metrics["protected"])
    m4.metric(
        "Avg Decision Latency",
        f"{metrics['latency']} ms",
    )

    m5, m6, m7, m8 = st.columns(4)

    m5.metric("Suspicious Events", metrics["suspicious"])
    m6.metric("High-Risk Events", metrics["high_risk"])
    m7.metric(
        "Poisoning Attempts Blocked",
        metrics["blocked"],
    )
    m8.metric(
        "Average ML Score",
        metrics["ml_average"],
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
                "State": (
                    f"{ICONS[profile['state']]} "
                    f"{profile['state']}"
                ),
                "Recent Risk": recent_risk,
                "ML Score": profile["ml_score"],
                "Evidence": round(
                    profile["deviation_evidence"],
                    2,
                ),
                "Trusted Events": profile["total_events"],
                "ML Samples": len(
                    profile["ml_feature_buffer"]
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
        width="stretch",
        hide_index=True,
    )

    st.subheader("Slow-Burn Deviation Monitor")

    slow_burn = []

    for identity, profile in st.session_state.profiles.items():
        evidence = profile["deviation_evidence"]

        if evidence >= 2.60:
            stage = "High-risk threshold reached"
        elif evidence >= 1.20:
            stage = "Suspicious threshold reached"
        elif evidence >= 0.40:
            stage = "Drift evidence accumulating"
        else:
            stage = "No meaningful accumulated evidence"

        slow_burn.append(
            {
                "Identity": identity,
                "ML Status": profile["ml_status"],
                "ML Score": profile["ml_score"],
                "Evidence Score": round(evidence, 2),
                "Deviation Events": profile[
                    "deviation_events"
                ],
                "Current State": (
                    f"{ICONS[profile['state']]} "
                    f"{profile['state']}"
                ),
                "Detection Stage": stage,
            }
        )

    st.dataframe(
        pd.DataFrame(slow_burn),
        width="stretch",
        hide_index=True,
    )

    st.subheader("Risk, ML, and Evidence Trends")

    if not decisions.empty:
        risk_chart = decisions.pivot_table(
            index="Cycle",
            columns="Identity",
            values="Risk Score",
            aggfunc="mean",
        ).sort_index()

        ml_chart = decisions.pivot_table(
            index="Cycle",
            columns="Identity",
            values="ML Anomaly Score",
            aggfunc="mean",
        ).sort_index()

        evidence_chart = decisions.pivot_table(
            index="Cycle",
            columns="Identity",
            values="Evidence Score",
            aggfunc="mean",
        ).sort_index()

        left_chart, center_chart, right_chart = st.columns(3)

        with left_chart:
            st.caption("Final risk score by cycle")
            st.line_chart(
                risk_chart,
                width="stretch",
                height=280,
            )

        with center_chart:
            st.caption("Isolation Forest ML anomaly score")
            st.line_chart(
                ml_chart,
                width="stretch",
                height=280,
            )

        with right_chart:
            st.caption("Cumulative evidence score")
            st.line_chart(
                evidence_chart,
                width="stretch",
                height=280,
            )
    else:
        st.write("Generate events to display trends.")

    st.subheader("Latest Decisions")

    if not decisions.empty:
        st.dataframe(
            decisions.iloc[::-1],
            width="stretch",
            hide_index=True,
        )

        st.download_button(
            "Download Decision Log",
            data=decisions.to_csv(index=False).encode("utf-8"),
            file_name="decision_log.csv",
            mime="text/csv",
            width="stretch",
        )
    else:
        st.warning("Generate an event cycle to begin.")

    st.subheader("Identity Explanation")

    selected = st.selectbox(
        "Select an identity",
        IDENTITIES,
    )

    profile = st.session_state.profiles[selected]

    st.markdown(
        f"### {ICONS[profile['state']]} {selected}"
    )

    st.write(f"**Current state:** {profile['state']}")

    st.write(
        f"**Trusted baseline events:** "
        f"{profile['total_events']}"
    )

    st.write(
        f"**Average data volume:** "
        f"{profile['average_bytes']:.2f} bytes"
    )

    st.write(
        f"**Isolation Forest ML score:** "
        f"{profile['ml_score']:.2f}"
    )

    st.write(
        f"**ML training status:** "
        f"{profile['ml_status']}"
    )

    st.write(
        f"**Cumulative evidence:** "
        f"{profile['deviation_evidence']:.2f}"
    )

    st.write(
        f"**Deviation events:** "
        f"{profile['deviation_events']}"
    )

    st.write(
        f"**Evidence status:** "
        f"{profile['last_evidence_reason']}"
    )

    st.write(
        f"**Latest explanation:** "
        f"{profile['last_reason']}"
    )

    if profile["baseline_updated"]:
        st.success(
            "Baseline decision: trusted behavior updated "
            "the identity profile and ML training buffer."
        )
    else:
        st.warning(
            "Baseline decision: behavior was quarantined "
            "or excluded; it was not used for ML training."
        )

    trusted, quarantined = st.columns(2)

    with trusted:
        st.write("#### Trusted Resources")
        st.json(dict(profile["trusted_resources"]))

    with quarantined:
        st.write("#### Quarantined Resources")
        st.json(dict(profile["quarantine"]))

    st.subheader("Recent Event Stream")

    events = events_dataframe()

    if not events.empty:
        st.dataframe(
            events.iloc[::-1],
            width="stretch",
            hide_index=True,
        )

        st.download_button(
            "Download Event Log",
            data=events.to_csv(index=False).encode("utf-8"),
            file_name="event_log.csv",
            mime="text/csv",
            width="stretch",
        )

    if st.session_state.auto_run:
        time.sleep(1)
        generate_cycle()
        st.rerun()


def render_explore():
    st.markdown(
        """
        <div style="
            padding: 22px 26px;
            margin-bottom: 18px;
            border-radius: 16px;
            border: 1px solid rgba(168, 85, 247, 0.35);
            background:
                linear-gradient(
                    135deg,
                    rgba(35, 13, 70, 0.78),
                    rgba(7, 27, 48, 0.86)
                );
        ">
            <div style="
                color: #D8B4FE;
                font-size: 0.82rem;
                font-weight: 800;
                letter-spacing: 1.8px;
            ">
                SYSTEM DOCUMENTATION · EXPLAINABILITY
            </div>
            <div style="
                color: #F5F3FF;
                font-size: 2rem;
                font-weight: 800;
                margin-top: 6px;
            ">
                🔎 Explore the Trust Engine
            </div>
            <div style="
                color: #C7D7E3;
                margin-top: 7px;
            ">
                Threat model, Isolation Forest ML, adaptation policy,
                slow-burn defense, evaluation, and limitations.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
        [
            "Threat Model",
            "Trust States",
            "Isolation Forest ML",
            "Slow-Burn Defense",
            "Evaluation",
            "Limitations",
        ]
    )

    with tab1:
        st.subheader("Threat Model")

        st.markdown(
            """
            The system monitors synthetic Non-Human Identities:
            service accounts, workload identities, API identities,
            and deployment identities.

            The threat is a compromised identity using valid
            credentials while changing behavior gradually or
            suddenly. Deviations can include unfamiliar resources,
            new actions, new IP addresses, unusual data volumes,
            failed operations, and sensitive-resource access.
            """
        )

        st.warning(
            "This project uses simulated identities and sandboxed "
            "resources only. No real credentials are used."
        )

    with tab2:
        st.subheader("Trust-State Definitions")

        state_table = pd.DataFrame(
            [
                [
                    "NORMAL",
                    "Matches trusted baseline.",
                    "Baseline can be updated.",
                ],
                [
                    "DRIFTING",
                    "Low-risk unfamiliar behavior.",
                    "Quarantine and verify.",
                ],
                [
                    "SUSPICIOUS",
                    "Repeated or multi-signal deviations.",
                    "Exclude from learning.",
                ],
                [
                    "HIGH_RISK",
                    "Severe or persistent compromise evidence.",
                    "Exclude from learning.",
                ],
            ],
            columns=["State", "Meaning", "Learning Decision"],
        )

        st.dataframe(
            state_table,
            width="stretch",
            hide_index=True,
        )

    with tab3:
        st.subheader("Isolation Forest ML Layer")

        st.markdown(
            """
            The backend uses Isolation Forest, an unsupervised
            Machine Learning anomaly-detection algorithm.

            Each NHI has a separate ML model, feature buffer, and
            scaler. The model is trained only using trusted normal
            events and verified legitimate drift.

            Features include data-volume ratio, unknown resource,
            unknown action, unknown IP, sensitive access, dangerous
            action, and failed operation.

            The model learns the normal feature distribution for
            each identity. If a new event is easy to isolate from
            trusted samples, it receives a higher ML anomaly score.

            Final Risk Score =
            Rule-Based Security Score +
            25% of Isolation Forest ML Anomaly Score.

            The ML score can increase risk, but it cannot reduce
            explicit security risk from known dangerous actions.
            """
        )

        ml_table = pd.DataFrame(
            [
                ["1", "Collect trusted NHI event features"],
                ["2", "Scale numeric features with StandardScaler"],
                ["3", "Train Isolation Forest on trusted buffer"],
                ["4", "Score new event for anomaly likelihood"],
                ["5", "Combine ML score with security rules"],
                ["6", "Train only after safe baseline decision"],
            ],
            columns=["Step", "ML Process"],
        )

        st.dataframe(
            ml_table,
            width="stretch",
            hide_index=True,
        )

    with tab4:
        st.subheader("Slow-Burn Behavioral Deviation")

        st.markdown(
            """
            A compromised NHI may avoid detection by creating small
            deviations rather than one obvious malicious event.

            This system stores an identity-specific cumulative
            evidence score. A mild deviation begins as DRIFTING.
            Repeated deviations raise the evidence score until the
            identity becomes SUSPICIOUS and later HIGH_RISK.

            Normal behavior decays evidence gradually. Therefore,
            one isolated harmless event does not permanently flag an
            identity, while persistent deviations still escalate.
            """
        )

        slow_burn_table = pd.DataFrame(
            [
                [
                    "Early",
                    "New IP with otherwise normal activity.",
                    "DRIFTING",
                ],
                [
                    "Middle",
                    "Repeated mild changes over several events.",
                    "SUSPICIOUS",
                ],
                [
                    "Late",
                    "Persistent deviation evidence reaches limit.",
                    "HIGH_RISK",
                ],
                [
                    "Recovery",
                    "Normal behavior decreases evidence.",
                    "DRIFTING or NORMAL",
                ],
            ],
            columns=["Stage", "Behavior", "Expected State"],
        )

        st.dataframe(
            slow_burn_table,
            width="stretch",
            hide_index=True,
        )

    with tab5:
        st.subheader("Evaluation Metrics")

        st.markdown(
            """
            - Decision latency measures monitoring speed.
            - Rule score shows explainable security risk.
            - ML anomaly score shows Isolation Forest output.
            - Baseline updates show controlled adaptation.
            - Baseline-protected events show observations excluded
              from both trusted profile and ML training.
            - Poisoning attempts blocked counts suspicious and
              high-risk observations prevented from affecting trust.
            - Trend charts show detection consistency and time to
              escalation.
            """
        )

    with tab6:
        st.subheader("Known Limitations")

        st.markdown(
            """
            - Events are synthetic and generated for demonstration.
            - The ML model uses a rolling trusted sample buffer.
            - Isolation Forest is retrained periodically, not after
              every single event.
            - Rule weights and thresholds are manually selected.
            - Baselines and ML models exist only during the session.
            - Data resets when the application restarts.
            - The project does not integrate a real SIEM, IAM, EDR,
              database, or production environment.
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

    st.caption("Hybrid ML Behavioral Security Monitor")

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
        **PROJECT STATUS**

        🟢 Monitoring engine ready

        🟣 Isolation Forest ML enabled

        🟠 Baseline and slow-burn defense enabled
        """
    )

    st.divider()

    st.markdown(
        """
        **Project:** Adaptive Behavioral Trust

        **Problem:** Cyber Security PS-02

        **Backend:** Python + Scikit-learn

        **ML Model:** Isolation Forest

        **Focus:** Continuous identity trust, controlled
        adaptation, baseline-poisoning resistance, and
        slow-burn compromise detection.
        """
    )


if st.session_state.page == "Dashboard":
    render_dashboard()
else:
    render_explore()