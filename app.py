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
        "deviation_evidence": 0.0,
        "deviation_events": 0,
        "last_evidence_reason": "No accumulated deviation evidence.",
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


def update_evidence(profile, score):
    if score >= 0.25:
        profile["deviation_evidence"] += score
        profile["deviation_events"] += 1

        profile["last_evidence_reason"] = (
            f"Accumulated evidence: "
            f"{profile['deviation_evidence']:.2f} across "
            f"{profile['deviation_events']} deviations."
        )
    else:
        profile["deviation_evidence"] = max(
            0.0,
            profile["deviation_evidence"] - 0.10,
        )

        profile["last_evidence_reason"] = (
            f"Evidence decayed after normal activity: "
            f"{profile['deviation_evidence']:.2f}."
        )


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

        return {
            "state": "NORMAL",
            "risk_score": 0.0,
            "reasons": [
                "Warm-up: collecting trusted baseline behavior."
            ],
            "baseline_updated": True,
        }

    score, reasons = calculate_event_score(profile, event)

    profile["recent_scores"].append(score)
    update_evidence(profile, score)

    state = choose_state(profile, score, event)
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
        observed = profile["quarantine"][resource]

        safe_to_promote = (
            observed >= 3
            and profile["deviation_evidence"] < 1.20
            and resource not in SENSITIVE_RESOURCES
        )

        if safe_to_promote:
            update_baseline(profile, event)
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
    }


def render_dashboard():
    st.title(
        "🛡️ Adaptive Behavioral Trust "
        "for Non-Human Identities"
    )

    st.caption(
        "Cyber Security PS-02 | Continuous monitoring, "
        "controlled adaptation, and baseline protection."
    )

    st.info(
        "The system learns separate identity baselines, "
        "quarantines unfamiliar low-risk behavior, and "
        "excludes suspicious behavior from trusted learning."
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

    m5, m6, m7 = st.columns(3)

    m5.metric("Suspicious Events", metrics["suspicious"])
    m6.metric("High-Risk Events", metrics["high_risk"])
    m7.metric(
        "Poisoning Attempts Blocked",
        metrics["blocked"],
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
                "Evidence": round(
                    profile["deviation_evidence"],
                    2,
                ),
                "Deviation Events": profile[
                    "deviation_events"
                ],
                "Trusted Events": profile["total_events"],
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

    st.subheader("Risk and Evidence Trends")

    if not decisions.empty:
        risk_chart = decisions.pivot_table(
            index="Cycle",
            columns="Identity",
            values="Risk Score",
            aggfunc="mean",
        ).sort_index()

        evidence_chart = decisions.pivot_table(
            index="Cycle",
            columns="Identity",
            values="Evidence Score",
            aggfunc="mean",
        ).sort_index()

        chart_left, chart_right = st.columns(2)

        with chart_left:
            st.caption("Per-event risk score by cycle")

            st.line_chart(
                risk_chart,
                width="stretch",
                height=300,
            )

        with chart_right:
            st.caption("Cumulative evidence score by cycle")

            st.line_chart(
                evidence_chart,
                width="stretch",
                height=300,
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
            "the identity profile."
        )
    else:
        st.warning(
            "Baseline decision: behavior was quarantined "
            "or excluded; baseline protected."
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
    st.title("🔎 Explore the Trust Engine")

    st.caption(
        "Threat model, trust-state logic, controlled adaptation, "
        "slow-burn defense, and known limitations."
    )

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
        [
            "Threat Model",
            "Trust States",
            "Adaptation",
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
        st.subheader("Controlled Adaptation")

        st.markdown(
            """
            Each identity receives five warm-up events to establish
            a baseline. Normal events update trusted behavior.

            A low-risk unknown resource is quarantined. It must be
            observed safely at least three times before promotion.

            Suspicious and high-risk events are recorded but never
            incorporated into the trusted baseline. This protects
            the system against immediate baseline poisoning.
            """
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
            - Decision latency measures continuous-monitoring speed.
            - Baseline updates show controlled adaptation.
            - Baseline-protected events show observations excluded
              from trusted learning.
            - Poisoning attempts blocked counts suspicious and
              high-risk observations prevented from affecting trust.
            - Risk and evidence charts demonstrate detection
              consistency and time to escalation.
            """
        )

    with tab6:
        st.subheader("Known Limitations")

        st.markdown(
            """
            - Events are synthetic and generated for demonstration.
            - Risk weights and thresholds are rule-based.
            - Baselines are stored only during the Streamlit session.
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

        **Focus:** Continuous identity trust, controlled
        adaptation, baseline-poisoning resistance, and
        slow-burn compromise detection.
        """
    )


if st.session_state.page == "Dashboard":
    render_dashboard()
else:
    render_explore()