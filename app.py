import random
import time
from collections import Counter, deque
from datetime import datetime

import pandas as pd
import streamlit as st
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from storage.database import initialize_database, save_decision, save_event

st.set_page_config(page_title="NHI Adaptive Trust", page_icon="🛡️", layout="wide")
initialize_database()

st.markdown("""
<style>
#MainMenu {visibility:hidden;} footer {visibility:hidden;}
.stApp {background: linear-gradient(135deg,#040A13 0%,#07111F 50%,#0A1830 100%);}
.block-container {max-width:1450px; padding-top:1.8rem; padding-bottom:3rem;}
h1 {color:#EAFBFF!important; font-weight:800!important;}
h2 {color:#72EEFF!important; border-left:4px solid #00E5FF; padding-left:12px;}
h3 {color:#DDF9FF!important;}
div[data-testid="stMetric"] {background:linear-gradient(135deg,rgba(15,42,67,.92),rgba(7,23,40,.94)); border:1px solid rgba(0,229,255,.25); border-radius:14px; padding:15px;}
div[data-testid="stDataFrame"] {border:1px solid rgba(0,229,255,.18); border-radius:12px; overflow:hidden;}
.stButton>button {color:#EFFFFF!important; font-weight:700; border:1px solid rgba(0,229,255,.55); background:linear-gradient(135deg,#0C6A83,#063C59);}
div[data-testid="stSidebar"] {background:linear-gradient(180deg,#061422,#091D31);}
</style>
""", unsafe_allow_html=True)

IDENTITIES = ["service_alpha", "worker_beta", "deploy_gamma", "api_delta"]
NORMAL_RESOURCES = ["customer_db", "orders_db", "logs_bucket", "metrics_api"]
SENSITIVE_RESOURCES = ["secrets_vault", "admin_console", "production_backup"]
STATES = ["NORMAL", "DRIFTING", "SUSPICIOUS", "HIGH_RISK"]
ICONS = {"NORMAL":"🟢", "DRIFTING":"🟡", "SUSPICIOUS":"🟠", "HIGH_RISK":"🔴"}
ML_MIN_SAMPLES = 5
ML_BUFFER_SIZE = 40
ML_RETRAIN_INTERVAL = 3
ML_WEIGHT = 0.25


def create_profile():
    return {
        "trusted_resources": Counter(), "trusted_actions": Counter(),
        "trusted_ips": Counter(), "total_events": 0, "average_bytes": 0.0,
        "quarantine": Counter(), "recent_scores": deque(maxlen=5),
        "state": "NORMAL", "last_reason": "Waiting for the first event.",
        "baseline_updated": False, "state_changes": 0, "last_event": None,
        "deviation_evidence": 0.0, "deviation_events": 0,
        "last_evidence_reason": "No accumulated deviation evidence.",
        "ml_feature_buffer": deque(maxlen=ML_BUFFER_SIZE), "ml_model": None,
        "ml_scaler": None, "ml_score": 0.0,
        "ml_status": "Collecting trusted warm-up events.",
        "ml_trusted_samples": 0, "ml_last_trained": 0,
    }


def create_event(identity, scenario):
    event = {
        "timestamp": datetime.now().strftime("%H:%M:%S"), "identity": identity,
        "resource": random.choice(NORMAL_RESOURCES),
        "action": random.choice(["READ", "WRITE"]),
        "bytes_transferred": random.randint(700, 2800),
        "source_ip": f"10.0.0.{random.randint(2, 20)}", "success": True,
        "scenario": scenario,
    }
    if scenario == "DRIFTING":
        event.update(resource="reporting_api", bytes_transferred=random.randint(1200, 4000))
    elif scenario == "SUSPICIOUS":
        event.update(
            resource=random.choice(NORMAL_RESOURCES + ["analytics_db"]),
            action=random.choice(["READ", "WRITE", "EXECUTE"]),
            bytes_transferred=random.randint(4000, 10000),
            source_ip=f"172.16.10.{random.randint(2, 200)}",
        )
    elif scenario == "HIGH_RISK":
        event.update(
            resource=random.choice(SENSITIVE_RESOURCES),
            action=random.choice(["READ", "DELETE", "EXECUTE"]),
            bytes_transferred=random.randint(10000, 50000),
            source_ip=f"203.0.113.{random.randint(2, 200)}",
            success=random.choice([True, True, False]),
        )
    elif scenario == "SLOW_BURN":
        event.update(
            resource=random.choice(NORMAL_RESOURCES + ["partner_api"]),
            action=random.choice(["READ", "WRITE"]),
            bytes_transferred=random.randint(2800, 5000),
            source_ip=f"10.10.5.{random.randint(2, 50)}",
        )
    return event


def update_baseline(profile, event):
    old_count = profile["total_events"]
    profile["total_events"] += 1
    profile["trusted_resources"][event["resource"]] += 1
    profile["trusted_actions"][event["action"]] += 1
    profile["trusted_ips"][event["source_ip"]] += 1
    profile["average_bytes"] = (
        profile["average_bytes"] * old_count + event["bytes_transferred"]
    ) / profile["total_events"]


def calculate_event_score(profile, event):
    score, reasons = 0.0, []
    if event["resource"] not in profile["trusted_resources"]:
        score += 0.30; reasons.append(f"New resource: {event['resource']}")
    if event["action"] not in profile["trusted_actions"]:
        score += 0.20; reasons.append(f"New action: {event['action']}")
    if event["source_ip"] not in profile["trusted_ips"]:
        score += 0.20; reasons.append(f"New source IP: {event['source_ip']}")
    if event["bytes_transferred"] > max(profile["average_bytes"], 1) * 3:
        score += 0.25; reasons.append("Data volume exceeds 3x baseline average.")
    if not event["success"]:
        score += 0.15; reasons.append("Operation failed.")
    if event["resource"] in SENSITIVE_RESOURCES:
        score += 0.35; reasons.append(f"Sensitive resource: {event['resource']}")
    return min(score, 1.0), reasons


def extract_ml_features(profile, event):
    average_bytes = max(profile["average_bytes"], 1)
    return [
        float(min(event["bytes_transferred"] / average_bytes, 15.0)),
        float(event["resource"] not in profile["trusted_resources"]),
        float(event["action"] not in profile["trusted_actions"]),
        float(event["source_ip"] not in profile["trusted_ips"]),
        float(event["resource"] in SENSITIVE_RESOURCES),
        float(event["action"] in ["DELETE", "EXECUTE"]),
        float(not event["success"]),
    ]


def train_ml_model(profile):
    samples = list(profile["ml_feature_buffer"])
    if len(samples) < ML_MIN_SAMPLES:
        profile["ml_status"] = f"Collecting trusted samples: {len(samples)}/{ML_MIN_SAMPLES}."
        return
    scaler = StandardScaler()
    scaled_samples = scaler.fit_transform(samples)
    model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
    model.fit(scaled_samples)
    profile["ml_model"] = model
    profile["ml_scaler"] = scaler
    profile["ml_last_trained"] = len(samples)
    profile["ml_status"] = f"Trained on {len(samples)} trusted samples."


def learn_trusted_ml_behavior(profile, event):
    profile["ml_feature_buffer"].append(extract_ml_features(profile, event))
    profile["ml_trusted_samples"] += 1
    count = len(profile["ml_feature_buffer"])
    if count >= ML_MIN_SAMPLES and (
        profile["ml_model"] is None or count - profile["ml_last_trained"] >= ML_RETRAIN_INTERVAL
    ):
        train_ml_model(profile)
    elif profile["ml_model"] is None:
        profile["ml_status"] = f"Collecting trusted samples: {count}/{ML_MIN_SAMPLES}."


def calculate_ml_score(profile, event):
    if profile["ml_model"] is None or profile["ml_scaler"] is None:
        profile["ml_score"] = 0.0
        return 0.0
    features = profile["ml_scaler"].transform([extract_ml_features(profile, event)])
    raw_score = -profile["ml_model"].decision_function(features)[0]
    profile["ml_score"] = round(max(0.0, min(raw_score * 2.5, 1.0)), 2)
    return profile["ml_score"]


def update_evidence(profile, score):
    evidence = profile["deviation_evidence"]
    if score >= 0.25:
        evidence += score
        profile["deviation_events"] += 1
        profile["last_evidence_reason"] = f"Evidence increased by {score:.2f}; accumulated evidence is {evidence:.2f}."
    else:
        evidence = max(0.0, evidence - 0.10)
        profile["last_evidence_reason"] = f"No major deviation; evidence decayed to {evidence:.2f}."
    profile["deviation_evidence"] = round(evidence, 2)


def choose_state(profile, score, event):
    evidence = profile["deviation_evidence"]
    if score >= 0.80 or evidence >= 2.60 or (event["resource"] in SENSITIVE_RESOURCES and score >= 0.50):
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
            "state": "NORMAL", "risk_score": 0.0, "rule_score": 0.0,
            "ml_score": 0.0, "reasons": ["Warm-up: collecting trusted baseline behavior."],
            "baseline_updated": True,
        }

    rule_score, reasons = calculate_event_score(profile, event)
    ml_score = calculate_ml_score(profile, event)
    final_score = min(1.0, rule_score + ml_score * ML_WEIGHT)
    reasons.append(f"Isolation Forest ML anomaly score: {ml_score:.2f}")
    profile["recent_scores"].append(final_score)
    update_evidence(profile, final_score)
    state = choose_state(profile, final_score, event)
    baseline_updated = False

    if state == "NORMAL":
        update_baseline(profile, event)
        learn_trusted_ml_behavior(profile, event)
        baseline_updated = True
        reasons.append("Matches trusted baseline; profile updated.")
    elif state == "DRIFTING":
        resource = event["resource"]
        profile["quarantine"][resource] += 1
        observed = profile["quarantine"][resource]
        if observed >= 3 and profile["deviation_evidence"] < 1.20 and resource not in SENSITIVE_RESOURCES:
            update_baseline(profile, event)
            learn_trusted_ml_behavior(profile, event)
            baseline_updated = True
            reasons.append(f"Verified legitimate drift: {resource} promoted to trusted baseline.")
        else:
            reasons.append(f"Low-risk drift quarantined: {resource} observed {observed}/3 times.")
    else:
        profile["quarantine"][event["resource"]] += 1
        reasons.append("Excluded from trusted learning to prevent baseline poisoning.")

    return {
        "state": state, "risk_score": round(final_score, 2),
        "rule_score": round(rule_score, 2), "ml_score": round(ml_score, 2),
        "reasons": reasons, "baseline_updated": baseline_updated,
    }


def reset_demo():
    st.session_state.profiles = {identity: create_profile() for identity in IDENTITIES}
    st.session_state.events = []
    st.session_state.decisions = []
    st.session_state.cycle = 0


def get_scenarios(cycle):
    scenarios = {identity: "NORMAL" for identity in IDENTITIES}
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

    for identity, scenario in get_scenarios(cycle).items():
        event = create_event(identity, scenario)
        profile = st.session_state.profiles[identity]
        previous_state = profile["state"]
        started = time.perf_counter()
        decision = analyze_event(profile, event)
        latency_ms = round((time.perf_counter() - started) * 1000, 3)
        new_state = decision["state"]

        if previous_state != new_state:
            profile["state_changes"] += 1

        profile["state"] = new_state
        profile["last_event"] = event
        profile["baseline_updated"] = decision["baseline_updated"]
        profile["last_reason"] = " | ".join(decision["reasons"])

        st.session_state.events.append(event)
        save_event(cycle, event)

        decision_row = {
            "Cycle": cycle, "Time": event["timestamp"], "Identity": identity,
            "State": new_state, "Rule Score": decision["rule_score"],
            "ML Anomaly Score": decision["ml_score"], "Risk Score": decision["risk_score"],
            "Evidence Score": round(profile["deviation_evidence"], 2),
            "Baseline Updated": "Yes" if decision["baseline_updated"] else "No",
            "Latency (ms)": latency_ms, "Scenario": scenario,
            "Reason": profile["last_reason"],
        }
        st.session_state.decisions.append(decision_row)
        save_decision(cycle, decision_row)

    st.session_state.events = st.session_state.events[-120:]
    st.session_state.decisions = st.session_state.decisions[-120:]


def decisions_dataframe():
    return pd.DataFrame(st.session_state.decisions)


def events_dataframe():
    return pd.DataFrame(st.session_state.events)


def calculate_metrics(decisions):
    if decisions.empty:
        return {"total": 0, "updates": 0, "protected": 0, "suspicious": 0, "high_risk": 0, "blocked": 0, "latency": 0.0, "ml_average": 0.0}
    total = len(decisions)
    updates = int((decisions["Baseline Updated"] == "Yes").sum())
    suspicious = int((decisions["State"] == "SUSPICIOUS").sum())
    high_risk = int((decisions["State"] == "HIGH_RISK").sum())
    protected_rows = decisions[decisions["State"].isin(["SUSPICIOUS", "HIGH_RISK"])]
    return {
        "total": total, "updates": updates, "protected": total - updates,
        "suspicious": suspicious, "high_risk": high_risk,
        "blocked": int((protected_rows["Baseline Updated"] == "No").sum()),
        "latency": round(decisions["Latency (ms)"].mean(), 3),
        "ml_average": round(decisions["ML Anomaly Score"].mean(), 2),
    }


def render_banner():
    st.markdown("""
    <div style="padding:28px 30px;margin-bottom:16px;border-radius:18px;border:1px solid rgba(0,229,255,.34);background:linear-gradient(135deg,rgba(5,29,48,.96),rgba(17,24,67,.93));">
    <div style="color:#66E8FF;font-size:.86rem;font-weight:800;letter-spacing:2px;">CYBER SECURITY PS-02 · HYBRID ML TRUST MONITOR</div>
    <div style="color:#F0FCFF;font-size:2.2rem;font-weight:850;margin-top:8px;">🛡️ Adaptive Behavioral Trust</div>
    <div style="color:#A9CBD8;margin-top:8px;">Isolation Forest ML + security rules + cumulative evidence for continuous NHI monitoring.</div>
    </div>
    """, unsafe_allow_html=True)


def render_dashboard():
    render_banner()
    st.info("The system combines explicit security rules, Isolation Forest anomaly detection, and cumulative evidence for continuous non-human identity monitoring.")

    c1, c2, c3, c4 = st.columns([1, 1, 1, 3])
    with c1:
        if st.button("Generate One Cycle", use_container_width=True):
            generate_cycle()
    with c2:
        st.checkbox("Auto-run simulation", key="auto_run")
    with c3:
        if st.button("Reset Demo", use_container_width=True):
            reset_demo()
    with c4:
        st.info(f"Cycle: {st.session_state.cycle}. 1-5 baseline | 6-11 drift | 12-17 suspicious | 18-23 high risk | 24+ slow burn.")

    state_columns = st.columns(4)
    for column, state in zip(state_columns, STATES):
        count = sum(profile["state"] == state for profile in st.session_state.profiles.values())
        column.metric(f"{ICONS[state]} {state}", count)

    decisions = decisions_dataframe()
    metrics = calculate_metrics(decisions)
    st.subheader("Live Evaluation Metrics")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Events Processed", metrics["total"])
    m2.metric("Baseline Updates", metrics["updates"])
    m3.metric("Baseline Protected", metrics["protected"])
    m4.metric("Avg Decision Latency", f"{metrics['latency']} ms")
    m5, m6, m7, m8 = st.columns(4)
    m5.metric("Suspicious Events", metrics["suspicious"])
    m6.metric("High-Risk Events", metrics["high_risk"])
    m7.metric("Poisoning Attempts Blocked", metrics["blocked"])
    m8.metric("Average ML Score", metrics["ml_average"])

    st.subheader("Identity Trust Overview")
    overview = []
    for identity, profile in st.session_state.profiles.items():
        recent_risk = round(sum(profile["recent_scores"]) / len(profile["recent_scores"]), 2) if profile["recent_scores"] else 0.0
        overview.append({
            "Identity": identity, "State": f"{ICONS[profile['state']]} {profile['state']}",
            "Recent Risk": recent_risk, "ML Score": profile["ml_score"],
            "Evidence": round(profile["deviation_evidence"], 2),
            "Trusted Events": profile["total_events"],
            "ML Samples": len(profile["ml_feature_buffer"]),
            "Baseline Updated": "Yes" if profile["baseline_updated"] else "No",
        })
    st.dataframe(pd.DataFrame(overview), use_container_width=True, hide_index=True)

    st.subheader("Risk, ML, and Evidence Trends")
    if not decisions.empty:
        left, middle, right = st.columns(3)
        with left:
            st.caption("Final risk score")
            st.line_chart(decisions.pivot_table(index="Cycle", columns="Identity", values="Risk Score", aggfunc="mean").sort_index(), use_container_width=True)
        with middle:
            st.caption("Isolation Forest ML anomaly score")
            st.line_chart(decisions.pivot_table(index="Cycle", columns="Identity", values="ML Anomaly Score", aggfunc="mean").sort_index(), use_container_width=True)
        with right:
            st.caption("Cumulative evidence score")
            st.line_chart(decisions.pivot_table(index="Cycle", columns="Identity", values="Evidence Score", aggfunc="mean").sort_index(), use_container_width=True)
    else:
        st.write("Generate events to display trends.")

    st.subheader("Latest Decisions")
    if not decisions.empty:
        st.dataframe(decisions.iloc[::-1], use_container_width=True, hide_index=True)
        st.download_button("Download Decision Log", decisions.to_csv(index=False).encode("utf-8"), "decision_log.csv", "text/csv", use_container_width=True)
    else:
        st.warning("Generate an event cycle to begin.")

    st.subheader("Identity Explanation")
    selected = st.selectbox("Select an identity", IDENTITIES)
    profile = st.session_state.profiles[selected]
    st.markdown(f"### {ICONS[profile['state']]} {selected}")
    st.write(f"**Current state:** {profile['state']}")
    st.write(f"**Trusted baseline events:** {profile['total_events']}")
    st.write(f"**Average data volume:** {profile['average_bytes']:.2f} bytes")
    st.write(f"**Isolation Forest ML score:** {profile['ml_score']:.2f}")
    st.write(f"**ML training status:** {profile['ml_status']}")
    st.write(f"**Cumulative evidence:** {profile['deviation_evidence']:.2f}")
    st.write(f"**Latest explanation:** {profile['last_reason']}")

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
        st.dataframe(events.iloc[::-1], use_container_width=True, hide_index=True)
        st.download_button("Download Event Log", events.to_csv(index=False).encode("utf-8"), "event_log.csv", "text/csv", use_container_width=True)
    else:
        st.warning("No events generated yet.")

    if st.session_state.auto_run:
        time.sleep(1)
        generate_cycle()
        st.rerun()


def render_explore():
    st.title("🔎 Explore the Trust Engine")
    st.markdown("This prototype monitors synthetic non-human identities using behavioral baselines, security rules, Isolation Forest anomaly detection, and controlled adaptation.")
    tab1, tab2, tab3, tab4 = st.tabs(["Threat Model", "Trust States", "ML Layer", "Limitations"])
    with tab1:
        st.subheader("Threat Model")
        st.write("The system detects unexpected resources, actions, IP addresses, data volumes, sensitive access, dangerous actions, and failed operations from service, API, worker, and deployment identities.")
    with tab2:
        st.dataframe(pd.DataFrame([
            ["NORMAL", "Matches trusted baseline", "Baseline can be updated"],
            ["DRIFTING", "Low-risk unfamiliar behavior", "Quarantine and verify"],
            ["SUSPICIOUS", "Repeated or multi-signal deviations", "Exclude from learning"],
            ["HIGH_RISK", "Severe or persistent compromise evidence", "Exclude from learning"],
        ], columns=["State", "Meaning", "Learning Decision"]), use_container_width=True, hide_index=True)
    with tab3:
        st.write("A separate Isolation Forest model is trained for each identity using trusted events only. It evaluates data-volume ratio, unknown resource/action/IP, sensitive access, dangerous action, and failed operation features.")
    with tab4:
        st.write("Events are simulated for demonstration. Production deployment would require real IAM/SIEM integration, secure database hosting, authentication, access controls, monitoring, and calibrated thresholds.")


if "profiles" not in st.session_state:
    reset_demo()
if "auto_run" not in st.session_state:
    st.session_state.auto_run = False
if "page" not in st.session_state:
    st.session_state.page = "Dashboard"

with st.sidebar:
    st.title("🛡️ NHI Trust")
    st.caption("Hybrid ML Behavioral Security Monitor")
    st.session_state.page = st.radio("Navigate", ["Dashboard", "Explore"], index=0 if st.session_state.page == "Dashboard" else 1)
    st.divider()
    st.markdown("""**PROJECT STATUS**

🟢 Monitoring engine ready

🟣 Isolation Forest ML enabled

🟠 Baseline and slow-burn defense enabled

---

**Project:** Adaptive Behavioral Trust

**Problem:** Cyber Security PS-02

**Backend:** Python + Scikit-learn + SQLite

**ML Model:** Isolation Forest""")

if st.session_state.page == "Dashboard":
    render_dashboard()
else:
    render_explore()