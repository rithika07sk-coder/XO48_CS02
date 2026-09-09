# Adaptive Behavioral Trust for Non-Human Identities

## Cyber Security PS-02 | XO CODE 2026

A real-time Streamlit dashboard that monitors simulated
Non-Human Identities (NHIs), learns separate behavioral baselines,
detects behavioral deviation, supports controlled adaptation, and
prevents suspicious behavior from contaminating trusted profiles.

The project demonstrates safe monitoring of synthetic service accounts,
workload identities, deployment identities, and API identities. It uses
no real credentials, production systems, customer data, or external
security infrastructure.

---

## Problem Addressed

Modern software systems depend on Non-Human Identities such as service
accounts, automation accounts, API credentials, deployment bots, and
workload identities. These identities access databases, APIs, storage,
deployment systems, and internal services without direct human action.

A compromised NHI may still use valid credentials. Instead of launching
an obvious attack immediately, it may introduce small deviations over
time: a new IP address, slightly higher data transfer, new resources, or
unfamiliar actions. If every new event is blindly learned as normal, the
trusted baseline can be poisoned.

This project provides an adaptive trust layer that distinguishes:

- Normal known behavior.
- Legitimate low-risk behavioral drift.
- Suspicious multi-signal behavior.
- Severe or persistent high-risk compromise behavior.

---

## Objectives

- Continuously process simulated NHI activity as a live event stream.
- Maintain a separate behavioral profile for every identity.
- Use resource, action, IP, data volume, success status, and sensitive
  resource access as behavioral signals.
- Support `NORMAL`, `DRIFTING`, `SUSPICIOUS`, and `HIGH_RISK` states.
- Allow repeated, verified low-risk drift to influence the baseline.
- Prevent suspicious and high-risk observations from influencing trust.
- Detect slow-burn compromise attempts through cumulative evidence.
- Provide human-readable explanations for decisions.
- Measure decision latency and display live evaluation metrics.

---

## Implemented Features

| Feature | Implementation |
|---|---|
| Live event monitoring | Generate one simulation cycle or enable auto-run |
| Multiple NHIs | Four independently profiled synthetic identities |
| Warm-up baseline | First five events per identity establish trusted behavior |
| Per-identity baseline | Resources, actions, IPs, and average data volume |
| Risk scoring | Adds weighted deviation signals and caps score at `1.0` |
| Trust states | `NORMAL`, `DRIFTING`, `SUSPICIOUS`, `HIGH_RISK` |
| Controlled adaptation | Repeated low-risk drift can be promoted after verification |
| Baseline protection | Suspicious and high-risk observations are excluded |
| Slow-burn detection | Persistent mild deviations accumulate identity evidence |
| Evidence decay | Normal behavior gradually reduces accumulated evidence |
| Explainability | Every decision includes risk and adaptation reasons |
| Dashboard metrics | Events, baseline updates, protected events, latency, alerts |
| Charts | Per-cycle risk score and cumulative evidence trends |
| Export | CSV downloads for decisions and event logs |
| Explore page | Threat model, states, adaptation, metrics, and limitations |

---

## Actual Project Structure

```text
cyber_ps02_adaptive_trust/
├── .gitignore
├── app.py
├── README.md
└── requirements.txt
```

The complete prototype is implemented in `app.py`.

---

## Architecture

```text
Synthetic NHI Event Stream
          |
          v
Per-Identity Behavioral Profile
Resources | Actions | IPs | Average Data Volume
          |
          v
Per-Event Risk Scoring
New Resource | New Action | New IP | High Volume
Failure | Sensitive Resource
          |
          v
Cumulative Evidence Store
Per-identity evidence accumulation and normal-event decay
          |
          v
Trust-State Decision
NORMAL | DRIFTING | SUSPICIOUS | HIGH_RISK
          |
          v
Controlled Baseline Adaptation
Promote verified safe drift / block suspicious behavior
          |
          v
Streamlit Dashboard
Metrics | Charts | Explanations | CSV Event and Decision Logs
```

---

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application and behavioral trust logic |
| Streamlit | Live interactive dashboard |
| Pandas | Tables, CSV export, trend-chart data preparation |
| `Counter` and `deque` | Profile frequency tracking and recent score history |
| Git and GitHub | Version control and project collaboration |

---

## Monitored Event Fields

Every simulated event includes the following fields:

| Field | Description |
|---|---|
| `timestamp` | Time at which the event is generated |
| `identity` | Synthetic NHI performing the operation |
| `resource` | Resource accessed by the identity |
| `action` | `READ`, `WRITE`, `EXECUTE`, or `DELETE` |
| `bytes_transferred` | Simulated amount of transferred data |
| `source_ip` | Source IP address for the activity |
| `success` | Whether the simulated operation succeeds |
| `scenario` | Demonstration scenario label |

Example:

```json
{
  "timestamp": "20:15:42",
  "identity": "service_alpha",
  "resource": "orders_db",
  "action": "READ",
  "bytes_transferred": 1450,
  "source_ip": "10.0.0.8",
  "success": true,
  "scenario": "NORMAL"
}
```

---

## Risk-Scoring Signals

The system evaluates each event against the selected identity's trusted
baseline.

| Signal | Weight | Reason |
|---|---:|---|
| Previously unseen resource | 0.30 | May represent a new service dependency or unauthorized access |
| Previously unseen action | 0.20 | Detects unusual operation types |
| Previously unseen source IP | 0.20 | Detects new network origin |
| Data transfer above 3× baseline | 0.25 | Detects unusually large transfers |
| Failed operation | 0.15 | Detects abnormal access behavior |
| Sensitive resource access | 0.35 | Detects high-impact resource interaction |

The per-event score is capped at `1.0`.

---

## Trust-State Logic

| State | Trigger | Baseline Decision |
|---|---|---|
| `NORMAL` | No meaningful deviation evidence | Update trusted profile |
| `DRIFTING` | Low-risk per-event deviation or early cumulative evidence | Quarantine and observe |
| `SUSPICIOUS` | Multi-signal event or cumulative evidence ≥ `1.20` | Exclude from learning |
| `HIGH_RISK` | Severe event, sensitive-resource risk, or cumulative evidence ≥ `2.60` | Exclude from learning |

The system also records state changes for each identity.

---

## Baseline Protection

### Normal behavior

Normal observations update the identity's trusted resources, actions, IP
history, and average data volume.

```text
NORMAL event
      |
      v
Trusted behavioral baseline updated
```

### Legitimate drift

A low-risk new behavior is not trusted immediately. It is quarantined
until it has appeared safely at least three times.

```text
New low-risk behavior
      |
      v
Quarantine counter increases
      |
      v
Three safe observations
      |
      v
Eligible for trusted baseline promotion
```

### Suspicious or high-risk behavior

Suspicious and high-risk activity is never included in the trusted
baseline.

```text
SUSPICIOUS or HIGH_RISK event
      |
      v
Record explanation and quarantine observation
      |
      v
Exclude from trusted learning
      |
      v
Prevent baseline poisoning
```

---

## Surprise Challenge 1

### Baseline Poisoning Resistance

The system prevents unknown activity from becoming trusted immediately.

- `worker_beta` starts accessing `reporting_api`.
- The new resource initially becomes `DRIFTING`.
- It is placed in quarantine rather than being immediately trusted.
- After three low-risk observations, it can be promoted.
- Suspicious and high-risk behavior remains excluded from the baseline.

This demonstrates controlled adaptation: legitimate operational change can
be learned, while anomalous behavior cannot poison the profile.

---

## Surprise Challenge 2

### Slow-Burn Behavioral Deviation

A compromise may occur gradually. An attacker can introduce small
deviations over multiple events instead of producing one clear malicious
event.

For this challenge, `service_alpha` begins a `SLOW_BURN` scenario after
cycle 24. Early events use a new source-IP range and moderately changed
activity. The system stores a separate cumulative evidence score for the
identity.

```text
Mild deviation
      |
      v
Evidence accumulates per identity
      |
      v
DRIFTING
      |
      v
Repeated mild deviations
      |
      v
SUSPICIOUS
      |
      v
Persistent deviation evidence
      |
      v
HIGH_RISK
```

The implementation also decays evidence by `0.10` after normal behavior.
This reduces the chance that one harmless, isolated anomaly permanently
flags an identity.

When evidence reaches the suspicious threshold, baseline promotion is
blocked even if an unfamiliar behavior is observed repeatedly.

---

## Demo Scenarios

| Cycle | Identity | Scenario | Expected Outcome |
|---:|---|---|---|
| 1–5 | All identities | Warm-up normal behavior | `NORMAL` baseline learning |
| 6–11 | `worker_beta` | New `reporting_api` resource | `DRIFTING`, then safe promotion |
| 12–17 | `deploy_gamma` | New IP, unusual action, larger transfer | `SUSPICIOUS` |
| 18–23 | `api_delta` | Sensitive resource and high-volume access | `HIGH_RISK` |
| 24+ | `service_alpha` | Repeated mild new-IP and activity deviations | Slow-burn escalation |

---

## How to Run

### Prerequisites

- Python 3.10 or later
- Git
- Visual Studio Code or another Python editor

### Create and activate a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Start the dashboard

```bash
streamlit run app.py
```

Open the local URL displayed by Streamlit, usually:

```text
http://localhost:8501
```

---

## How to Demonstrate

1. Open the Dashboard page.
2. Click **Reset Demo**.
3. Use **Generate One Cycle** five times to establish baselines.
4. Continue to cycle 6 and select `worker_beta`.
5. Show that `reporting_api` is quarantined as legitimate drift.
6. Continue to cycle 8 and show promotion after repeated safe behavior.
7. Continue to cycle 12 and show `deploy_gamma` as `SUSPICIOUS`.
8. Continue to cycle 18 and show `api_delta` as `HIGH_RISK`.
9. Continue to cycle 24 and select `service_alpha`.
10. Show cumulative evidence growing across repeated mild deviations.
11. Show the risk and evidence trend charts.
12. Open the Explore page to explain the threat model and adaptation logic.
13. Download CSV logs if event or decision evidence is requested.

---

## Dashboard Outputs

The Dashboard page provides:

- Current state counts for all four trust levels.
- Live evaluation metrics.
- Identity Trust Overview table.
- Slow-Burn Deviation Monitor.
- Per-cycle risk-score chart.
- Per-cycle cumulative-evidence chart.
- Latest decision table with human-readable reasons.
- Identity-specific explanation panel.
- Trusted-resource and quarantined-resource views.
- Event stream table.
- CSV downloads for decision and event logs.

The Explore page explains:

- Threat model.
- Trust-state definitions.
- Controlled adaptation.
- Slow-burn defense.
- Evaluation metrics.
- Known limitations.

---

## Evaluation Metrics

| Metric | Meaning |
|---|---|
| Events Processed | Number of streaming events assessed |
| Baseline Updates | Normal or verified-drift events added to trust profiles |
| Baseline Protected | Events excluded from trusted learning |
| Average Decision Latency | Mean processing time per event |
| Suspicious Events | Count classified as `SUSPICIOUS` |
| High-Risk Events | Count classified as `HIGH_RISK` |
| Poisoning Attempts Blocked | Suspicious/high-risk observations excluded from baseline |
| Risk Trend | Per-event deviation score across simulation cycles |
| Evidence Trend | Per-identity cumulative evidence across cycles |

---

## Security and Safety

- The project uses synthetic identities and simulated resources only.
- No real credentials, customer data, production systems, or external
  targets are used.
- The application runs locally on normal hardware.
- The dashboard does not perform offensive actions or access external
  systems.
- Suspicious observations are recorded for explanation but blocked from
  changing trusted behavioral profiles.

---

## Known Limitations

- Events are synthetic and designed for a safe live demonstration.
- Risk weights and thresholds are rule-based rather than learned from a
  production dataset.
- Baselines exist only in Streamlit session state and reset when the app
  restarts.
- The prototype does not connect to a real IAM platform, SIEM, EDR,
  cloud audit log, or database.
- It does not yet model event timing, request frequency, or advanced
  action sequences.
- A production version would require secure log ingestion, persistent
  storage, authentication, alert routing, access control, audit
  retention, and threshold tuning from real organizational data.

---

## Future Improvements

- Persist profiles and event history using SQLite or PostgreSQL.
- Ingest sandboxed cloud or API audit logs.
- Add time-window, frequency, and sequence-based analysis.
- Add configurable policy thresholds and sensitive-resource lists.
- Add alert workflow integration with email, Slack, or SIEM systems.
- Add an analyst approval workflow for quarantined drift.
- Add precision, false-positive, response-time, and recovery metrics
  using labeled test scenarios.
- Add graph-based analysis of identity-to-resource relationships.

---

## Team Responsibilities

| Area | Suggested Responsibility |
|---|---|
| Event simulation | Generate safe normal, drift, suspicious, high-risk, and slow-burn events |
| Behavioral profiling | Maintain independent trusted and quarantine profiles |
| Risk engine | Score deviations and classify trust states |
| Baseline protection | Verify drift and block suspicious promotion |
| Dashboard | Implement Streamlit controls, metrics, charts, and exports |
| Documentation | Maintain README, architecture, screenshots, and demo workflow |
| GitHub | Commit genuine development progress and keep the repository current |

Replace the suggested responsibilities with your team members' actual
names and contributions before final submission.

---

## Conclusion

This project demonstrates a lightweight, explainable adaptive behavioral
trust system for Non-Human Identities. It assesses streaming identity
activity, distinguishes legitimate drift from suspicious change, adapts
only after controlled verification, and protects trust baselines from both
sudden attacks and gradual slow-burn compromise attempts.

### Team Responsibilities and Contribution

|Rithikakrishnan G| Streamlit dashboard and event simulation|
|Rithikakrishnan G|Behavioral risk engine and baseline adaptation|
|Akash S|Testing, Documentation, and Presentation|