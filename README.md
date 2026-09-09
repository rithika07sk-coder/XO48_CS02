# Adaptive Behavioral Trust for Non-Human Identities

## Cyber Security PS-02 | XO CODE 2026

A real-time behavioral trust-monitoring prototype for **Non-Human Identities (NHIs)** such as service accounts, API credentials, automation accounts, deployment bots, workload identities, and application identities.

The system continuously monitors identity activity, learns a separate behavioral baseline for every identity, detects meaningful deviations, prevents suspicious behavior from contaminating the trusted baseline, and assigns one of four operational trust states:

- `NORMAL`
- `DRIFTING`
- `SUSPICIOUS`
- `HIGH_RISK`

---

## Problem Statement

Modern systems depend heavily on non-human identities to access databases, APIs, cloud storage, repositories, deployment systems, and internal services.

A compromised service account can use valid credentials and gradually modify its behavior. For example, an attacker may first access one new resource, then slowly increase access frequency, introduce new actions, access sensitive resources, or transfer abnormal amounts of data. If a security system blindly learns every new event as normal, the attacker's behavior can poison the baseline.

This project addresses that challenge through an adaptive behavioral trust model that:

1. Learns normal behavior separately for each identity.
2. Detects new resources, actions, IP addresses, failures, and data-transfer deviations.
3. Differentiates low-risk operational drift from suspicious activity.
4. Quarantines uncertain behavior before allowing it to influence the baseline.
5. Prevents suspicious and high-risk events from becoming trusted behavior.
6. Provides a human-readable explanation for every decision.

---

## Objectives

- Build a continuously running activity-monitoring system.
- Maintain independent profiles for multiple NHIs.
- Analyze behavioral context rather than a single event field.
- Detect sudden suspicious actions and gradual behavioral changes.
- Support controlled baseline adaptation.
- Resist baseline poisoning attempts.
- Generate explanations for risk decisions.
- Demonstrate the four required trust states in a safe simulated environment.

---

## Trust States

| State | Meaning | Example |
|---|---|---|
| `NORMAL` | Behavior matches the identity's trusted baseline | A service account accesses its regular database with normal data volume |
| `DRIFTING` | New but currently low-risk behavior that needs observation | A service account starts using a newly deployed reporting API |
| `SUSPICIOUS` | Repeated or significant abnormal behavior | An identity uses an unfamiliar IP and abnormal action pattern |
| `HIGH_RISK` | Severe anomaly or access to a sensitive resource | An identity accesses a secrets vault with high data transfer |

---

## Key Features

- **Real-time activity stream** generated continuously for multiple identities.
- **Per-identity behavioral profiles** rather than one global baseline.
- **Warm-up learning phase** to establish initial trusted normal behavior.
- **Resource novelty detection** for newly accessed databases, APIs, buckets, and systems.
- **Action novelty detection** for unfamiliar actions such as `EXECUTE` or `DELETE`.
- **Source IP novelty detection** for access from unfamiliar network locations.
- **Data-volume anomaly detection** based on each identity's historical average.
- **Failed-action detection** for potentially abnormal access attempts.
- **Sensitive-resource detection** for high-impact systems such as secrets storage and admin consoles.
- **Quarantine-based adaptation** for unfamiliar but low-risk behavior.
- **Baseline protection** that prevents suspicious or high-risk behavior from changing the trusted profile.
- **Human-readable explanations** for every trust decision.

---

## System Architecture

```text
┌─────────────────────────────┐
│ Synthetic Activity Generator │
│  - Service accounts          │
│  - API identities            │
│  - Deployment identities     │
└──────────────┬──────────────┘
               │ Real-time events
               ▼
┌─────────────────────────────┐
│ Event Data Model             │
│  - Identity                  │
│  - Resource                  │
│  - Action                    │
│  - IP address                │
│  - Data volume               │
│  - Success / failure         │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│ Profile Manager              │
│  - Separate profile per NHI  │
│  - Trusted baseline          │
│  - Quarantine profile        │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│ Behavioral Risk Engine       │
│  - Anomaly scoring           │
│  - Cumulative risk           │
│  - State classification      │
│  - Explanation generation    │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│ Decision Output              │
│ NORMAL / DRIFTING /          │
│ SUSPICIOUS / HIGH_RISK       │
└─────────────────────────────┘
```

---

## Project Structure

```text
cyber_ps02_adaptive_trust/
│
├── src/
│   ├── __init__.py
│   ├── models.py
│   ├── activity_generator.py
│   ├── identity_profile.py
│   └── risk_engine.py
│
├── tests/
│   ├── __init__.py
│   ├── test_profile.py
│   └── test_risk_engine.py
│
├── data/
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Event Format

The activity generator produces events in the following format:

```json
{
  "identity": "service_alpha",
  "timestamp": "2026-09-09T11:35:20",
  "resource": "orders_db",
  "action": "READ",
  "bytes_transferred": 1400,
  "source_ip": "10.0.0.8",
  "success": true,
  "simulated_state": "NORMAL"
}
```

### Event Fields

| Field | Description |
|---|---|
| `identity` | Name of the non-human identity performing the action |
| `timestamp` | Time at which the activity occurred |
| `resource` | Database, API, storage bucket, or system being accessed |
| `action` | Operation performed, such as `READ`, `WRITE`, `DELETE`, or `EXECUTE` |
| `bytes_transferred` | Amount of data involved in the activity |
| `source_ip` | Source IP address associated with the event |
| `success` | Whether the requested operation succeeded |
| `simulated_state` | Scenario label used only for safe demonstration testing |

---

## Behavioral Risk Factors

The risk engine evaluates each event using the following signals:

| Risk Signal | Description | Example |
|---|---|---|
| New resource | Identity accesses a resource not in its trusted profile | First access to `reporting_api` |
| New action | Identity performs an unfamiliar action | `EXECUTE` appears for a read-only service |
| New IP address | Access comes from a previously unseen source IP | Access moves from internal IP to external IP |
| High data transfer | Transfer volume is much larger than normal | 20,000 bytes compared to a 1,500-byte baseline |
| Failed operation | Operation fails unexpectedly | Multiple unsuccessful access attempts |
| Sensitive resource | Identity accesses a high-impact system | `secrets_vault`, `admin_console`, or `production_backup` |
| Cumulative behavior | Multiple moderate anomalies occur close together | Repeated new resources and unusual activity patterns |

---

## Risk Scoring Method

The system calculates a risk score from `0.0` to `1.0`.

```text
Risk Score =
    New Resource Score
  + New Action Score
  + New Source IP Score
  + High Data Transfer Score
  + Failed Operation Score
  + Sensitive Resource Score
```

Current prototype weights:

| Condition | Score Added |
|---|---:|
| New resource | 0.30 |
| New action | 0.20 |
| New source IP | 0.20 |
| Data transfer more than 3× normal average | 0.25 |
| Failed action | 0.15 |
| Sensitive resource access | 0.35 |

The final score is capped at `1.0`.

---

## State Classification Logic

```text
Risk score < 0.25
    → NORMAL

0.25 ≤ Risk score < 0.55
    → DRIFTING

0.55 ≤ Risk score < 0.80
    → SUSPICIOUS

Risk score ≥ 0.80
    → HIGH_RISK
```

The system also considers the recent average risk score for an identity. This helps identify cumulative suspicious activity instead of treating every action as fully independent.

---

## Controlled Baseline Adaptation

A critical requirement of this project is preventing baseline poisoning.

### Trusted baseline update

Events classified as `NORMAL` are added to the identity's trusted baseline.

```text
NORMAL event
      ↓
Trusted behavior profile updated
```

### Quarantine process

Events classified as `DRIFTING` are not immediately trusted.

```text
New low-risk behavior
      ↓
Quarantine profile
      ↓
Repeated observation required
      ↓
Possible future trusted baseline update
```

### Suspicious and high-risk behavior

Events classified as `SUSPICIOUS` or `HIGH_RISK` are excluded from trusted learning.

```text
Suspicious or high-risk event
      ↓
Risk alert generated
      ↓
Event remains outside trusted baseline
      ↓
Baseline poisoning is prevented
```

---

## Demo Scenarios

The simulated event stream demonstrates the following situations:

| Identity | Scenario | Expected System State |
|---|---|---|
| `service_alpha` | Stable regular access to known resources | `NORMAL` |
| `worker_beta` | Starts accessing a new analytics/reporting resource | `DRIFTING` |
| `deploy_gamma` | Uses unusual actions, IP addresses, or large transfers | `SUSPICIOUS` |
| `api_delta` | Accesses sensitive resources such as a secrets vault | `HIGH_RISK` |

### Demonstration Flow

1. The system begins in a warm-up phase and learns normal activity.
2. `service_alpha` continues normal behavior and remains trusted.
3. `worker_beta` introduces low-risk new behavior and moves to `DRIFTING`.
4. The drifting behavior is placed in quarantine instead of being immediately trusted.
5. `deploy_gamma` creates multiple unusual signals and becomes `SUSPICIOUS`.
6. `api_delta` accesses sensitive resources with high transfer volume and becomes `HIGH_RISK`.
7. Suspicious and high-risk behavior does not update the trusted baseline.

---

## Installation

### Prerequisites

- Python 3.10 or later
- Git
- Visual Studio Code or another Python IDE

### Create and activate a virtual environment

#### Windows PowerShell

```powershell
python -m venv .venv
.venv\Scripts\activate
```

#### Linux/macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## How to Run

### Run the real-time activity generator

From the root project folder:

```bash
python -m src.activity_generator
```

The terminal prints a continuous stream of JSON activity events.

Stop the generator with:

```text
Ctrl + C
```

### Test behavioral profiles

```bash
python -m tests.test_profile
```

This test verifies that:

- A normal event updates the trusted baseline.
- A drifting event is stored in quarantine.
- Each identity receives an independent profile.

### Test the risk engine

```bash
python -m tests.test_risk_engine
```

This test demonstrates:

- Warm-up baseline learning.
- Normal behavior.
- Drifting behavior.
- High-risk behavior.
- Risk-score calculation.
- Explanation generation.
- Baseline update and quarantine decisions.

---

## Example Decision Output

```text
RiskDecision(
    identity='api_delta',
    state='HIGH_RISK',
    risk_score=1.0,
    reasons=[
        'New resource accessed: secrets_vault',
        'New action observed: EXECUTE',
        'New source IP observed: 203.0.113.45',
        'Data transfer is unusually high',
        'Sensitive resource accessed: secrets_vault',
        'Behavior was excluded from the trusted baseline because its risk level is suspicious or high-risk.'
    ],
    baseline_updated=False
)
```

---

## Security Design Principles

- The project uses only synthetic and sandboxed identity activity.
- No real credentials, customer data, production systems, or external targets are used.
- Each identity has an independent behavioral baseline.
- Unseen behavior is not automatically treated as malicious.
- Unseen behavior is also not automatically trusted.
- Suspicious observations do not modify the trusted baseline.
- The system produces explainable outputs instead of an opaque anomaly score alone.
- The prototype is designed to run on a normal development machine.

---

## Limitations

This is a hackathon prototype. Current limitations include:

- The activity source is simulated rather than connected to real IAM, SIEM, cloud, or audit logs.
- Thresholds and scoring weights are initially rule-based.
- The first version uses simple recent-score aggregation instead of advanced sequence models.
- Drift confirmation is represented through quarantine but can be expanded with stronger approval and observation policies.
- Identity-resource relationships can be enhanced with graph-based behavioral analysis.
- A production system would require secure log ingestion, authentication, role-based access control, encryption, alerting integrations, and privacy controls.

---

## Future Improvements

- Add a Streamlit live monitoring dashboard.
- Store events and profiles in SQLite or PostgreSQL.
- Add an API layer using FastAPI.
- Add real-time charts for identity risk, state transitions, and anomaly trends.
- Introduce time-of-day and request-frequency analysis.
- Add sequential anomaly detection using Markov models or LSTM/Transformer-based sequence models.
- Add graph-based analysis of identity-to-resource relationships.
- Add configurable policies for sensitive resources.
- Add alerting through email, Slack, or SIEM-compatible outputs.
- Add a review workflow to approve legitimate behavioral drift.
- Add metrics for false positives, response latency, baseline contamination resistance, and drift handling.

---

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core implementation |
| Pydantic | Event validation and structured data model |
| Dataclasses | Behavioral profile and decision structures |
| Collections / Counter | Frequency tracking for trusted and quarantine profiles |
| Pytest or Python test scripts | Functional testing |
| Git and GitHub | Version control and collaboration |
| Streamlit | Planned real-time dashboard |
| FastAPI | Planned backend API |
| Pandas / NumPy | Planned event analysis and metrics |
| Scikit-learn | Planned advanced anomaly detection |

---

## Team Responsibilities

| Area | Responsibility |
|---|---|
| Event simulation | Generate safe and realistic NHI activity streams |
| Behavioral profiling | Maintain trusted and quarantine profiles per identity |
| Risk analysis | Detect deviations and calculate trust scores |
| Baseline protection | Prevent suspicious behavior from becoming trusted |
| Testing | Validate normal, drift, suspicious, high-risk, and poisoning scenarios |
| Documentation | Maintain setup, architecture, and demonstration instructions |
| GitHub | Commit meaningful development progress and maintain repository quality |

---

## Conclusion

This project demonstrates an adaptive behavioral trust approach for non-human identities. Instead of only detecting isolated anomalies, it models each identity separately, evaluates changing behavior over time, quarantines uncertain changes, and protects the trusted baseline against suspicious or gradually introduced malicious activity.

The goal is to help security teams distinguish between legitimate workload evolution and possible credential compromise while keeping the system explainable, lightweight, and suitable for continuous monitoring.
