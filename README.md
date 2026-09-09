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

1. Learns normal beha
