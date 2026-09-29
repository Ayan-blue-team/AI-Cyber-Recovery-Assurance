<div align="center">

# AI Cyber Recovery Assurance
[![Tests](https://github.com/Ayan-blue-team/AI-Cyber-Recovery-Assurance/actions/workflows/tests.yml/badge.svg)](https://github.com/Ayan-blue-team/AI-Cyber-Recovery-Assurance/actions/workflows/tests.yml)

**AI-Assisted Incident Recovery with Independent Security Verification and Controlled Re-Attack Validation**

[![Status](https://img.shields.io/badge/status-early%20development-yellow)]()
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)]()
[![Research](https://img.shields.io/badge/type-cybersecurity%20research-informational)]()
[![Lab Only](https://img.shields.io/badge/scope-isolated%20lab%20only-critical)]()

> Recovery is not considered successful until the recovered environment passes independent security verification and survives controlled re-attack.

</div>

---

## Table of Contents

- [Overview](#overview)
- [Research Problem](#research-problem)
- [Research Question](#research-question)
- [System Model](#system-model)
- [Core Methodology](#core-methodology)
- [AI / Security Boundary](#ai--security-boundary)
- [Security Invariants](#security-invariants)
- [Evaluation Framework](#evaluation-framework)
- [Experimental Scenarios](#experimental-scenarios)
- [Technology Stack](#technology-stack)
- [Repository Structure](#repository-structure)
- [Getting Started](#getting-started)
- [Documentation](#documentation)
- [Development Roadmap](#development-roadmap)
- [Research Contribution](#research-contribution)
- [Current Status](#current-status)
- [Safety & Scope](#safety--scope)
- [License](#license)

---

## Overview

**AI Cyber Recovery Assurance** is a cybersecurity research and engineering project investigating how AI-assisted incident recovery can be **independently verified**.

Modern security operations increasingly rely on AI to investigate alerts, correlate evidence, identify probable root causes, and recommend response actions. However, generating a recovery plan does not, by itself, demonstrate that a compromised environment has actually returned to a secure state.

This project introduces an **additional assurance layer** between recovery and incident closure. The system:

1. Investigates the incident
2. Generates a structured recovery plan
3. Executes controlled recovery actions
4. Evaluates predefined security invariants
5. Reproduces relevant attack techniques in an isolated environment
6. Determines whether the recovered state withstands re-validation

Recovery verification is treated as an **explicit security problem**, rather than an assumption that successful remediation commands imply successful recovery.

---

## Research Problem

A conventional incident-response lifecycle can be simplified as:

```
Detection → Investigation → Response → Recovery → Closure
```

The problem is that **operational recovery** and **security recovery** are not necessarily equivalent. A system may be available again while:

- Compromised credentials remain valid
- Persistence mechanisms remain active
- Unauthorized accounts remain
- Security controls remain degraded
- Telemetry is incomplete
- The original exploitation path remains available

This project investigates whether recovery can be evaluated through an **independently verifiable security state**.

### Research Question

> Can an AI-assisted incident recovery workflow be independently verified through security invariants and controlled re-attack validation to determine whether a compromised environment has actually recovered securely?

---

## System Model

```mermaid
flowchart TB
    A["Attack Engine<br/>(Kali Linux)"] -->|Controlled TTP| B["Target Environment<br/>Windows / Linux<br/>Sysmon / auditd<br/>Defender / Firewall"]
    B -->|Telemetry| C["Wazuh Layer<br/>Collection · Detection<br/>Correlation · Alerting"]
    C --> D["AI SOC Engine<br/>Investigation<br/>Root Cause Analysis<br/>Recovery Planning"]
    D -->|Structured Plan| E["Recovery Orchestrator<br/>Python · PowerShell · Bash / APIs"]
    E -->|Recovery| F["Assurance Engine<br/>Security Invariants<br/>State Verification<br/>Evidence Validation"]
    F --> G["Controlled Re-Attack<br/>Reproduce relevant attack techniques"]
    G -->|Blocked| H["Recovery Proven ✅"]
    G -->|Success| I["Recovery Failed ❌"]
```

---

## Core Methodology

The system is built around four stages.

### 01 — Recovery

The AI analyzes the incident and generates a structured recovery plan:

```json
{
  "action": "disable_account",
  "target": "user123",
  "reason": "suspected credential compromise",
  "risk": "medium"
}
```

The AI does not directly execute unrestricted privileged commands. All actions pass through the recovery orchestration layer.

### 02 — Assurance

After recovery, an independent verification engine evaluates whether required security conditions are satisfied, including:

- Compromised account disabled
- Credentials rotated
- Malicious process removed
- Persistence removed
- Unauthorized administrative access removed
- Firewall configuration restored
- Endpoint security agent active
- Telemetry restored
- Exploited vulnerability remediated
- Malicious network connection removed

Each invariant produces one of: `PASS` · `FAIL` · `UNKNOWN`

### 03 — Re-Validation

The system safely reproduces relevant portions of the original attack inside the isolated laboratory. The goal is **not** to generate damage — it is to answer:

> Can the same security failure still be reproduced after recovery?

### 04 — Recovery Proof

The final recovery state combines invariant verification and controlled re-attack results, producing one of:

`PROVEN` · `PARTIALLY PROVEN` · `FAILED` · `UNKNOWN`

The exact decision logic is implemented and unit-tested in `re_attack/validator.py`; see [`docs/methodology.md`](docs/methodology.md) for the full rule set.

---

## AI / Security Boundary

A fundamental design principle is the **separation between AI reasoning and privileged execution**.

```mermaid
flowchart TB
    A["AI SOC Engine<br/>Investigation · Root Cause · Recovery Plan"] -->|Structured Request| B["Recovery Policy &<br/>Validation Layer"]
    B -->|Authorized Action| C["Recovery Executor<br/>PowerShell / Bash / Python / APIs"]
```

This architecture prevents the language model from being treated as an unrestricted system administrator. In the current implementation, this boundary is enforced in code: the AI recovery planner (`ai_engine/recovery_planner.py`) never sets an action's risk or approval requirement itself — a deterministic policy table does, and any action type the model proposes that isn't recognized is forced into a fail-safe, human-approval-required state.

---

## Security Invariants

Security invariants represent conditions that should hold after recovery.

| Category | Example |
|---|---|
| Identity | Compromised account disabled |
| Credentials | Compromised credentials rotated |
| Persistence | Malicious persistence removed |
| Process | Malicious process terminated |
| Network | Unauthorized connection removed |
| Firewall | Expected policy restored |
| Endpoint | Security agent operational |
| Telemetry | Required logs available |
| Vulnerability | Exploited weakness remediated |
| Backup | Recovery source verified |

The Assurance Engine evaluates these conditions **independently** from the AI's own conclusion. Missing evidence is always reported as `UNKNOWN` — it is never treated as a passing result.

---

## Evaluation Framework

| Metric | Description |
|---|---|
| Recovery Success Rate | Percentage of scenarios reaching verified recovery |
| Invariant Pass Rate | Percentage of required invariants satisfied |
| Re-Attack Success Rate | Percentage of scenarios where the original compromise remains reproducible |
| False Recovery Rate | Cases where recovery appears successful but fails independent validation |
| Recovery Time | Time from incident identification to verified recovery |
| Manual Intervention | Human actions required during recovery |
| AI Plan Accuracy | Correctness of recommended recovery actions |
| Verification Coverage | Percentage of relevant security conditions tested |

These metrics will be measured across multiple controlled attack scenarios once real lab integration (see [Current Status](#current-status)) is complete.

---

## Experimental Scenarios

The initial laboratory will focus on controlled scenarios such as:

- **Credential Compromise**
  - Account Abuse
  - Credential Rotation
- **Persistence**
  - Scheduled Task
  - Startup Persistence
- **Privilege Escalation**
  - Controlled Privilege Abuse
- **Execution**
  - Suspicious PowerShell
- **Lateral Movement**
  - Controlled Remote Access
- **Ransomware Simulation**
  - Non-destructive Recovery Validation

All scenarios run exclusively inside the isolated laboratory. See [`docs/threat_model.md`](docs/threat_model.md) for the assumed attacker capability and safety boundaries for each scenario.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Endpoint Monitoring | Sysmon, Windows Event Logs, auditd |
| SIEM / XDR | Wazuh |
| AI / Automation | Python, LLM API, Pydantic |
| Recovery | Python, PowerShell, Bash |
| Attack Simulation | Kali Linux |
| Virtualization | VMware |
| Testing | pytest |
| Version Control | Git / GitHub |
| Future UI | Web-based dashboard |

---

## Repository Structure

```
AI-Cyber-Recovery-Assurance/
│
├── ai_engine/
│   ├── schemas.py
│   ├── investigation.py
│   ├── recovery_planner.py
│   └── prompts/
│
├── recovery/
│   ├── orchestrator.py
│   ├── actions/
│   └── rollback/
│
├── assurance/
│   ├── engine.py
│   ├── invariants/
│   ├── persistence_checks.py
│   ├── identity_checks.py
│   ├── telemetry_checks.py
│   └── network_checks.py
│
├── re_attack/
│   ├── scenarios/
│   ├── simulator.py
│   └── validator.py
│
├── attacks/
│   ├── persistence/
│   ├── credential_compromise/
│   ├── privilege_escalation/
│   └── ransomware_simulation/
│
├── experiments/
│   ├── results/
│   ├── scenario_1_credential_compromise.py
│   └── evaluation.py
│
├── dashboard/
│
├── docs/
│   ├── methodology.md
│   ├── threat_model.md
│   └── research.md
│
├── tests/
│
└── .github/workflows/tests.yml
```

---

## Getting Started

The software pipeline (AI engine, orchestrator, assurance engine, re-attack
decision logic) can be run and tested today, independently of the physical
lab, using mocked LLM and evidence components.

```bash
git clone https://github.com/Ayan-blue-team/AI-Cyber-Recovery-Assurance.git
cd AI-Cyber-Recovery-Assurance

python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

pip install -r requirements.txt

# Run the full test suite
pytest -v

# Run the end-to-end Scenario 1 demo (mocked components — see docs/methodology.md)
python experiments/scenario_1_credential_compromise.py
```

A real `ANTHROPIC_API_KEY` is only required for live LLM calls; it is not
needed to run the test suite or the mocked demo script above. Set it in a
local `.env` file (never committed — see `.gitignore`) when working with
real model calls.

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/methodology.md`](docs/methodology.md) | Research question, design principles, pipeline stages, Recovery Proof decision rules, implementation status |
| [`docs/threat_model.md`](docs/threat_model.md) | Attacker profile per scenario, scope, safety controls, non-goals |
| `docs/research.md` | Experimental results and baseline comparison (added once real lab evaluation begins) |

---

## Development Roadmap

| # | Milestone | Status |
|---|---|---|
| 01 | Repository & Development Environment | ✅ Done |
| 02 | Isolated Security Laboratory (network, Windows target, Kali) | ✅ Done |
| 03 | Endpoint Telemetry (Sysmon on Windows target) | ✅ Done |
| 04 | Wazuh Detection Pipeline | 🔄 In progress |
| 05 | Controlled Attack Scenarios (real, in-lab) | ⬜ Not started |
| 06 | AI Investigation Engine | ✅ Implemented (mocked LLM, CI-tested) |
| 07 | Recovery Planner | ✅ Implemented (mocked LLM, CI-tested) |
| 08 | Recovery Orchestrator | ✅ Implemented (mock executor, CI-tested) |
| 09 | Security Assurance Engine | ✅ Implemented (mock evidence, CI-tested) |
| 10 | Controlled Re-Attack | ✅ Decision logic implemented (mock scenario, CI-tested) |
| 11 | Recovery Proof | ✅ Implemented and unit-tested (5 explicit decision rules) |
| 12 | Experimental Evaluation (real lab data) | ⬜ Not started |
| 13 | Dashboard & Research Documentation | ⬜ Not started |

**Note:** items 06–11 are complete at the *software* level — every stage
runs end-to-end and is covered by automated tests — but still uses mocked
LLM responses, mocked evidence, and a mocked re-attack outcome in place of
the real lab (items 02–05). See [`docs/methodology.md`](docs/methodology.md#4-implementation-status)
for the exact boundary between what has been tested in software and what
has been validated against a real environment.

---

## Research Contribution

This project does not claim that AI-assisted recovery, security verification, or adversarial validation individually originate here.

Instead, the project focuses on implementing and experimentally evaluating a specific **integrated workflow**:

```
AI Recovery → Independent Security Assurance → Controlled Re-Attack → Recovery Proof
```

The goal is to investigate whether this workflow can reduce the gap between *"the recovery procedure completed"* and *"the security failure was actually remediated."*

---

## Current Status

### Software Pipeline

*(implemented, automated-tested via CI, currently using mocked LLM/evidence — see [Documentation](#documentation))*

| Component | Progress |
|---|---|
| Repository & CI | `████████████████████` 100% |
| Data Contracts (`ai_engine/schemas.py`) | `████████████████████` 100% |
| AI Investigation Engine | `████████████████████` 100% |
| AI Recovery Planner | `████████████████████` 100% |
| Recovery Orchestrator | `████████████████████` 100% |
| Assurance Engine (5 invariants) | `████████████████████` 100% |
| Re-Attack Decision Logic | `████████████████████` 100% |
| End-to-End Integration (Scenario 1, mocked) | `████████████████████` 100% |

### Lab & Real-World Integration

| Component | Progress |
|---|---|
| Isolated Network (192.168.50.0/24) | `████████████████████` 100% |
| Windows Target (WIN-01) | `████████████████████` 100% |
| Kali Attacker | `████████████████████` 100% |
| Endpoint Telemetry (Sysmon) | `████████████████████` 100% |
| Wazuh Detection Pipeline | `████░░░░░░░░░░░░░░░░` 20% |
| Real Attack Scenarios (in-lab) | `░░░░░░░░░░░░░░░░░░░░` 0% |
| Real AI Investigation (live LLM + telemetry) | `░░░░░░░░░░░░░░░░░░░░` 0% |
| Real Assurance (live evidence sources) | `░░░░░░░░░░░░░░░░░░░░` 0% |
| Real Controlled Re-Attack | `░░░░░░░░░░░░░░░░░░░░` 0% |
| Experimental Evaluation & Baseline Comparison | `░░░░░░░░░░░░░░░░░░░░` 0% |

No experimental result in this repository is reported as real unless it
was produced by the actual lab environment. Results produced with mocked
components are explicitly labeled `"simulated": true` in code and output.

---

## Safety & Scope

> ⚠️ This project is intended **exclusively** for authorized cybersecurity research and isolated laboratory environments.

- Attack simulations must be performed only against systems owned by the researcher or explicitly authorized for testing.
- No real-world infrastructure, credentials, accounts, or third-party systems are targeted.

---

<div align="center">

**Recovery should not be trusted simply because it completed. It should be verified.**

`AI` · `SOC` · `Incident Response` · `Security Assurance` · `Adversarial Validation`

</div>

---

## License

This project is licensed under the [MIT License](LICENSE).
