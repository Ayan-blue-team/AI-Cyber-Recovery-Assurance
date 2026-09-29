# Methodology

## 1. Research Question

Traditional incident response workflows treat recovery as complete once
remediation actions have been executed: a compromised account is disabled,
a malicious process is terminated, a firewall rule is restored. Completion
of these actions is typically treated as equivalent to the environment
being secure again.

This project investigates whether that assumption is safe to make, and
proposes an alternative:

> Can an AI-assisted incident recovery workflow be independently verified
> through deterministic security invariants and controlled re-attack
> validation, to determine whether a compromised environment has actually
> recovered securely?

Recovery, in this project, is not considered proven by the completion of
recovery actions alone. It is proven only when the recovered environment
(a) passes independent, deterministic security checks, and (b) survives a
controlled attempt to reproduce the original attack.

### Secondary questions

1. Can an AI model generate structured, evidence-grounded recovery plans
   from incident data, without fabricating findings?
2. Can deterministic invariants catch recovery failures that an AI's own
   assessment would miss?
3. Can a controlled re-attack reveal recovery failures that pass every
   static invariant check?
4. What categories of recovery decisions must remain under human approval,
   and how should that boundary be enforced in software rather than left
   as a policy statement?

## 2. Design Principles

Three principles shaped every architectural decision in this project:

**AI reasons; it does not execute.** The language model used in the
investigation and recovery-planning stages produces structured proposals
only. It has no shell access, no credentials, and no path to directly
modify the environment. Every proposal passes through a separate,
deterministic policy layer before anything is executed
(`ai_engine/recovery_planner.py`), and execution itself is isolated in a
single component (`recovery/orchestrator.py`) that independently
re-checks approval requirements.

**Missing evidence is not a passing result.** The assurance engine
(`assurance/engine.py`) treats every security invariant as one of three
states: `PASS`, `FAIL`, or `UNKNOWN`. `UNKNOWN` is returned whenever
evidence cannot be retrieved, and it is never silently treated as `PASS`
by any consuming code. This was chosen deliberately to avoid the most
common failure mode of automated verification systems: mistaking absence
of a finding for absence of a problem.

**Static checks alone are not proof.** Even if every invariant returns
`PASS`, that result describes the environment's *state* at a point in
time — it does not prove that the underlying vulnerability or compromise
path cannot be reproduced. The controlled re-attack stage exists
specifically to test that claim empirically rather than assume it.

## 3. Pipeline

Incident -> AI Investigation -> AI Recovery Plan -> Recovery Orchestrator
-> Assurance Engine -> Controlled Re-Attack -> Recovery Proof


Each stage is implemented as an independently testable module with an
explicit data contract (`ai_engine/schemas.py`), so that any stage can be
replaced (e.g. swapping a mock evidence source for a real Wazuh/AD-backed
one) without requiring changes to the stages around it.

| Stage | Module | Responsibility |
|---|---|---|
| Investigation | `ai_engine/investigation.py` | Turn incident + telemetry into structured findings |
| Recovery Planning | `ai_engine/recovery_planner.py` | Propose recovery actions; apply deterministic risk/approval policy |
| Orchestration | `recovery/orchestrator.py` | Gate on approval, execute, maintain audit trail |
| Assurance | `assurance/engine.py` | Deterministic invariant checks (PASS/FAIL/UNKNOWN) |
| Re-Attack | `re_attack/simulator.py` | Replay the relevant TTP in a controlled, isolated manner |
| Proof | `re_attack/validator.py` | Combine assurance + re-attack into a final verdict |

### Recovery Proof decision rules

The final verdict (`PROVEN`, `PARTIALLY_PROVEN`, `FAILED`, `UNKNOWN`) is
computed by explicit, tested rules (`re_attack/validator.py`), in priority
order:

1. **Any invariant `FAIL` → `FAILED`.** A definitive, evidenced violation
   outweighs any ambiguity elsewhere.
2. **No `FAIL`, but any invariant `UNKNOWN` → `UNKNOWN`.** Incomplete
   evidence is never upgraded to a positive result.
3. **All invariants `PASS`, no re-attack performed yet → `PARTIALLY_PROVEN`.**
   State checks passed, but the central claim of the project — survival
   of a live re-attack — has not yet been tested.
4. **All invariants `PASS`, re-attack blocked → `PROVEN`.**
5. **All invariants `PASS`, re-attack succeeds anyway → `FAILED`.** This is
   the failure mode the project exists to catch: deterministic checks can
   look clean while the original compromise remains reproducible.

## 4. Implementation Status

As of this writing, the full pipeline (Sections 7–14 of the project's
master specification) is implemented and unit/integration tested at the
**software level**, using mocked components in place of a real lab
environment:

- The LLM client used by the investigation and planning stages is
  injectable (`LLMClient` protocol); tests and demonstration scripts use a
  fake client returning canned responses, not live model calls.
- The evidence source used by the assurance engine is a
  `MockEvidenceProvider`, populated with explicit test values rather than
  queried from a real Windows/AD/Sysmon environment.
- The re-attack stage uses a `MockReAttackScenario`, whose outcome is
  supplied directly rather than observed from a real Kali-vs-target
  exchange.

This status is reflected explicitly in code (every mock component tags
its evidence `"simulated": true`) and in experiment output
(`experiments/results/`), per the project's requirement that no result be
represented as real unless it was actually observed.

A minimal isolated lab (VMware, host-only network `192.168.50.0/24`, one
Windows target, one Kali attacker) has been built separately and is being
integrated with the pipeline incrementally, starting with endpoint
telemetry (Sysmon) on the Windows target.

## 5. Evaluation Plan

Once real lab integration is complete, the project will be evaluated
against the metrics defined in the project specification:

- **Recovery Success Rate** — percentage of scenarios reaching a `PROVEN` verdict.
- **False Recovery Rate** — percentage of scenarios where all invariants
  passed but the re-attack still succeeded (rule 5 above). This is the
  metric most directly tied to the project's central thesis.
- **Invariant Pass Rate**, **Re-Attack Success Rate**, **Recovery Time**,
  **Manual Intervention Count**, **AI Plan Accuracy**, **Verification
  Coverage** — as defined in the project specification.

Results will be compared against a baseline workflow that stops at
"recovery complete" without independent assurance or re-attack
validation, to test whether the additional stages catch failures the
baseline would report as resolved.

## 6. Integrity Statement

No experimental result in this repository is reported as real unless it
was produced by the actual lab environment described above. Results
produced with mocked components are labeled as simulated wherever they
appear, in code and in output. This document will be updated as each
project phase moves from simulated to real validation.
