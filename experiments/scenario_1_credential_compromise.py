"""
Scenario 1 — Credential Compromise (Section 15).

This script demonstrates the FULL pipeline end-to-end, wiring together every
module built so far:

    Incident -> AI Investigation -> AI Recovery Plan -> Recovery Orchestrator
             -> Assurance Engine -> Controlled Re-Attack -> Recovery Proof

IMPORTANT — what this script is and isn't:
    - Every LLM call, execution, and re-attack result here is FAKE/MOCK,
      because the isolated lab (Phase 03-06: VMware, Sysmon, Wazuh, Kali)
      does not exist yet. This script exists to validate that the pipeline's
      *control flow and data contracts* are correct end-to-end, not to
      produce a real experimental result.
    - Section 22 forbids fabricating experimental results. Nothing in this
      script's output should ever be reported as a real finding — every
      output is tagged "simulated": true at the evidence level, and this
      docstring says so explicitly. Once the lab exists, this same script
      structure will be reused with real clients/executors/evidence.

Two runs are demonstrated:
    Run A — the "clean" path: investigation finds a compromised account,
        recovery disables it and rotates credentials, all invariants pass,
        and the re-attack (attempting to reuse the credential) is blocked.
        Expected verdict: PROVEN.
    Run B — the "false recovery" path: identical up through assurance (all
        invariants pass), but the re-attack still succeeds — demonstrating
        the project's central thesis: passing invariants alone can miss a
        recovery failure that a live re-attack catches.
        Expected verdict: FAILED.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ai_engine.investigation import investigate
from ai_engine.recovery_planner import plan_recovery
from ai_engine.schemas import Incident, Severity
from assurance.engine import (
    AccountDisabledInvariant,
    MockEvidenceProvider,
    run_assurance,
)
from re_attack.simulator import MockReAttackScenario, run_re_attack
from re_attack.validator import determine_recovery_proof
from recovery.orchestrator import AutoApprovalProvider, MockActionExecutor, execute_plan

RESULTS_DIR = Path(__file__).parent / "results"


class FakeLLMClient:
    """Returns a fixed canned response. See ai_engine tests for the same pattern."""

    def __init__(self, response: str):
        self._response = response

    def complete(self, system: str, user: str) -> str:
        return self._response


def build_incident() -> Incident:
    return Incident(
        incident_id="INC-SCN1-001",
        source="wazuh",
        severity=Severity.HIGH,
        host="WIN-01",
        user="user123",
        alert="Suspicious authentication followed by lateral movement attempt",
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
    )


def run_investigation(incident: Incident):
    fake_response = json.dumps(
        {
            "incident_id": incident.incident_id,
            "severity": "high",
            "findings": [
                {
                    "description": "Valid credentials for user123 used from an unusual source host",
                    "evidence_source": "wazuh_alert",
                    "confidence": "high",
                }
            ],
            "root_cause": "Compromised credential for user123 used for lateral movement",
            "affected_assets": ["WIN-01"],
            "recommended_recovery": ["disable_account", "rotate_credentials"],
        }
    )
    return investigate(incident, client=FakeLLMClient(fake_response))


def run_planning(investigation):
    fake_response = json.dumps(
        {
            "actions": [
                {
                    "action": "disable_account",
                    "target": "user123",
                    "reason": "Compromised credential used for lateral movement",
                },
                {
                    "action": "rotate_credentials",
                    "target": "user123",
                    "reason": "Credential must be invalidated to prevent reuse",
                },
            ]
        }
    )
    return plan_recovery(investigation, client=FakeLLMClient(fake_response))


def run_orchestration(plan):
    # Demo only: auto-approving everything. A real deployment would use
    # CLIApprovalProvider or a real human-in-the-loop workflow here —
    # never approve_all=True outside of a controlled demo/test.
    return execute_plan(
        plan,
        executor=MockActionExecutor(),
        approval_provider=AutoApprovalProvider(approve_all=True),
    )


def run_assurance_check(incident: Incident) -> "AssuranceReport":  # noqa: F821 (type hint string to avoid unused import)
    evidence = MockEvidenceProvider()
    # Simulate that the recovery actually took effect: the account is now disabled.
    evidence.set_account_enabled(incident.user, False)

    return run_assurance(
        incident_id=incident.incident_id,
        invariants=[AccountDisabledInvariant(incident.user)],
        evidence=evidence,
    )


def print_stage(title: str, payload) -> None:
    print(f"\n=== {title} ===")
    print(payload.model_dump_json(indent=2))


def run_scenario(re_attack_blocked: bool, label: str) -> None:
    print(f"\n{'#' * 70}\nSCENARIO 1 — Credential Compromise — Run: {label}\n{'#' * 70}")

    incident = build_incident()
    print_stage("1. Incident", incident)

    investigation = run_investigation(incident)
    print_stage("2. Investigation Result", investigation)

    plan = run_planning(investigation)
    print_stage("3. Recovery Plan", plan)

    execution_results = run_orchestration(plan)
    print("\n=== 4. Execution Results ===")
    for result in execution_results:
        print(result.model_dump_json(indent=2))

    assurance_report = run_assurance_check(incident)
    print_stage("5. Assurance Report", assurance_report)

    re_attack_result = run_re_attack(
        MockReAttackScenario(
            incident_id=incident.incident_id,
            scenario_name="credential_reuse_attempt",
            outcome_blocked=re_attack_blocked,
        )
    )
    print_stage("6. Re-Attack Result", re_attack_result)

    proof = determine_recovery_proof(assurance_report, re_attack_result)
    print_stage("7. RECOVERY PROOF", proof)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / f"scenario_1_{label}.json"
    out_path.write_text(proof.model_dump_json(indent=2), encoding="utf-8")
    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    run_scenario(re_attack_blocked=True, label="proven")
    run_scenario(re_attack_blocked=False, label="false_recovery")
