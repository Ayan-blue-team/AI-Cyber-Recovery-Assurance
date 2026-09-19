"""
Integration test for the full Scenario 1 pipeline (Section 15).

Unlike the other test files, this one does not test a single module in
isolation — it wires investigation -> planning -> orchestration ->
assurance -> re-attack -> recovery proof together, the same way
experiments/scenario_1_credential_compromise.py does, and checks that the
final verdict is what the project's design says it should be.
"""

from experiments.scenario_1_credential_compromise import (
    build_incident,
    run_assurance_check,
    run_investigation,
    run_orchestration,
    run_planning,
)
from ai_engine.schemas import RecoveryProofStatus
from re_attack.simulator import MockReAttackScenario, run_re_attack
from re_attack.validator import determine_recovery_proof


def test_full_pipeline_proven_when_re_attack_blocked():
    incident = build_incident()
    investigation = run_investigation(incident)
    plan = run_planning(investigation)
    execution_results = run_orchestration(plan)
    assurance_report = run_assurance_check(incident)

    # Sanity check on the earlier stages before asserting the final verdict.
    assert investigation.root_cause is not None
    assert len(plan.actions) == 2
    assert all(r.executed for r in execution_results)
    assert assurance_report.any_fail is False
    assert assurance_report.any_unknown is False

    re_attack_result = run_re_attack(
        MockReAttackScenario(incident.incident_id, "credential_reuse_attempt", outcome_blocked=True)
    )
    proof = determine_recovery_proof(assurance_report, re_attack_result)

    assert proof.status == RecoveryProofStatus.PROVEN


def test_full_pipeline_failed_when_re_attack_succeeds_despite_passing_invariants():
    incident = build_incident()
    investigation = run_investigation(incident)
    plan = run_planning(investigation)
    run_orchestration(plan)
    assurance_report = run_assurance_check(incident)

    re_attack_result = run_re_attack(
        MockReAttackScenario(incident.incident_id, "credential_reuse_attempt", outcome_blocked=False)
    )
    proof = determine_recovery_proof(assurance_report, re_attack_result)

    assert proof.status == RecoveryProofStatus.FAILED
    assert "still succeeded" in proof.rationale
