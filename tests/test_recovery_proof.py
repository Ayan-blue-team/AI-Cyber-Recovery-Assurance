"""
Unit tests for re_attack.validator.determine_recovery_proof.

Each test corresponds directly to one of the five numbered rules in the
module docstring, so this file doubles as executable documentation of the
Recovery Proof decision logic (Section 14).
"""

from ai_engine.schemas import (
    AssuranceReport,
    InvariantResult,
    InvariantStatus,
    ReAttackResult,
    RecoveryProofStatus,
)
from re_attack.validator import determine_recovery_proof


def make_report(*statuses: InvariantStatus) -> AssuranceReport:
    results = [
        InvariantResult(invariant=f"invariant_{i}", status=status)
        for i, status in enumerate(statuses)
    ]
    return AssuranceReport(incident_id="INC-001", invariant_results=results)


def test_rule1_any_fail_wins_over_unknown():
    # Mix of FAIL and UNKNOWN -> FAILED must win, per priority order.
    report = make_report(InvariantStatus.FAIL, InvariantStatus.UNKNOWN, InvariantStatus.PASS)
    proof = determine_recovery_proof(report)

    assert proof.status == RecoveryProofStatus.FAILED
    assert "invariant_0" in proof.rationale


def test_rule2_unknown_when_no_fail_but_incomplete_evidence():
    report = make_report(InvariantStatus.PASS, InvariantStatus.UNKNOWN)
    proof = determine_recovery_proof(report)

    assert proof.status == RecoveryProofStatus.UNKNOWN
    assert "invariant_1" in proof.rationale


def test_rule3_partially_proven_when_all_pass_but_no_re_attack_yet():
    report = make_report(InvariantStatus.PASS, InvariantStatus.PASS)
    proof = determine_recovery_proof(report, re_attack_result=None)

    assert proof.status == RecoveryProofStatus.PARTIALLY_PROVEN


def test_rule4_proven_when_all_pass_and_re_attack_blocked():
    report = make_report(InvariantStatus.PASS, InvariantStatus.PASS)
    re_attack = ReAttackResult(incident_id="INC-001", scenario="cred_reuse", blocked=True)
    proof = determine_recovery_proof(report, re_attack_result=re_attack)

    assert proof.status == RecoveryProofStatus.PROVEN


def test_rule5_failed_when_all_pass_but_re_attack_succeeds():
    # The core thesis of the whole project: passing invariants alone can lie.
    report = make_report(InvariantStatus.PASS, InvariantStatus.PASS)
    re_attack = ReAttackResult(incident_id="INC-001", scenario="cred_reuse", blocked=False)
    proof = determine_recovery_proof(report, re_attack_result=re_attack)

    assert proof.status == RecoveryProofStatus.FAILED
    assert "still succeeded" in proof.rationale
