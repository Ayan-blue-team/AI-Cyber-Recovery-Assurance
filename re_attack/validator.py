"""
Recovery Proof decision logic (Section 14).

Responsibility: combine an AssuranceReport (deterministic invariant checks)
and an optional ReAttackResult (controlled re-attack outcome) into a single
final verdict: PROVEN, PARTIALLY_PROVEN, FAILED, or UNKNOWN.

Section 14 gives the conceptual logic but explicitly requires the exact
decision rules to be defined and tested during implementation. The rules
implemented here, in priority order:

    1. Any invariant FAIL  -> FAILED
       A definitive, evidenced violation is the strongest possible signal.
       It must win over UNKNOWN elsewhere: "some things are broken" is a
       worse (and more certain) situation than "some things are unclear".

    2. No FAIL, but any invariant UNKNOWN -> UNKNOWN
       We refuse to call recovery proven when evidence is incomplete, per
       the Assurance Engine's core rule (Section 10): missing evidence is
       never silently upgraded to a pass.

    3. All invariants PASS, no re-attack has been run yet -> PARTIALLY_PROVEN
       Static/state checks passed, but the central claim of this whole
       project — that recovery survives a live attempt to reproduce the
       original failure — has not yet been tested.

    4. All invariants PASS, re-attack BLOCKED -> PROVEN
       This is the target end state: independent state verification AND
       live re-validation both succeeded.

    5. All invariants PASS, re-attack SUCCEEDED (not blocked) -> FAILED
       This is the exact failure mode the whole project exists to catch:
       every deterministic check looked fine, yet the original compromise
       is still reproducible. Invariant coverage was insufficient; recovery
       is not actually proven, regardless of what the checks said.
"""

from __future__ import annotations

from typing import Optional

from ai_engine.schemas import AssuranceReport, ReAttackResult, RecoveryProof, RecoveryProofStatus


def determine_recovery_proof(
    assurance_report: AssuranceReport,
    re_attack_result: Optional[ReAttackResult] = None,
) -> RecoveryProof:
    """Apply the Section 14 decision rules and produce a RecoveryProof.

    Args:
        assurance_report: result of assurance.engine.run_assurance.
        re_attack_result: result of re_attack.simulator.run_re_attack, or
            None if re-attack validation has not been performed yet.

    Returns:
        A RecoveryProof with an explicit status and human-readable rationale.
    """
    if assurance_report.any_fail:
        failed = [
            r.invariant for r in assurance_report.invariant_results if r.status.value == "FAIL"
        ]
        return RecoveryProof(
            incident_id=assurance_report.incident_id,
            status=RecoveryProofStatus.FAILED,
            assurance_report=assurance_report,
            re_attack_result=re_attack_result,
            rationale=f"Invariant(s) failed: {', '.join(failed)}.",
        )

    if assurance_report.any_unknown:
        unknown = [
            r.invariant for r in assurance_report.invariant_results if r.status.value == "UNKNOWN"
        ]
        return RecoveryProof(
            incident_id=assurance_report.incident_id,
            status=RecoveryProofStatus.UNKNOWN,
            assurance_report=assurance_report,
            re_attack_result=re_attack_result,
            rationale=f"Insufficient evidence for invariant(s): {', '.join(unknown)}.",
        )

    # All invariants PASS at this point.
    if re_attack_result is None:
        return RecoveryProof(
            incident_id=assurance_report.incident_id,
            status=RecoveryProofStatus.PARTIALLY_PROVEN,
            assurance_report=assurance_report,
            re_attack_result=None,
            rationale="All invariants passed, but controlled re-attack validation has not been performed yet.",
        )

    if re_attack_result.blocked:
        return RecoveryProof(
            incident_id=assurance_report.incident_id,
            status=RecoveryProofStatus.PROVEN,
            assurance_report=assurance_report,
            re_attack_result=re_attack_result,
            rationale=(
                f"All invariants passed and the controlled re-attack "
                f"('{re_attack_result.scenario}') was blocked."
            ),
        )

    return RecoveryProof(
        incident_id=assurance_report.incident_id,
        status=RecoveryProofStatus.FAILED,
        assurance_report=assurance_report,
        re_attack_result=re_attack_result,
        rationale=(
            f"All invariants passed, but the controlled re-attack "
            f"('{re_attack_result.scenario}') still succeeded — the original "
            f"security failure remains reproducible despite passing checks."
        ),
    )
