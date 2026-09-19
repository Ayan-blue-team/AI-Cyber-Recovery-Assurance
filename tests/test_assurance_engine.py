"""
Unit tests for assurance.engine.

Key thing under test: missing evidence must produce UNKNOWN, never PASS.
Every invariant is tested for all three outcomes (PASS, FAIL, UNKNOWN)
using MockEvidenceProvider, which defaults to "no evidence configured".
"""

from ai_engine.schemas import InvariantStatus
from assurance.engine import (
    AccountDisabledInvariant,
    EndpointSecurityActiveInvariant,
    FirewallRuleAbsentInvariant,
    MockEvidenceProvider,
    ProcessTerminatedInvariant,
    ScheduledTaskAbsentInvariant,
    run_assurance,
)


def test_account_disabled_invariant_unknown_when_no_evidence():
    evidence = MockEvidenceProvider()
    result = AccountDisabledInvariant("user123").check(evidence)
    assert result.status == InvariantStatus.UNKNOWN


def test_account_disabled_invariant_pass_when_disabled():
    evidence = MockEvidenceProvider()
    evidence.set_account_enabled("user123", False)
    result = AccountDisabledInvariant("user123").check(evidence)
    assert result.status == InvariantStatus.PASS


def test_account_disabled_invariant_fail_when_still_enabled():
    evidence = MockEvidenceProvider()
    evidence.set_account_enabled("user123", True)
    result = AccountDisabledInvariant("user123").check(evidence)
    assert result.status == InvariantStatus.FAIL


def test_scheduled_task_absent_invariant_all_three_outcomes():
    evidence = MockEvidenceProvider()

    # No evidence configured -> UNKNOWN
    inv = ScheduledTaskAbsentInvariant("WIN-01", "EvilTask")
    assert inv.check(evidence).status == InvariantStatus.UNKNOWN

    # Task list retrieved, malicious task still present -> FAIL
    evidence.set_scheduled_tasks("WIN-01", ["EvilTask", "WindowsUpdate"])
    assert inv.check(evidence).status == InvariantStatus.FAIL

    # Task list retrieved, malicious task gone -> PASS
    evidence.set_scheduled_tasks("WIN-01", ["WindowsUpdate"])
    assert inv.check(evidence).status == InvariantStatus.PASS


def test_process_terminated_invariant_all_three_outcomes():
    evidence = MockEvidenceProvider()
    inv = ProcessTerminatedInvariant("WIN-01", "malicious.exe")

    assert inv.check(evidence).status == InvariantStatus.UNKNOWN

    evidence.set_running_processes("WIN-01", ["malicious.exe", "explorer.exe"])
    assert inv.check(evidence).status == InvariantStatus.FAIL

    evidence.set_running_processes("WIN-01", ["explorer.exe"])
    assert inv.check(evidence).status == InvariantStatus.PASS


def test_firewall_rule_absent_invariant_all_three_outcomes():
    evidence = MockEvidenceProvider()
    inv = FirewallRuleAbsentInvariant("WIN-01", "AllowBackdoor4444")

    assert inv.check(evidence).status == InvariantStatus.UNKNOWN

    evidence.set_firewall_rules("WIN-01", ["AllowBackdoor4444", "DefaultInbound"])
    assert inv.check(evidence).status == InvariantStatus.FAIL

    evidence.set_firewall_rules("WIN-01", ["DefaultInbound"])
    assert inv.check(evidence).status == InvariantStatus.PASS


def test_endpoint_security_active_invariant_all_three_outcomes():
    evidence = MockEvidenceProvider()
    inv = EndpointSecurityActiveInvariant("WIN-01")

    assert inv.check(evidence).status == InvariantStatus.UNKNOWN

    evidence.set_security_agent_status("WIN-01", "stopped")
    assert inv.check(evidence).status == InvariantStatus.FAIL

    evidence.set_security_agent_status("WIN-01", "running")
    assert inv.check(evidence).status == InvariantStatus.PASS


def test_run_assurance_aggregates_and_flags_any_fail():
    evidence = MockEvidenceProvider()
    evidence.set_account_enabled("user123", False)  # PASS
    evidence.set_running_processes("WIN-01", ["malicious.exe"])  # FAIL (still running)

    report = run_assurance(
        incident_id="INC-001",
        invariants=[
            AccountDisabledInvariant("user123"),
            ProcessTerminatedInvariant("WIN-01", "malicious.exe"),
        ],
        evidence=evidence,
    )

    assert len(report.invariant_results) == 2
    assert report.any_fail is True
    assert report.any_unknown is False


def test_run_assurance_flags_any_unknown_when_evidence_missing():
    evidence = MockEvidenceProvider()  # nothing configured at all

    report = run_assurance(
        incident_id="INC-001",
        invariants=[AccountDisabledInvariant("user123")],
        evidence=evidence,
    )

    assert report.any_unknown is True
    assert report.any_fail is False
