"""
Unit tests for recovery.orchestrator.

Key things under test:
    1. Fail-safe default: an action requiring approval is REJECTED unless a
       real approval provider says yes. No approval provider = no execution.
    2. A denied action still produces an ExecutionResult (never silently
       dropped) with executed=False.
    3. Executor failures are captured as result="failed", not exceptions
       bubbling out of the orchestrator.
    4. The audit trail file gets one JSON line per action, matching what
       was returned.
"""

import json

from ai_engine.schemas import RecoveryAction, RecoveryPlan, RiskLevel
from recovery.orchestrator import (
    AutoApprovalProvider,
    ExecutionError,
    MockActionExecutor,
    execute_plan,
)


def make_plan(*actions: RecoveryAction) -> RecoveryPlan:
    return RecoveryPlan(incident_id="INC-001", actions=list(actions))


def low_risk_action() -> RecoveryAction:
    return RecoveryAction(
        action="terminate_process",
        target="powershell.exe (PID 4821)",
        reason="Malicious encoded command execution",
        risk=RiskLevel.LOW,
        requires_approval=False,
    )


def high_risk_action() -> RecoveryAction:
    return RecoveryAction(
        action="isolate_endpoint",
        target="WIN-01",
        reason="Active lateral movement observed",
        risk=RiskLevel.HIGH,
        requires_approval=True,
    )


def test_action_not_requiring_approval_executes_by_default():
    plan = make_plan(low_risk_action())
    results = execute_plan(plan)

    assert len(results) == 1
    assert results[0].approved is True
    assert results[0].executed is True
    assert results[0].result == "success"
    assert results[0].evidence["simulated"] is True


def test_action_requiring_approval_is_rejected_by_default_provider():
    # No approval_provider passed in -> defaults to AutoApprovalProvider(False)
    # -> fail safe: nothing requiring approval runs without an explicit yes.
    plan = make_plan(high_risk_action())
    results = execute_plan(plan)

    assert results[0].approved is False
    assert results[0].executed is False
    assert results[0].result == "rejected"


def test_action_requiring_approval_executes_when_approved():
    plan = make_plan(high_risk_action())
    results = execute_plan(plan, approval_provider=AutoApprovalProvider(approve_all=True))

    assert results[0].approved is True
    assert results[0].executed is True
    assert results[0].result == "success"


class FailingExecutor:
    def execute(self, action):
        raise ExecutionError("simulated failure: endpoint unreachable")

    def supports_rollback(self, action):
        return False

    def rollback(self, action):
        raise NotImplementedError


def test_executor_failure_is_captured_not_raised():
    plan = make_plan(low_risk_action())
    results = execute_plan(plan, executor=FailingExecutor())

    assert results[0].approved is True
    assert results[0].executed is False
    assert results[0].result == "failed"
    assert "endpoint unreachable" in results[0].evidence["error"]


def test_audit_trail_written_to_file(tmp_path):
    audit_path = tmp_path / "audit" / "log.jsonl"
    plan = make_plan(low_risk_action(), high_risk_action())

    results = execute_plan(
        plan,
        approval_provider=AutoApprovalProvider(approve_all=True),
        audit_log_path=audit_path,
    )

    assert audit_path.exists()
    lines = audit_path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2

    logged = [json.loads(line) for line in lines]
    assert logged[0]["action"] == "terminate_process"
    assert logged[1]["action"] == "isolate_endpoint"
    assert all(entry["executed"] for entry in logged)
    # Make sure what's on disk matches what was returned to the caller.
    assert logged[0]["action_id"] == results[0].action_id
