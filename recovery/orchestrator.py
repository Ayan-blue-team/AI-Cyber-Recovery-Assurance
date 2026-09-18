"""
Recovery Orchestrator (Section 9).

Responsibility: take a RecoveryPlan produced by the AI Recovery Planner and
turn it into audited, authorized execution — nothing more, nothing less.

Design rules this module must respect (Sections 5, 9, 24, 25):
    - This is the ONLY component in the pipeline allowed to actually change
      anything in the environment. The AI never executes directly.
    - Every action with requires_approval=True MUST go through the
      ApprovalProvider before execution, no exceptions and no bypass flag.
    - Every action — approved or not, executed or not, succeeded or failed —
      produces an ExecutionResult and is appended to the audit trail. A
      rejected or failed action is not silently dropped.
    - Execution itself is delegated to an ActionExecutor. Today that's a
      MockActionExecutor (no lab environment yet); later it becomes a real
      PowerShell/Bash/API executor. The orchestrator's logic does not change
      when that swap happens — that's the whole point of the Protocol.
    - Rollback is best-effort and explicit: if an executor doesn't support
      rolling back a given action, that must be visible, not hidden.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Optional, Protocol

from ai_engine.schemas import ExecutionResult, RecoveryAction, RecoveryPlan


class ApprovalProvider(Protocol):
    """Decides whether a given action is approved for execution.

    Kept as a Protocol so tests (and early automation) can inject an
    auto-approve/auto-deny stub, while a real deployment can later plug in
    a CLI prompt, a Slack approval workflow, a ticketing system, etc.
    """

    def request_approval(self, action: RecoveryAction) -> bool:
        ...


class AutoApprovalProvider:
    """Approves or denies every action the same way, no human involved.

    Useful for: unit tests, and for automatically running actions that
    were already marked requires_approval=False by the planner's
    deterministic policy table. NEVER use approve_all=True in a real
    deployment for anything requires_approval=True — it defeats the
    entire point of Section 5's human-in-the-loop boundary.
    """

    def __init__(self, approve_all: bool = False):
        self._approve_all = approve_all

    def request_approval(self, action: RecoveryAction) -> bool:
        return self._approve_all


class CLIApprovalProvider:
    """Prompts a human on the terminal for each action requiring approval.

    This is the minimal real ApprovalProvider for a single-developer lab
    setup — good enough until a proper approval UI/workflow exists.
    """

    def request_approval(self, action: RecoveryAction) -> bool:
        prompt = (
            f"\nAPPROVAL REQUIRED\n"
            f"  action: {action.action}\n"
            f"  target: {action.target}\n"
            f"  reason: {action.reason}\n"
            f"  risk:   {action.risk.value}\n"
            f"Approve? [y/N]: "
        )
        answer = input(prompt).strip().lower()
        return answer == "y"


class ActionExecutor(Protocol):
    """Actually performs a recovery action against the environment."""

    def execute(self, action: RecoveryAction) -> dict:
        """Run the action. Return an evidence dict on success.

        Raise ExecutionError on failure — the orchestrator distinguishes
        "failed" from "succeeded" only through this exception, never by
        inspecting free-text output.
        """
        ...

    def supports_rollback(self, action: RecoveryAction) -> bool:
        ...

    def rollback(self, action: RecoveryAction) -> dict:
        ...


class ExecutionError(Exception):
    """Raised by an ActionExecutor when an action fails to execute."""


class MockActionExecutor:
    """Simulates execution without touching any real system.

    This exists because the lab environment (Phase 03-06) is not built
    yet. It lets us build and test the orchestrator's control flow —
    approval gating, audit trail, error handling — today, without lying
    about what actually happened: every evidence dict is explicitly
    tagged "simulated": true so nobody mistakes this for a real result.
    """

    def execute(self, action: RecoveryAction) -> dict:
        return {
            "simulated": True,
            "note": f"MockActionExecutor pretended to run '{action.action}' on '{action.target}'",
        }

    def supports_rollback(self, action: RecoveryAction) -> bool:
        return True

    def rollback(self, action: RecoveryAction) -> dict:
        return {
            "simulated": True,
            "note": f"MockActionExecutor pretended to roll back '{action.action}' on '{action.target}'",
        }


def _new_action_id() -> str:
    return f"ACT-{uuid.uuid4().hex[:8].upper()}"


def _append_audit_record(path: Path, result: ExecutionResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(result.model_dump_json() + "\n")


def execute_plan(
    plan: RecoveryPlan,
    executor: Optional[ActionExecutor] = None,
    approval_provider: Optional[ApprovalProvider] = None,
    audit_log_path: Optional[Path] = None,
) -> list[ExecutionResult]:
    """Execute every action in a RecoveryPlan, gated by approval, and audited.

    Args:
        plan: the structured plan from ai_engine.recovery_planner.
        executor: how actions are actually carried out. Defaults to
            MockActionExecutor (safe: no lab environment required).
        approval_provider: how requires_approval actions get a yes/no.
            Defaults to AutoApprovalProvider(approve_all=False), i.e. every
            action requiring approval is DENIED unless a real provider is
            supplied — fail safe, never fail open.
        audit_log_path: if given, every ExecutionResult (approved or not,
            executed or not) is appended as a JSON line to this file.

    Returns:
        One ExecutionResult per action in the plan, in order.
    """
    executor = executor or MockActionExecutor()
    approval_provider = approval_provider or AutoApprovalProvider(approve_all=False)

    results: list[ExecutionResult] = []

    for action in plan.actions:
        action_id = action.action_id or _new_action_id()

        approved = True
        if action.requires_approval:
            approved = approval_provider.request_approval(action)

        if not approved:
            result = ExecutionResult(
                action_id=action_id,
                action=action.action,
                target=action.target,
                approved=False,
                executed=False,
                result="rejected",
            )
            results.append(result)
            if audit_log_path:
                _append_audit_record(audit_log_path, result)
            continue

        try:
            evidence = executor.execute(action)
            result = ExecutionResult(
                action_id=action_id,
                action=action.action,
                target=action.target,
                approved=True,
                executed=True,
                result="success",
                evidence=evidence,
            )
        except ExecutionError as exc:
            result = ExecutionResult(
                action_id=action_id,
                action=action.action,
                target=action.target,
                approved=True,
                executed=False,
                result="failed",
                evidence={"error": str(exc)},
            )

        results.append(result)
        if audit_log_path:
            _append_audit_record(audit_log_path, result)

    return results
