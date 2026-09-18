"""
Unit tests for ai_engine.recovery_planner.

Key thing under test: the deterministic policy override. The LLM never gets
to decide risk/requires_approval — we verify that no matter what a (fake)
model returns, known actions get their table-defined risk/approval, and
unknown actions are forced into the fail-safe HIGH/requires_approval=True
posture.
"""

import json

import pytest

from ai_engine.recovery_planner import plan_recovery
from ai_engine.schemas import InvestigationResult, RiskLevel, Severity


class FakeLLMClient:
    def __init__(self, response: str):
        self._response = response

    def complete(self, system: str, user: str) -> str:
        return self._response


def make_investigation() -> InvestigationResult:
    return InvestigationResult(
        incident_id="INC-001",
        severity=Severity.HIGH,
        findings=[],
        root_cause="Compromised credential used for lateral movement",
        affected_assets=["WIN-01"],
        recommended_recovery=["disable_account"],
    )


def test_known_action_gets_deterministic_risk_and_approval():
    response = json.dumps(
        {
            "actions": [
                {
                    "action": "disable_account",
                    "target": "user123",
                    "reason": "Compromised credential",
                }
            ]
        }
    )
    plan = plan_recovery(make_investigation(), client=FakeLLMClient(response))

    assert len(plan.actions) == 1
    action = plan.actions[0]
    assert action.risk == RiskLevel.MEDIUM
    assert action.requires_approval is True


def test_unknown_action_is_forced_high_risk_and_requires_approval():
    # Simulates a model proposing an action name we don't recognize.
    response = json.dumps(
        {
            "actions": [
                {
                    "action": "wipe_entire_disk",
                    "target": "WIN-01",
                    "reason": "just to be safe",
                }
            ]
        }
    )
    plan = plan_recovery(make_investigation(), client=FakeLLMClient(response))

    action = plan.actions[0]
    assert action.risk == RiskLevel.HIGH
    assert action.requires_approval is True


def test_low_risk_known_action_does_not_require_approval():
    response = json.dumps(
        {
            "actions": [
                {
                    "action": "terminate_process",
                    "target": "powershell.exe (PID 4821)",
                    "reason": "Malicious encoded command execution",
                }
            ]
        }
    )
    plan = plan_recovery(make_investigation(), client=FakeLLMClient(response))

    action = plan.actions[0]
    assert action.risk == RiskLevel.LOW
    assert action.requires_approval is False


def test_missing_field_raises_value_error():
    response = json.dumps({"actions": [{"action": "disable_account"}]})  # missing target/reason
    with pytest.raises(ValueError, match="missing required field"):
        plan_recovery(make_investigation(), client=FakeLLMClient(response))


def test_non_json_output_raises_value_error():
    with pytest.raises(ValueError, match="non-JSON"):
        plan_recovery(make_investigation(), client=FakeLLMClient("sure, I'll disable the account"))


def test_missing_actions_key_raises_value_error():
    with pytest.raises(ValueError, match="missing 'actions' list"):
        plan_recovery(make_investigation(), client=FakeLLMClient(json.dumps({"foo": "bar"})))
