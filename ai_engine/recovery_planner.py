"""
AI Recovery Planner (Section 8).

Responsibility: convert an InvestigationResult into a structured
RecoveryPlan (a list of RecoveryAction objects), explicit and auditable.

Design rules this module must respect (Sections 5, 8, 24, 25):
    - The LLM proposes *which* actions and *why* (reason), but it does not
      get the final say on risk/approval for known action types. A
      deterministic lookup table (KNOWN_ACTIONS) overrides the model's
      risk/approval fields whenever the action is recognized, so the LLM
      cannot understate the risk of a dangerous operation.
    - Any action the model proposes that is NOT in the known-actions table
      is treated as unrecognized and is forced to requires_approval=True
      with risk=HIGH — fail safe rather than fail open.
    - This module never executes anything. It only produces a plan; the
      Recovery Orchestrator (Section 9) is the only component with
      execution capability, and it re-checks policy independently anyway.
"""

from __future__ import annotations

import json
from typing import Optional

from pydantic import ValidationError

from ai_engine.investigation import LLMClient, AnthropicLLMClient
from ai_engine.schemas import InvestigationResult, RecoveryAction, RecoveryPlan, RiskLevel

# Deterministic policy defaults for recognized action types.
# (action_name -> (default_risk, requires_approval))
# This table is the single source of truth for how dangerous we consider
# each action to be, independent of anything the LLM says.
KNOWN_ACTIONS: dict[str, tuple[RiskLevel, bool]] = {
    "disable_account": (RiskLevel.MEDIUM, True),
    "rotate_credentials": (RiskLevel.MEDIUM, True),
    "terminate_process": (RiskLevel.LOW, False),
    "remove_scheduled_task": (RiskLevel.MEDIUM, True),
    "remove_persistence": (RiskLevel.MEDIUM, True),
    "restore_firewall_configuration": (RiskLevel.MEDIUM, True),
    "isolate_endpoint": (RiskLevel.HIGH, True),
    "remove_unauthorized_account": (RiskLevel.HIGH, True),
    "restore_security_agent": (RiskLevel.LOW, False),
    "patch_vulnerability": (RiskLevel.MEDIUM, True),
    "remove_malicious_artifact": (RiskLevel.LOW, False),
    "restore_verified_backup": (RiskLevel.HIGH, True),
}

# Fail-safe default applied to any action the planner proposes that we do
# not recognize. Unknown = treat as dangerous until a human says otherwise.
UNKNOWN_ACTION_DEFAULT: tuple[RiskLevel, bool] = (RiskLevel.HIGH, True)

SYSTEM_PROMPT = """\
You are a recovery-planning assistant for a security incident response \
system. Given a structured investigation result, propose concrete recovery \
actions as a STRICT JSON object matching this schema:

{
  "actions": [
    {"action": string, "target": string, "reason": string}
  ]
}

Rules:
- Prefer these known action names when applicable: disable_account,
  rotate_credentials, terminate_process, remove_scheduled_task,
  remove_persistence, restore_firewall_configuration, isolate_endpoint,
  remove_unauthorized_account, restore_security_agent, patch_vulnerability,
  remove_malicious_artifact, restore_verified_backup.
- "target" must reference an asset, user, or host that actually appears in
  the investigation result (affected_assets, or the incident's user/host).
  Do not invent targets that were not mentioned.
- "reason" should briefly cite the finding or root cause that justifies
  the action.
- Do not include risk levels or approval flags — those are assigned by a
  separate deterministic policy step, not by you.
- Return ONLY the JSON object. No prose, no markdown fences.
"""


def _build_user_message(investigation: InvestigationResult) -> str:
    payload = json.loads(investigation.model_dump_json())
    return (
        "Propose recovery actions for the following investigation result. "
        "Respond with the JSON object described in the system prompt only.\n\n"
        f"{json.dumps(payload, indent=2)}"
    )


def _apply_policy_defaults(action_name: str) -> tuple[RiskLevel, bool]:
    """Deterministically assign risk/approval for an action name.

    This is the safety net referenced in the module docstring: the LLM's
    opinion on risk is never consulted, so it cannot talk its way into a
    lower approval bar for a dangerous action.
    """
    return KNOWN_ACTIONS.get(action_name, UNKNOWN_ACTION_DEFAULT)


def plan_recovery(
    investigation: InvestigationResult,
    client: Optional[LLMClient] = None,
) -> RecoveryPlan:
    """Produce a RecoveryPlan from an InvestigationResult.

    Args:
        investigation: validated output of the investigation engine.
        client: an LLMClient implementation (see ai_engine.investigation).
            Defaults to AnthropicLLMClient. Injectable for testing.

    Returns:
        A validated RecoveryPlan with deterministic risk/approval fields.

    Raises:
        ValueError: on non-JSON output or schema violations. Same
            fail-loud philosophy as the investigation engine — a bad plan
            must be visible, never silently accepted.
    """
    client = client or AnthropicLLMClient()
    user_message = _build_user_message(investigation)
    raw_output = client.complete(system=SYSTEM_PROMPT, user=user_message)

    try:
        parsed = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Recovery planner returned non-JSON output: {raw_output!r}") from exc

    raw_actions = parsed.get("actions")
    if not isinstance(raw_actions, list):
        raise ValueError(f"Recovery planner output missing 'actions' list: {parsed!r}")

    actions: list[RecoveryAction] = []
    for raw_action in raw_actions:
        try:
            action_name = raw_action["action"]
            target = raw_action["target"]
            reason = raw_action["reason"]
        except KeyError as exc:
            raise ValueError(f"Recovery action missing required field: {raw_action!r}") from exc

        risk, requires_approval = _apply_policy_defaults(action_name)

        try:
            actions.append(
                RecoveryAction(
                    action=action_name,
                    target=target,
                    reason=reason,
                    risk=risk,
                    requires_approval=requires_approval,
                )
            )
        except ValidationError as exc:
            raise ValueError(f"Recovery action failed schema validation: {exc}") from exc

    return RecoveryPlan(incident_id=investigation.incident_id, actions=actions)
