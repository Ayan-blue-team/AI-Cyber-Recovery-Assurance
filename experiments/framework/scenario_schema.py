"""
Scenario schema — the structure every scenario YAML file must follow.

A new scenario (Persistence, Privilege Abuse, etc.) is, in the common
case, just a new YAML file conforming to this schema, plus — only if it
needs a security check or recovery action type that doesn't exist yet —
a small addition to assurance/invariant_registry.py or
recovery/executors/winrm_executor.py's ACTION_COMMANDS.

This schema deliberately does NOT include a field for "how to simulate
the attack precondition" as something the runner executes automatically.
Setting up the attacker's starting artifact (e.g. actually creating the
malicious scheduled task, dropping the test file) is treated as a
controlled, reviewed, scenario-specific setup step the operator runs
themselves before invoking the runner — matching this project's
requirement (Section 23) that offensive setup stays deliberate and
reviewed, not auto-generated from a config file.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

from ai_engine.schemas import Severity


class IncidentSpec(BaseModel):
    incident_id: str
    source: str = "manual_trigger"
    severity: Severity
    host: str
    user: Optional[str] = None
    alert: str
    telemetry_note: Optional[str] = Field(
        default=None,
        description="Extra context passed to the AI investigation step as telemetry.",
    )


class InvariantSpec(BaseModel):
    """One assurance check to run, by name (see assurance/invariant_registry.py)."""

    name: str
    params: dict = Field(default_factory=dict)


class ReAttackSpec(BaseModel):
    """How to verify, after recovery, whether the original failure still reproduces."""

    scenario_name: str
    executor: Literal["winrm", "ssh"]
    host_ref: Literal["win01", "kali"] = Field(
        description="Which configured host (see experiments/framework/host_config.py) to run the command on."
    )
    command: str
    success_markers: list[str] = Field(
        description="Substrings in the command output that mean the attack STILL succeeded (blocked=False)."
    )
    failure_markers: list[str] = Field(
        description="Substrings in the command output that mean the attack was BLOCKED (blocked=True)."
    )


class ScenarioSpec(BaseModel):
    """Full definition of one scenario, as loaded from a YAML file."""

    name: str
    description: str
    incident: IncidentSpec
    assurance: list[InvariantSpec]
    re_attack: ReAttackSpec
