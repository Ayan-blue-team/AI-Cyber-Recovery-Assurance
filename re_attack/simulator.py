"""
Controlled Re-Attack Simulator (Section 13).

Responsibility: replay the relevant portion of the original attack TTP
against the recovered environment and report whether it was blocked.

Design rules this module must respect (Sections 13, 23, 24):
    - Re-attacks must be isolated, authorized, non-destructive, and
      scenario-specific — never generic offensive tooling.
    - This module defines the *shape* of a re-attack (the ReAttackScenario
      protocol) and a MockReAttackScenario for use before the Kali lab
      (Phase 03/06) exists. Real scenarios (re_attack/scenarios/) will
      implement the same protocol against the real lab later, without
      requiring any change to code that consumes ReAttackResult.
    - A scenario's `blocked` result must come from an actual observed
      outcome (e.g. "authentication attempt returned 401", "payload did
      not execute"), never from an assumption. The mock scenario is
      labelled as simulated for the same reason MockActionExecutor is —
      so a simulated result is never mistaken for a real one.
"""

from __future__ import annotations

from typing import Protocol

from ai_engine.schemas import ReAttackResult


class ReAttackScenario(Protocol):
    """A single controlled re-attack scenario tied to one recovery action."""

    name: str

    def run(self) -> ReAttackResult:
        """Execute the scenario and return whether the attack was blocked."""
        ...


class MockReAttackScenario:
    """Simulates a re-attack outcome without any real lab environment.

    `outcome_blocked` is supplied explicitly by the caller (e.g. a test, or
    an experiment script exploring both outcomes) rather than computed —
    this module has no way to actually know the answer without a real
    attacker tool and target, so it never pretends to.
    """

    def __init__(self, incident_id: str, scenario_name: str, outcome_blocked: bool):
        self.incident_id = incident_id
        self.name = scenario_name
        self._outcome_blocked = outcome_blocked

    def run(self) -> ReAttackResult:
        return ReAttackResult(
            incident_id=self.incident_id,
            scenario=self.name,
            blocked=self._outcome_blocked,
            evidence={
                "simulated": True,
                "note": f"MockReAttackScenario pretended to replay '{self.name}'",
            },
        )


def run_re_attack(scenario: ReAttackScenario) -> ReAttackResult:
    """Run a single re-attack scenario and return its result.

    Thin wrapper today; kept as a function (rather than inlining
    `scenario.run()` everywhere) so later we can add cross-cutting
    concerns here — timeouts, retries, logging — without touching every
    call site.
    """
    return scenario.run()
