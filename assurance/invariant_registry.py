"""
Invariant registry — maps a string name (as written in a scenario YAML
file) to the actual Invariant class in assurance/engine.py, and builds an
instance from a parameter dict.

This is the piece that lets experiments/run_scenario.py stay generic: a
new scenario does not require new Python code to reference an *existing*
invariant type — it just names it and supplies parameters in YAML. A
scenario that needs a genuinely new kind of check still requires a new
Invariant class in assurance/engine.py (and a registry entry here) — this
registry does not let you invent checks purely in YAML, which is
intentional: the check logic itself must stay in reviewed, tested code.
"""

from __future__ import annotations

from typing import Any, Callable

from assurance.engine import (
    AccountDisabledInvariant,
    EndpointSecurityActiveInvariant,
    FirewallRuleAbsentInvariant,
    Invariant,
    ProcessTerminatedInvariant,
    ScheduledTaskAbsentInvariant,
)


class UnknownInvariantError(Exception):
    """Raised when a scenario file names an invariant this registry doesn't recognize."""


# Each entry: invariant name (as used in YAML) -> a function building the
# invariant from its YAML `params` dict. Keeping this explicit (rather
# than e.g. **kwargs passthrough via getattr) means a typo'd or
# unsupported param name fails loudly at registration time, not silently.
_REGISTRY: dict[str, Callable[[dict[str, Any]], Invariant]] = {
    "AccountDisabledInvariant": lambda p: AccountDisabledInvariant(account=p["account"]),
    "ScheduledTaskAbsentInvariant": lambda p: ScheduledTaskAbsentInvariant(
        host=p["host"], task_name=p["task_name"]
    ),
    "ProcessTerminatedInvariant": lambda p: ProcessTerminatedInvariant(
        host=p["host"], process_identifier=p["process_identifier"]
    ),
    "FirewallRuleAbsentInvariant": lambda p: FirewallRuleAbsentInvariant(
        host=p["host"], rule_name=p["rule_name"]
    ),
    "EndpointSecurityActiveInvariant": lambda p: EndpointSecurityActiveInvariant(host=p["host"]),
}


def build_invariant(name: str, params: dict[str, Any]) -> Invariant:
    """Build an Invariant instance from its registry name and YAML params.

    Raises:
        UnknownInvariantError: if `name` isn't registered.
        KeyError: if `params` is missing a field the invariant requires
            (e.g. ScheduledTaskAbsentInvariant without "task_name") — this
            is intentionally not caught and reworded, so the exact missing
            key is visible to whoever is debugging the scenario file.
    """
    builder = _REGISTRY.get(name)
    if builder is None:
        raise UnknownInvariantError(
            f"No invariant registered under the name '{name}'. "
            f"Known invariants: {sorted(_REGISTRY)}"
        )
    return builder(params)


def registered_invariant_names() -> list[str]:
    return sorted(_REGISTRY)
