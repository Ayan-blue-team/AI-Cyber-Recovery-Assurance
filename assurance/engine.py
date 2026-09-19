"""
Security Assurance Engine (Sections 10-11).

Responsibility: independently verify, through deterministic checks, whether
specific security invariants hold after recovery. This engine NEVER asks an
LLM whether the environment is secure — every invariant here is a plain
Python check against evidence pulled from the environment (AD, Sysmon,
firewall, EDR, etc).

Design rules this module must respect (Sections 10, 24):
    - PASS requires positive, present evidence that the condition holds.
    - FAIL requires positive, present evidence that the condition is violated.
    - UNKNOWN is the result whenever evidence is missing, partial, or the
      evidence source itself is unreachable. UNKNOWN must never be silently
      upgraded to PASS by this engine or by any caller.
    - Each invariant is small, single-purpose, and independently testable.
    - Evidence access goes through the EvidenceProvider protocol, so a
      MockEvidenceProvider (used now, before the lab exists) can later be
      swapped for a real one (Wazuh/AD/Sysmon-backed) without changing any
      invariant's logic.
"""

from __future__ import annotations

from typing import Optional, Protocol

from ai_engine.schemas import AssuranceReport, InvariantResult, InvariantStatus


class EvidenceProvider(Protocol):
    """Source of truth for invariant checks.

    Every method returns None when the evidence is unavailable (source
    unreachable, query failed, nothing collected yet) rather than raising
    or guessing — invariants treat None as "insufficient evidence" and
    report UNKNOWN, per Section 10.
    """

    def get_account_enabled(self, account: str) -> Optional[bool]:
        """True if the account is currently enabled, False if disabled, None if unknown."""
        ...

    def get_scheduled_tasks(self, host: str) -> Optional[list[str]]:
        """List of scheduled task names present on the host, or None if unavailable."""
        ...

    def get_running_processes(self, host: str) -> Optional[list[str]]:
        """List of running process names/identifiers on the host, or None if unavailable."""
        ...

    def get_firewall_rules(self, host: str) -> Optional[list[str]]:
        """List of active firewall rule names on the host, or None if unavailable."""
        ...

    def get_security_agent_status(self, host: str) -> Optional[str]:
        """e.g. 'running', 'stopped', or None if unavailable."""
        ...


class Invariant(Protocol):
    """A single, named, independently-checkable security condition."""

    name: str

    def check(self, evidence: EvidenceProvider) -> InvariantResult:
        ...


class AccountDisabledInvariant:
    """Identity invariant: the compromised account must be disabled (Section 11)."""

    def __init__(self, account: str):
        self.account = account
        self.name = f"compromised_account_disabled:{account}"

    def check(self, evidence: EvidenceProvider) -> InvariantResult:
        enabled = evidence.get_account_enabled(self.account)
        if enabled is None:
            return InvariantResult(
                invariant=self.name,
                status=InvariantStatus.UNKNOWN,
                evidence={"reason": "account status could not be retrieved", "account": self.account},
            )
        status = InvariantStatus.FAIL if enabled else InvariantStatus.PASS
        return InvariantResult(
            invariant=self.name,
            status=status,
            evidence={"account": self.account, "enabled": enabled},
        )


class ScheduledTaskAbsentInvariant:
    """Persistence invariant: a known malicious scheduled task must be absent (Section 11)."""

    def __init__(self, host: str, task_name: str):
        self.host = host
        self.task_name = task_name
        self.name = f"malicious_scheduled_task_absent:{host}:{task_name}"

    def check(self, evidence: EvidenceProvider) -> InvariantResult:
        tasks = evidence.get_scheduled_tasks(self.host)
        if tasks is None:
            return InvariantResult(
                invariant=self.name,
                status=InvariantStatus.UNKNOWN,
                evidence={"reason": "scheduled task list could not be retrieved", "host": self.host},
            )
        present = self.task_name in tasks
        status = InvariantStatus.FAIL if present else InvariantStatus.PASS
        return InvariantResult(
            invariant=self.name,
            status=status,
            evidence={"host": self.host, "task_name": self.task_name, "present": present},
        )


class ProcessTerminatedInvariant:
    """Process invariant: a known malicious process must no longer be running (Section 11)."""

    def __init__(self, host: str, process_identifier: str):
        self.host = host
        self.process_identifier = process_identifier
        self.name = f"malicious_process_terminated:{host}:{process_identifier}"

    def check(self, evidence: EvidenceProvider) -> InvariantResult:
        processes = evidence.get_running_processes(self.host)
        if processes is None:
            return InvariantResult(
                invariant=self.name,
                status=InvariantStatus.UNKNOWN,
                evidence={"reason": "process list could not be retrieved", "host": self.host},
            )
        running = self.process_identifier in processes
        status = InvariantStatus.FAIL if running else InvariantStatus.PASS
        return InvariantResult(
            invariant=self.name,
            status=status,
            evidence={"host": self.host, "process": self.process_identifier, "running": running},
        )


class FirewallRuleAbsentInvariant:
    """Firewall invariant: an unauthorized rule opened during compromise must be removed (Section 11)."""

    def __init__(self, host: str, rule_name: str):
        self.host = host
        self.rule_name = rule_name
        self.name = f"unauthorized_firewall_rule_absent:{host}:{rule_name}"

    def check(self, evidence: EvidenceProvider) -> InvariantResult:
        rules = evidence.get_firewall_rules(self.host)
        if rules is None:
            return InvariantResult(
                invariant=self.name,
                status=InvariantStatus.UNKNOWN,
                evidence={"reason": "firewall rules could not be retrieved", "host": self.host},
            )
        present = self.rule_name in rules
        status = InvariantStatus.FAIL if present else InvariantStatus.PASS
        return InvariantResult(
            invariant=self.name,
            status=status,
            evidence={"host": self.host, "rule": self.rule_name, "present": present},
        )


class EndpointSecurityActiveInvariant:
    """Endpoint security invariant: the security agent must be running (Section 11)."""

    def __init__(self, host: str):
        self.host = host
        self.name = f"endpoint_security_active:{host}"

    def check(self, evidence: EvidenceProvider) -> InvariantResult:
        agent_status = evidence.get_security_agent_status(self.host)
        if agent_status is None:
            return InvariantResult(
                invariant=self.name,
                status=InvariantStatus.UNKNOWN,
                evidence={"reason": "security agent status could not be retrieved", "host": self.host},
            )
        status = InvariantStatus.PASS if agent_status == "running" else InvariantStatus.FAIL
        return InvariantResult(
            invariant=self.name,
            status=status,
            evidence={"host": self.host, "agent_status": agent_status},
        )


class MockEvidenceProvider:
    """In-memory EvidenceProvider for testing and pre-lab development.

    Every field defaults to "unknown" (None) unless explicitly set, which
    means a freshly constructed MockEvidenceProvider drives every invariant
    to UNKNOWN by default — matching the fail-safe posture we want: absence
    of configured evidence must never be mistaken for a passing check.
    """

    def __init__(self):
        self._account_enabled: dict[str, bool] = {}
        self._scheduled_tasks: dict[str, list[str]] = {}
        self._running_processes: dict[str, list[str]] = {}
        self._firewall_rules: dict[str, list[str]] = {}
        self._security_agent_status: dict[str, str] = {}

    def set_account_enabled(self, account: str, enabled: bool) -> None:
        self._account_enabled[account] = enabled

    def set_scheduled_tasks(self, host: str, tasks: list[str]) -> None:
        self._scheduled_tasks[host] = tasks

    def set_running_processes(self, host: str, processes: list[str]) -> None:
        self._running_processes[host] = processes

    def set_firewall_rules(self, host: str, rules: list[str]) -> None:
        self._firewall_rules[host] = rules

    def set_security_agent_status(self, host: str, status: str) -> None:
        self._security_agent_status[host] = status

    def get_account_enabled(self, account: str) -> Optional[bool]:
        return self._account_enabled.get(account)

    def get_scheduled_tasks(self, host: str) -> Optional[list[str]]:
        return self._scheduled_tasks.get(host)

    def get_running_processes(self, host: str) -> Optional[list[str]]:
        return self._running_processes.get(host)

    def get_firewall_rules(self, host: str) -> Optional[list[str]]:
        return self._firewall_rules.get(host)

    def get_security_agent_status(self, host: str) -> Optional[str]:
        return self._security_agent_status.get(host)


def run_assurance(
    incident_id: str,
    invariants: list[Invariant],
    evidence: EvidenceProvider,
) -> AssuranceReport:
    """Run every invariant against the given evidence source and aggregate results.

    This function performs no judgment of its own beyond aggregation — each
    invariant is solely responsible for its own PASS/FAIL/UNKNOWN decision.
    """
    results = [invariant.check(evidence) for invariant in invariants]
    return AssuranceReport(incident_id=incident_id, invariant_results=results)
