"""
Scenario 1 — Credential Compromise — REAL lab result.

Unlike experiments/scenario_1_credential_compromise.py (which uses fake
LLM clients, a MockEvidenceProvider, and a MockReAttackScenario), this
script records an ACTUAL result observed in the isolated VMware lab:

  Lab: WIN-01 (192.168.50.20), Kali (192.168.50.10), Wazuh (192.168.50.30)

  1. Attacker action (Kali):
     nxc smb 192.168.50.20 -u user123 -p 'Passw0rd123!'
     -> Authenticated successfully.

  2. Detection (Wazuh, Discover):
     Event ID 4624 ("Windows Logon Success") at 2026-10-06 15:14:12,
     data.srcip=192.168.50.10, data.account_name=user123, logon_type=3.

  3. Recovery (WIN-01, PowerShell, manual — simulating the orchestrator):
     Disable-LocalUser -Name 'user123'

  4. Assurance (WIN-01, PowerShell):
     Get-LocalUser -Name 'user123' -> Enabled: False

  5. Re-Attack (Kali):
     nxc smb 192.168.50.20 -u user123 -p 'Passw0rd123!'
     -> Rejected.

  6. Detection of the re-attack (Wazuh, Discover):
     Event ID 4625 ("Windows Logon Failure - Unknown user or bad password")
     at 2026-10-06 15:47:51, data.srcip=192.168.50.10,
     data.account_name=user123.

This is the project's first end-to-end result produced by the real
environment rather than mocked components. No value here is fabricated;
every field is transcribed directly from what was observed in Wazuh's
Discover view and in WIN-01's local PowerShell output.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ai_engine.schemas import InvariantResult, InvariantStatus
from assurance.engine import run_assurance, AccountDisabledInvariant, EvidenceProvider
from re_attack.simulator import ReAttackResult
from re_attack.validator import determine_recovery_proof

RESULTS_DIR = Path(__file__).parent / "results"
INCIDENT_ID = "INC-SCN1-REAL-001"


class RealObservedEvidenceProvider:
    """EvidenceProvider backed by the actual PowerShell output observed on
    WIN-01 after running `Get-LocalUser -Name 'user123'`, rather than a
    canned test value. This is still a thin stand-in for a full
    WazuhEvidenceProvider/ADEvidenceProvider (not built yet), but the value
    it returns is real, not invented.
    """

    def get_account_enabled(self, account: str) -> bool | None:
        if account == "user123":
            return False  # observed: Get-LocalUser -> Enabled: False
        return None

    def get_scheduled_tasks(self, host: str):
        return None

    def get_running_processes(self, host: str):
        return None

    def get_firewall_rules(self, host: str):
        return None

    def get_security_agent_status(self, host: str):
        return None


def main() -> None:
    evidence = RealObservedEvidenceProvider()

    assurance_report = run_assurance(
        incident_id=INCIDENT_ID,
        invariants=[AccountDisabledInvariant("user123")],
        evidence=evidence,
    )

    re_attack_result = ReAttackResult(
        incident_id=INCIDENT_ID,
        scenario="credential_reuse_attempt_smb",
        blocked=True,  # observed: nxc smb re-attempt rejected (Event 4625)
        evidence={
            "simulated": False,
            "source": "wazuh_discover",
            "detection_event_success": {
                "event_id": 4624,
                "timestamp": "2026-10-06T15:14:12",
                "data.srcip": "192.168.50.10",
                "data.account_name": "user123",
                "data.logon_type": 3,
                "rule.description": "Windows Logon Success",
            },
            "detection_event_failure": {
                "event_id": 4625,
                "timestamp": "2026-10-06T15:47:51",
                "data.srcip": "192.168.50.10",
                "data.account_name": "user123",
                "rule.description": "Windows Logon Failure - Unknown user or bad password",
            },
            "attack_tool": "netexec (nxc) smb",
            "target": "WIN-01 (192.168.50.20)",
        },
    )

    proof = determine_recovery_proof(assurance_report, re_attack_result)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / "scenario_1_real.json"
    out_path.write_text(proof.model_dump_json(indent=2), encoding="utf-8")

    print(proof.model_dump_json(indent=2))
    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
