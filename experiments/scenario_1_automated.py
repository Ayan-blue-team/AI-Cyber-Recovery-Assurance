"""
Scenario 1 — Credential Compromise — FULLY AUTOMATED run.

Unlike scenario_1_credential_compromise.py (fake LLM, mocked evidence,
mocked re-attack) and scenario_1_real_result.py (real evidence, but
transcribed by a human from manual PowerShell/Wazuh output), THIS script
drives the entire pipeline automatically against the real lab:

    Incident -> AI Investigation (real LLM) -> AI Recovery Plan (real LLM)
             -> Recovery Orchestrator (real WinRM execution on WIN-01)
             -> Assurance Engine (real WinRM evidence from WIN-01)
             -> Controlled Re-Attack (real SSH-triggered attack from Kali)
             -> Recovery Proof

==============================================================================
WHERE TO RUN THIS
==============================================================================
This script makes real network connections to your lab (WinRM to WIN-01,
SSH to Kali). It must be run on a machine that can reach your lab network
(192.168.50.0/24) — i.e. your own computer, NOT a cloud sandbox. It will
not work if run anywhere without that network path.

==============================================================================
SETUP (run once, on your own computer)
==============================================================================
    pip install pywinrm paramiko anthropic pydantic

    # Set these environment variables (never commit real values to git):
    export ANTHROPIC_API_KEY="sk-ant-..."
    export WIN01_HOST="192.168.50.20"
    export WIN01_USER="Administrator"
    export WIN01_PASSWORD="<your WIN-01 Administrator password>"
    export KALI_HOST="192.168.50.10"
    export KALI_USER="root"
    export KALI_PASSWORD="<your Kali root/login password>"

==============================================================================
PREREQUISITES ON THE LAB ITSELF
==============================================================================
    - WIN-01: a local account named 'user123' with a known password must
      exist (see earlier manual testing), AND WinRM must be enabled:
          Enable-PSRemoting -Force
      Your own computer's WinRM client must trust WIN-01:
          Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value "<WIN01_HOST>" -Force
    - Kali: SSH server running and reachable, netexec (nxc) installed.
    - Both VM clocks should be correct (see docs/methodology.md's note on
      the clock-drift issue found during manual testing — Wazuh's
      Discover view depends on this, though this script's own evidence
      path does not).

==============================================================================
SAFETY
==============================================================================
Disabling 'user123' requires approval per the deterministic policy table
in ai_engine/recovery_planner.py. This script uses CLIApprovalProvider,
so it will prompt you interactively before executing anything — it does
NOT auto-approve, even though this is a lab. This mirrors the production
posture: nothing requiring approval runs without an explicit human yes.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from ai_engine.investigation import AnthropicLLMClient, investigate
from ai_engine.gemini_client import GeminiLLMClient
from ai_engine.recovery_planner import plan_recovery
from ai_engine.schemas import Incident, Severity
from assurance.connectors.winrm_evidence import WinRMEvidenceProvider
from assurance.engine import AccountDisabledInvariant, run_assurance
from re_attack.connectors.ssh_kali import KaliSSHReAttackScenario
from re_attack.validator import determine_recovery_proof
from recovery.executors.winrm_executor import WinRMActionExecutor
from recovery.orchestrator import CLIApprovalProvider, execute_plan

RESULTS_DIR = Path(__file__).parent / "results"


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"ERROR: required environment variable {name} is not set.", file=sys.stderr)
        sys.exit(1)
    return value


def build_incident(target_host: str) -> Incident:
    return Incident(
        incident_id="INC-SCN1-AUTO-001",
        source="manual_trigger",  # this run's detection is driven by the operator, not Wazuh alerting
        severity=Severity.HIGH,
        host=target_host,
        user="user123",
        alert="Compromised credential used for SMB authentication from an external host",
        timestamp=datetime.now(timezone.utc),
    )


def main() -> None:
    win01_host = require_env("WIN01_HOST")
    win01_user = require_env("WIN01_USER")
    win01_password = require_env("WIN01_PASSWORD")
    kali_host = require_env("KALI_HOST")
    kali_user = require_env("KALI_USER")
    kali_password = require_env("KALI_PASSWORD")
    # Pick which LLM provider to use. Default is Anthropic (paid, $5 min
    # top-up); set LLM_PROVIDER=gemini to use Google's free-tier API
    # instead (see ai_engine/gemini_client.py for setup).
    provider = os.environ.get("LLM_PROVIDER", "anthropic").lower()
    if provider == "gemini":
        require_env("GEMINI_API_KEY")
        llm_client = GeminiLLMClient()
    else:
        require_env("ANTHROPIC_API_KEY")  # consumed implicitly by AnthropicLLMClient
        llm_client = AnthropicLLMClient()

    incident = build_incident(win01_host)
    print("=== 1. Incident ===")
    print(incident.model_dump_json(indent=2))

    # --- 2. AI Investigation (real LLM call) -------------------------------
    investigation = investigate(
        incident,
        telemetry={
            "note": (
                "A credential-reuse attempt against this host was manually "
                "confirmed via SMB authentication from an external attacker "
                "host prior to this run."
            )
        },
        client=llm_client,
    )
    print("\n=== 2. Investigation Result (real LLM) ===")
    print(investigation.model_dump_json(indent=2))

    # --- 3. AI Recovery Plan (real LLM call, deterministic policy applied) -
    plan = plan_recovery(investigation, client=llm_client)
    print("\n=== 3. Recovery Plan (real LLM + deterministic policy) ===")
    print(plan.model_dump_json(indent=2))

    # --- 4. Recovery Orchestrator (real WinRM execution) -------------------
    executor = WinRMActionExecutor(win01_host, win01_user, win01_password)
    approval_provider = CLIApprovalProvider()  # prompts you interactively — see module docstring
    execution_results = execute_plan(plan, executor=executor, approval_provider=approval_provider)
    print("\n=== 4. Execution Results (real WinRM) ===")
    for result in execution_results:
        print(result.model_dump_json(indent=2))

    # --- 5. Assurance Engine (real WinRM evidence) --------------------------
    evidence = WinRMEvidenceProvider(win01_host, win01_user, win01_password)
    assurance_report = run_assurance(
        incident_id=incident.incident_id,
        invariants=[AccountDisabledInvariant("user123")],
        evidence=evidence,
    )
    print("\n=== 5. Assurance Report (real WinRM evidence) ===")
    print(assurance_report.model_dump_json(indent=2))

    # --- 6. Controlled Re-Attack (real SSH-triggered attack from Kali) ------
    re_attack_scenario = KaliSSHReAttackScenario(
        incident_id=incident.incident_id,
        kali_host=kali_host,
        kali_username=kali_user,
        kali_password=kali_password,
        target_host=win01_host,
        account="user123",
        credential="Passw0rd123!",  # the ORIGINAL compromised credential, intentionally unchanged
    )
    re_attack_result = re_attack_scenario.run()
    print("\n=== 6. Re-Attack Result (real SSH + netexec) ===")
    print(re_attack_result.model_dump_json(indent=2))

    # --- 7. Recovery Proof ---------------------------------------------------
    proof = determine_recovery_proof(assurance_report, re_attack_result)
    print("\n=== 7. RECOVERY PROOF ===")
    print(proof.model_dump_json(indent=2))

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / "scenario_1_automated.json"
    out_path.write_text(proof.model_dump_json(indent=2), encoding="utf-8")
    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
