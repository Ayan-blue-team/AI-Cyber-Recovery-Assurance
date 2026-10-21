"""
Generic Scenario Runner.

Drives the full pipeline — AI Investigation -> AI Recovery Plan ->
Recovery Orchestrator -> Assurance Engine -> Controlled Re-Attack ->
Recovery Proof — for ANY scenario defined in a YAML file under
experiments/scenarios/, instead of writing a new Python script per
scenario (as scenario_1_automated.py did for Scenario 1).

==============================================================================
WHERE TO RUN THIS
==============================================================================
Same as scenario_1_automated.py: this makes real WinRM/SSH connections to
your lab and must run on a machine with network access to it (your own
computer), not a cloud sandbox.

==============================================================================
USAGE
==============================================================================
    python experiments/run_scenario.py experiments/scenarios/scenario_2_persistence.yaml

Environment variables required (see experiments/framework/host_config.py):
    WIN01_HOST, WIN01_USER, WIN01_PASSWORD
    KALI_HOST, KALI_USER, KALI_PASSWORD
    ANTHROPIC_API_KEY (default) or GEMINI_API_KEY + LLM_PROVIDER=gemini

A scenario YAML file may reference ${VAR_NAME} anywhere in its text (e.g.
"${WIN01_HOST}") — these are substituted from the same environment
variables before the file is parsed, so scenario files don't hardcode a
specific lab's IP addresses.

==============================================================================
BEFORE RUNNING
==============================================================================
Set up the attack precondition yourself first (see the scenario YAML's
`description` field and docs/threat_model.md) — this runner starts from
"the incident has already happened", matching every other script in this
project. It does not generate offensive payloads on its own.

==============================================================================
SAFETY
==============================================================================
Same as scenario_1_automated.py: uses CLIApprovalProvider, so any action
with requires_approval=True (per ai_engine/recovery_planner.py's
deterministic policy table) prompts you interactively. Nothing is
auto-approved.
"""

from __future__ import annotations

import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from ai_engine.gemini_client import GeminiLLMClient
from ai_engine.investigation import AnthropicLLMClient, investigate
from ai_engine.recovery_planner import plan_recovery
from ai_engine.schemas import Incident
from assurance.connectors.winrm_evidence import WinRMEvidenceProvider
from assurance.engine import run_assurance
from assurance.invariant_registry import build_invariant
from experiments.framework.host_config import resolve_host
from experiments.framework.scenario_schema import ScenarioSpec
from re_attack.connectors.generic_command import GenericCommandReAttackScenario
from re_attack.validator import determine_recovery_proof
from recovery.executors.winrm_executor import WinRMActionExecutor
from recovery.orchestrator import CLIApprovalProvider, execute_plan

RESULTS_DIR = Path(__file__).parent / "results"
_ENV_VAR_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _substitute_env_vars(text: str) -> str:
    """Replace ${VAR_NAME} with the value of the matching environment variable."""

    def _replace(match: "re.Match[str]") -> str:
        name = match.group(1)
        value = os.environ.get(name)
        if value is None:
            print(
                f"ERROR: scenario file references ${{{name}}}, but that "
                f"environment variable is not set.",
                file=sys.stderr,
            )
            sys.exit(1)
        return value

    return _ENV_VAR_PATTERN.sub(_replace, text)


def load_scenario(path: Path) -> ScenarioSpec:
    with path.open("r", encoding="utf-8") as f:
        raw_text = f.read()
    substituted = _substitute_env_vars(raw_text)
    raw = yaml.safe_load(substituted)
    return ScenarioSpec(**raw)


def build_llm_client():
    provider = os.environ.get("LLM_PROVIDER", "anthropic").lower()
    if provider == "gemini":
        return GeminiLLMClient()
    return AnthropicLLMClient()


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python experiments/run_scenario.py <path-to-scenario.yaml>", file=sys.stderr)
        sys.exit(1)

    scenario_path = Path(sys.argv[1])
    spec = load_scenario(scenario_path)

    print(f"=== Scenario: {spec.name} ===")
    print(spec.description)

    incident = Incident(
        incident_id=spec.incident.incident_id,
        source=spec.incident.source,
        severity=spec.incident.severity,
        host=spec.incident.host,
        user=spec.incident.user,
        alert=spec.incident.alert,
        timestamp=datetime.now(timezone.utc),
    )
    print("\n=== 1. Incident ===")
    print(incident.model_dump_json(indent=2))

    llm_client = build_llm_client()

    investigation = investigate(
        incident,
        telemetry={"note": spec.incident.telemetry_note} if spec.incident.telemetry_note else None,
        client=llm_client,
    )
    print("\n=== 2. Investigation Result (real LLM) ===")
    print(investigation.model_dump_json(indent=2))

    plan = plan_recovery(investigation, client=llm_client)
    print("\n=== 3. Recovery Plan (real LLM + deterministic policy) ===")
    print(plan.model_dump_json(indent=2))

    win01 = resolve_host("win01")
    executor = WinRMActionExecutor(win01.host, win01.username, win01.password)
    approval_provider = CLIApprovalProvider()
    execution_results = execute_plan(plan, executor=executor, approval_provider=approval_provider)
    print("\n=== 4. Execution Results (real WinRM) ===")
    for result in execution_results:
        print(result.model_dump_json(indent=2))

    evidence = WinRMEvidenceProvider(win01.host, win01.username, win01.password)
    invariants = [build_invariant(inv.name, inv.params) for inv in spec.assurance]
    assurance_report = run_assurance(
        incident_id=incident.incident_id,
        invariants=invariants,
        evidence=evidence,
    )
    print("\n=== 5. Assurance Report (real WinRM evidence) ===")
    print(assurance_report.model_dump_json(indent=2))

    re_attack_host = resolve_host(spec.re_attack.host_ref)
    re_attack_scenario = GenericCommandReAttackScenario(
        incident_id=incident.incident_id,
        scenario_name=spec.re_attack.scenario_name,
        executor=spec.re_attack.executor,
        host=re_attack_host.host,
        username=re_attack_host.username,
        password=re_attack_host.password,
        command=spec.re_attack.command,
        success_markers=spec.re_attack.success_markers,
        failure_markers=spec.re_attack.failure_markers,
    )
    re_attack_result = re_attack_scenario.run()
    print("\n=== 6. Re-Attack Result (real) ===")
    print(re_attack_result.model_dump_json(indent=2))

    proof = determine_recovery_proof(assurance_report, re_attack_result)
    print("\n=== 7. RECOVERY PROOF ===")
    print(proof.model_dump_json(indent=2))

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / f"{spec.name}.json"
    out_path.write_text(proof.model_dump_json(indent=2), encoding="utf-8")
    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
