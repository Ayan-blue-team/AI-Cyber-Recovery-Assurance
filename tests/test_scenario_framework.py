import os
from pathlib import Path

import pytest
import yaml

from experiments.framework.scenario_schema import ScenarioSpec
from experiments.run_scenario import _substitute_env_vars, load_scenario

SCENARIOS_DIR = Path(__file__).parent.parent / "experiments" / "scenarios"


def test_substitute_env_vars_replaces_known_variable(monkeypatch):
    monkeypatch.setenv("WIN01_HOST", "192.168.50.20")
    result = _substitute_env_vars("host: ${WIN01_HOST}")
    assert result == "host: 192.168.50.20"


def test_substitute_env_vars_exits_on_unset_variable(monkeypatch):
    monkeypatch.delenv("TOTALLY_UNSET_VAR", raising=False)
    with pytest.raises(SystemExit):
        _substitute_env_vars("host: ${TOTALLY_UNSET_VAR}")


def test_scenario_1_yaml_is_valid(monkeypatch):
    monkeypatch.setenv("WIN01_HOST", "192.168.50.20")
    spec = load_scenario(SCENARIOS_DIR / "scenario_1_credential_compromise.yaml")

    assert isinstance(spec, ScenarioSpec)
    assert spec.name == "scenario_1_credential_compromise"
    assert spec.incident.host == "192.168.50.20"
    assert spec.assurance[0].name == "AccountDisabledInvariant"
    assert spec.re_attack.executor == "ssh"
    assert "[+]" in spec.re_attack.success_markers


def test_scenario_2_yaml_is_valid(monkeypatch):
    monkeypatch.setenv("WIN01_HOST", "192.168.50.20")
    spec = load_scenario(SCENARIOS_DIR / "scenario_2_persistence.yaml")

    assert spec.name == "scenario_2_persistence"
    assert spec.assurance[0].name == "ScheduledTaskAbsentInvariant"
    assert spec.assurance[0].params["task_name"] == "EvilTask"
    assert spec.re_attack.executor == "winrm"
    assert spec.re_attack.host_ref == "win01"


def test_scenario_missing_required_field_fails_validation(tmp_path, monkeypatch):
    monkeypatch.setenv("WIN01_HOST", "192.168.50.20")
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(
        yaml.dump(
            {
                "name": "broken_scenario",
                "description": "missing incident/assurance/re_attack",
            }
        )
    )
    with pytest.raises(Exception):  # pydantic ValidationError
        load_scenario(bad_yaml)
