from ai_engine.schemas import ReAttackResult
from re_attack.simulator import MockReAttackScenario, run_re_attack


def test_mock_scenario_blocked_true():
    scenario = MockReAttackScenario("INC-001", "credential_reuse_attempt", outcome_blocked=True)
    result = run_re_attack(scenario)

    assert isinstance(result, ReAttackResult)
    assert result.blocked is True
    assert result.scenario == "credential_reuse_attempt"
    assert result.evidence["simulated"] is True


def test_mock_scenario_blocked_false():
    scenario = MockReAttackScenario("INC-001", "persistence_re_execution", outcome_blocked=False)
    result = run_re_attack(scenario)

    assert result.blocked is False
    assert result.scenario == "persistence_re_execution"
