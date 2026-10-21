from unittest.mock import MagicMock, patch

import pytest

from re_attack.connectors.generic_command import (
    GenericCommandReAttackScenario,
    ReAttackParseError,
)


def make_scenario(executor="winrm"):
    return GenericCommandReAttackScenario(
        incident_id="INC-001",
        scenario_name="persistence_task_rerun_attempt",
        executor=executor,
        host="192.168.50.20",
        username="Administrator",
        password="fakepass",
        command='schtasks /run /tn "EvilTask"',
        success_markers=["SUCCESS: Attempted to run"],
        failure_markers=["ERROR:", "cannot find the file specified"],
    )


def test_empty_markers_rejected_at_construction():
    with pytest.raises(ValueError, match="non-empty"):
        GenericCommandReAttackScenario(
            incident_id="INC-001",
            scenario_name="x",
            executor="winrm",
            host="h",
            username="u",
            password="p",
            command="cmd",
            success_markers=[],
            failure_markers=["ERROR:"],
        )


@patch("re_attack.connectors.generic_command.winrm.Session")
def test_winrm_success_marker_means_not_blocked(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    result_obj = MagicMock()
    result_obj.std_out = b"SUCCESS: Attempted to run the scheduled task"
    result_obj.std_err = b""
    mock_session.run_ps.return_value = result_obj

    result = make_scenario("winrm").run()

    assert result.blocked is False
    assert result.evidence["executor"] == "winrm"


@patch("re_attack.connectors.generic_command.winrm.Session")
def test_winrm_failure_marker_means_blocked(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    result_obj = MagicMock()
    result_obj.std_out = b""
    result_obj.std_err = b"ERROR: The system cannot find the file specified."
    mock_session.run_ps.return_value = result_obj

    result = make_scenario("winrm").run()

    assert result.blocked is True


@patch("re_attack.connectors.generic_command.winrm.Session")
def test_ambiguous_output_raises(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    result_obj = MagicMock()
    result_obj.std_out = b"SUCCESS: Attempted to run the scheduled task"
    result_obj.std_err = b"ERROR: also this"
    mock_session.run_ps.return_value = result_obj

    with pytest.raises(ReAttackParseError, match="BOTH"):
        make_scenario("winrm").run()


@patch("re_attack.connectors.generic_command.winrm.Session")
def test_unrecognized_output_raises(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    result_obj = MagicMock()
    result_obj.std_out = b"something unrelated"
    result_obj.std_err = b""
    mock_session.run_ps.return_value = result_obj

    with pytest.raises(ReAttackParseError, match="matched neither"):
        make_scenario("winrm").run()


@patch("re_attack.connectors.generic_command.paramiko.SSHClient")
def test_ssh_executor_path(mock_ssh_client_cls):
    mock_client = MagicMock()
    mock_ssh_client_cls.return_value = mock_client
    stdout = MagicMock()
    stdout.read.return_value = b"ERROR: cannot find the task"
    stderr = MagicMock()
    stderr.read.return_value = b""
    mock_client.exec_command.return_value = (MagicMock(), stdout, stderr)

    result = make_scenario("ssh").run()

    assert result.blocked is True
    assert result.evidence["executor"] == "ssh"
    mock_client.close.assert_called_once()
