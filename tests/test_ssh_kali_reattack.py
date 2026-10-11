"""
Unit tests for re_attack.connectors.ssh_kali.KaliSSHReAttackScenario.

paramiko.SSHClient is mocked entirely — no real SSH connection is made, so
this stays safe to run in CI. What's tested is the output-parsing logic
(success marker vs. failure markers vs. unrecognized output), which is the
part of this connector that has real behavioral consequences for the
project's RecoveryProof verdicts.
"""

from unittest.mock import MagicMock, patch

import pytest

from re_attack.connectors.ssh_kali import KaliSSHReAttackScenario, ReAttackParseError


def make_scenario():
    return KaliSSHReAttackScenario(
        incident_id="INC-001",
        kali_host="192.168.50.10",
        kali_username="root",
        kali_password="fakepass",
        target_host="192.168.50.20",
        account="user123",
        credential="Passw0rd123!",
    )


def mock_exec_result(output: str):
    stdout = MagicMock()
    stdout.read.return_value = output.encode("utf-8")
    return (MagicMock(), stdout, MagicMock())


@patch("re_attack.connectors.ssh_kali.paramiko.SSHClient")
def test_success_marker_means_not_blocked(mock_ssh_client_cls):
    mock_client = MagicMock()
    mock_ssh_client_cls.return_value = mock_client
    mock_client.exec_command.return_value = mock_exec_result(
        "SMB  192.168.50.20  445  WIN-01  [*] Windows Server 2022...\n"
        "SMB  192.168.50.20  445  WIN-01  [+] WIN-01\\user123:Passw0rd123!\n"
    )

    result = make_scenario().run()

    assert result.blocked is False
    assert result.evidence["simulated"] is False


@patch("re_attack.connectors.ssh_kali.paramiko.SSHClient")
def test_failure_marker_means_blocked(mock_ssh_client_cls):
    mock_client = MagicMock()
    mock_ssh_client_cls.return_value = mock_client
    mock_client.exec_command.return_value = mock_exec_result(
        "SMB  192.168.50.20  445  WIN-01  [-] WIN-01\\user123:Passw0rd123! STATUS_LOGON_FAILURE\n"
    )

    result = make_scenario().run()

    assert result.blocked is True


@patch("re_attack.connectors.ssh_kali.paramiko.SSHClient")
def test_unrecognized_output_raises_parse_error(mock_ssh_client_cls):
    mock_client = MagicMock()
    mock_ssh_client_cls.return_value = mock_client
    mock_client.exec_command.return_value = mock_exec_result("connection timed out, no markers here")

    with pytest.raises(ReAttackParseError, match="Could not classify"):
        make_scenario().run()


@patch("re_attack.connectors.ssh_kali.paramiko.SSHClient")
def test_ssh_client_is_closed_even_on_failure(mock_ssh_client_cls):
    mock_client = MagicMock()
    mock_ssh_client_cls.return_value = mock_client
    mock_client.connect.side_effect = Exception("connection refused")

    with pytest.raises(Exception, match="connection refused"):
        make_scenario().run()

    mock_client.close.assert_called_once()
