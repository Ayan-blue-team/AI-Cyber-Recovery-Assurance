"""
Unit tests for assurance.connectors.winrm_evidence and
recovery.executors.winrm_executor.

These tests mock winrm.Session entirely — no real network connection is
made, so this suite stays safe to run in CI (no lab network available
there). What's tested is the logic around WinRM: command construction,
JSON parsing, and the None-on-failure / ExecutionError-on-failure
contracts, not the actual remote execution (which can only be verified by
running experiments/scenario_1_automated.py against the real lab).
"""

from unittest.mock import MagicMock, patch

import pytest

from ai_engine.schemas import RecoveryAction, RiskLevel
from recovery.orchestrator import ExecutionError


def make_result(status_code=0, std_out=b"", std_err=b""):
    result = MagicMock()
    result.status_code = status_code
    result.std_out = std_out
    result.std_err = std_err
    return result


class TestWinRMEvidenceProvider:
    def _make_provider(self, mock_session_cls):
        from assurance.connectors.winrm_evidence import WinRMEvidenceProvider

        mock_session_cls.return_value = MagicMock()
        provider = WinRMEvidenceProvider("192.168.50.20", "Administrator", "fakepass")
        return provider

    @patch("assurance.connectors.winrm_evidence.winrm.Session")
    def test_get_account_enabled_true(self, mock_session_cls):
        provider = self._make_provider(mock_session_cls)
        provider._session.run_ps.return_value = make_result(
            std_out=b'{"Enabled":true}'
        )
        assert provider.get_account_enabled("user123") is True

    @patch("assurance.connectors.winrm_evidence.winrm.Session")
    def test_get_account_enabled_false(self, mock_session_cls):
        provider = self._make_provider(mock_session_cls)
        provider._session.run_ps.return_value = make_result(
            std_out=b'{"Enabled":false}'
        )
        assert provider.get_account_enabled("user123") is False

    @patch("assurance.connectors.winrm_evidence.winrm.Session")
    def test_get_account_enabled_unknown_on_connection_failure(self, mock_session_cls):
        provider = self._make_provider(mock_session_cls)
        provider._session.run_ps.side_effect = Exception("connection refused")
        assert provider.get_account_enabled("user123") is None

    @patch("assurance.connectors.winrm_evidence.winrm.Session")
    def test_get_account_enabled_unknown_on_malformed_output(self, mock_session_cls):
        provider = self._make_provider(mock_session_cls)
        provider._session.run_ps.return_value = make_result(std_out=b"not json")
        assert provider.get_account_enabled("user123") is None

    @patch("assurance.connectors.winrm_evidence.winrm.Session")
    def test_get_scheduled_tasks_parses_pipe_separated_list(self, mock_session_cls):
        provider = self._make_provider(mock_session_cls)
        provider._session.run_ps.return_value = make_result(
            std_out=b"EvilTask|WindowsUpdate"
        )
        assert provider.get_scheduled_tasks("WIN-01") == ["EvilTask", "WindowsUpdate"]

    @patch("assurance.connectors.winrm_evidence.winrm.Session")
    def test_get_security_agent_status_running(self, mock_session_cls):
        provider = self._make_provider(mock_session_cls)
        provider._session.run_ps.return_value = make_result(std_out=b"Running")
        assert provider.get_security_agent_status("WIN-01") == "running"


class TestWinRMActionExecutor:
    def _make_executor(self, mock_session_cls):
        from recovery.executors.winrm_executor import WinRMActionExecutor

        mock_session_cls.return_value = MagicMock()
        return WinRMActionExecutor("192.168.50.20", "Administrator", "fakepass")

    @patch("recovery.executors.winrm_executor.winrm.Session")
    def test_disable_account_builds_correct_command(self, mock_session_cls):
        executor = self._make_executor(mock_session_cls)
        executor._session.run_ps.return_value = make_result(std_out=b"")

        action = RecoveryAction(
            action="disable_account",
            target="user123",
            reason="test",
            risk=RiskLevel.MEDIUM,
            requires_approval=True,
        )
        result = executor.execute(action)

        executor._session.run_ps.assert_called_once()
        called_command = executor._session.run_ps.call_args[0][0]
        assert "Disable-LocalUser" in called_command
        assert "user123" in called_command
        assert result["simulated"] is False

    @patch("recovery.executors.winrm_executor.winrm.Session")
    def test_unrecognized_action_raises_execution_error(self, mock_session_cls):
        executor = self._make_executor(mock_session_cls)

        action = RecoveryAction(
            action="wipe_entire_disk",
            target="WIN-01",
            reason="test",
            risk=RiskLevel.HIGH,
            requires_approval=True,
        )
        with pytest.raises(ExecutionError, match="No real implementation registered"):
            executor.execute(action)
        executor._session.run_ps.assert_not_called()

    @patch("recovery.executors.winrm_executor.winrm.Session")
    def test_remote_command_failure_raises_execution_error(self, mock_session_cls):
        executor = self._make_executor(mock_session_cls)
        executor._session.run_ps.return_value = make_result(
            status_code=1, std_err=b"Access is denied"
        )

        action = RecoveryAction(
            action="disable_account",
            target="user123",
            reason="test",
            risk=RiskLevel.MEDIUM,
            requires_approval=True,
        )
        with pytest.raises(ExecutionError, match="Access is denied"):
            executor.execute(action)

    @patch("recovery.executors.winrm_executor.winrm.Session")
    def test_terminate_process_strips_exe_suffix(self, mock_session_cls):
        # Regression test: Stop-Process -Name expects the bare process name
        # ("powershell"), not "powershell.exe" — found when the AI planner
        # correctly named "powershell.exe" per its own instructions, but
        # the command silently failed because of this exact mismatch.
        executor = self._make_executor(mock_session_cls)
        executor._session.run_ps.return_value = make_result(std_out=b"")

        action = RecoveryAction(
            action="terminate_process",
            target="powershell.exe",
            reason="test",
            risk=RiskLevel.LOW,
            requires_approval=False,
        )
        executor.execute(action)

        called_command = executor._session.run_ps.call_args[0][0]
        assert "Stop-Process -Name 'powershell'" in called_command
        assert "powershell.exe" not in called_command.split("Stop-Process")[1]

    @patch("recovery.executors.winrm_executor.winrm.Session")
    def test_every_command_suppresses_progress_stream(self, mock_session_cls):
        # Regression test: PowerShell's progress stream ("Preparing modules
        # for first use") was previously captured as stderr noise and
        # mistaken for a real command failure.
        executor = self._make_executor(mock_session_cls)
        executor._session.run_ps.return_value = make_result(std_out=b"")

        action = RecoveryAction(
            action="disable_account", target="user123", reason="t", risk=RiskLevel.MEDIUM
        )
        executor.execute(action)

        called_command = executor._session.run_ps.call_args[0][0]
        assert called_command.startswith("$ProgressPreference = 'SilentlyContinue'; ")

    @patch("recovery.executors.winrm_executor.winrm.Session")
    def test_rollback_only_supported_for_disable_account(self, mock_session_cls):
        executor = self._make_executor(mock_session_cls)

        disable_action = RecoveryAction(
            action="disable_account", target="user123", reason="t", risk=RiskLevel.MEDIUM
        )
        terminate_action = RecoveryAction(
            action="terminate_process", target="malicious.exe", reason="t", risk=RiskLevel.LOW
        )

        assert executor.supports_rollback(disable_action) is True
        assert executor.supports_rollback(terminate_action) is False
