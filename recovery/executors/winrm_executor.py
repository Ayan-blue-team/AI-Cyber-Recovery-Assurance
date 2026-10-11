"""
WinRMActionExecutor — a real ActionExecutor (Section 9) that runs recovery
actions against a live Windows host over WinRM, replacing the
MockActionExecutor used before the lab was reachable from code.

Requires: pip install pywinrm

IMPORTANT — where this runs: same caveat as
assurance/connectors/winrm_evidence.py — this makes real network calls and
must run on a machine with access to your lab network.

Design note: only a small, explicit set of action names are mapped to real
PowerShell commands (ACTION_COMMANDS below). An action name the executor
does not recognize raises ExecutionError rather than guessing a command —
this is the executor-side counterpart to recovery_planner's fail-safe
policy table: an unrecognized action must be visible as a failure, never
silently skipped or improvised.
"""

from __future__ import annotations

from typing import Callable

try:
    import winrm
except ImportError:  # pragma: no cover
    winrm = None

from ai_engine.schemas import RecoveryAction
from recovery.orchestrator import ExecutionError


def _disable_account_cmd(target: str) -> str:
    return f"Disable-LocalUser -Name '{target}'"


def _rotate_credentials_cmd(target: str) -> str:
    # NOTE: generates a new random password rather than a fixed one, so the
    # new credential is never committed to code or logs in plain text.
    return (
        f"$newPass = -join ((48..57 + 65..90 + 97..122) | Get-Random -Count 20 | "
        f"ForEach-Object {{[char]$_}}); "
        f"Set-LocalUser -Name '{target}' -Password (ConvertTo-SecureString $newPass -AsPlainText -Force); "
        f"Write-Output 'rotated'"
    )


def _terminate_process_cmd(target: str) -> str:
    # `target` expected to be a process name (e.g. "powershell"), not a PID,
    # to stay stable across repeated runs.
    return f"Stop-Process -Name '{target}' -Force -ErrorAction SilentlyContinue"


def _remove_scheduled_task_cmd(target: str) -> str:
    return f"Unregister-ScheduledTask -TaskName '{target}' -Confirm:$false"


# Maps a recognized action name to a function building the PowerShell command.
# Mirrors ai_engine/recovery_planner.py's KNOWN_ACTIONS table — an action
# the planner recognizes should have a real implementation here before this
# executor is used for that action type.
ACTION_COMMANDS: dict[str, Callable[[str], str]] = {
    "disable_account": _disable_account_cmd,
    "rotate_credentials": _rotate_credentials_cmd,
    "terminate_process": _terminate_process_cmd,
    "remove_scheduled_task": _remove_scheduled_task_cmd,
}


class WinRMActionExecutor:
    """Executes RecoveryAction objects as real PowerShell commands over WinRM."""

    def __init__(self, host: str, username: str, password: str, use_ssl: bool = False):
        if winrm is None:
            raise RuntimeError("pywinrm is not installed. Run: pip install pywinrm")
        scheme = "https" if use_ssl else "http"
        port = 5986 if use_ssl else 5985
        self._session = winrm.Session(
            f"{scheme}://{host}:{port}/wsman",
            auth=(username, password),
            transport="ntlm",
        )

    def execute(self, action: RecoveryAction) -> dict:
        command_builder = ACTION_COMMANDS.get(action.action)
        if command_builder is None:
            raise ExecutionError(
                f"No real implementation registered for action '{action.action}'. "
                f"Refusing to guess a command — add one to ACTION_COMMANDS first."
            )

        command = command_builder(action.target)
        try:
            result = self._session.run_ps(command)
        except Exception as exc:
            raise ExecutionError(f"WinRM connection/execution failed: {exc}") from exc

        if result.status_code != 0:
            stderr = result.std_err.decode("utf-8", errors="replace")
            raise ExecutionError(f"Remote command failed (exit {result.status_code}): {stderr}")

        return {
            "simulated": False,
            "action": action.action,
            "target": action.target,
            "stdout": result.std_out.decode("utf-8", errors="replace").strip(),
        }

    def supports_rollback(self, action: RecoveryAction) -> bool:
        return action.action == "disable_account"  # re-enabling is the one safe, reversible case here

    def rollback(self, action: RecoveryAction) -> dict:
        if action.action != "disable_account":
            raise ExecutionError(f"No rollback implemented for action '{action.action}'")
        try:
            result = self._session.run_ps(f"Enable-LocalUser -Name '{action.target}'")
        except Exception as exc:
            raise ExecutionError(f"WinRM rollback failed: {exc}") from exc
        return {"simulated": False, "action": "rollback_disable_account", "target": action.target}
