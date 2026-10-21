"""
GenericCommandReAttackScenario — a ReAttackScenario (Section 13) that runs
one verification command over WinRM (Windows) or SSH (Linux, e.g. Kali)
and classifies the outcome using configurable success/failure markers.

This generalizes re_attack/connectors/ssh_kali.py's KaliSSHReAttackScenario
(which is hardcoded to the SMB credential-reuse check) so that new
scenarios (Persistence, Suspicious Execution, etc.) can define their
re-attack purely in a YAML scenario file — see
experiments/framework/scenario_schema.py — without writing a new
Python class per scenario.

Design rules (same as ssh_kali.py):
    - `blocked` is derived strictly from matching the command's output
      against the scenario's own success_markers / failure_markers, never
      guessed. Output matching neither list raises ReAttackParseError
      rather than defaulting to either outcome.
    - Matching BOTH lists also raises — an ambiguous result is a signal
      the markers themselves need fixing, not something to silently
      resolve one way or the other.
"""

from __future__ import annotations

from typing import Literal

try:
    import winrm
except ImportError:  # pragma: no cover
    winrm = None

try:
    import paramiko
except ImportError:  # pragma: no cover
    paramiko = None

from ai_engine.schemas import ReAttackResult

Executor = Literal["winrm", "ssh"]


class ReAttackParseError(Exception):
    """Raised when the command's output can't be confidently classified."""


class ReAttackConnectionError(Exception):
    """Raised when the WinRM/SSH connection or command execution itself fails."""


class GenericCommandReAttackScenario:
    """Runs one command over WinRM or SSH and classifies it as blocked/not blocked."""

    def __init__(
        self,
        incident_id: str,
        scenario_name: str,
        executor: Executor,
        host: str,
        username: str,
        password: str,
        command: str,
        success_markers: list[str],
        failure_markers: list[str],
    ):
        if not success_markers or not failure_markers:
            raise ValueError(
                "Both success_markers and failure_markers must be non-empty — "
                "a re-attack scenario with no failure markers can never report "
                "'blocked', and one with no success markers can never report "
                "'not blocked'."
            )
        self.incident_id = incident_id
        self.name = scenario_name
        self._executor_kind = executor
        self._host = host
        self._username = username
        self._password = password
        self._command = command
        self._success_markers = success_markers
        self._failure_markers = failure_markers

    def _run_winrm(self) -> str:
        if winrm is None:
            raise ReAttackConnectionError("pywinrm is not installed. Run: pip install pywinrm")
        session = winrm.Session(
            f"http://{self._host}:5985/wsman",
            auth=(self._username, self._password),
            transport="ntlm",
        )
        try:
            result = session.run_ps(self._command)
        except Exception as exc:
            raise ReAttackConnectionError(f"WinRM execution failed: {exc}") from exc

        output = result.std_out.decode("utf-8", errors="replace")
        output += result.std_err.decode("utf-8", errors="replace")
        return output

    def _run_ssh(self) -> str:
        if paramiko is None:
            raise ReAttackConnectionError("paramiko is not installed. Run: pip install paramiko")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(self._host, username=self._username, password=self._password, timeout=15)
            _stdin, stdout, stderr = client.exec_command(self._command, timeout=30)
            output = stdout.read().decode("utf-8", errors="replace")
            output += stderr.read().decode("utf-8", errors="replace")
        except Exception as exc:
            raise ReAttackConnectionError(f"SSH execution failed: {exc}") from exc
        finally:
            client.close()
        return output

    def run(self) -> ReAttackResult:
        if self._executor_kind == "winrm":
            output = self._run_winrm()
        elif self._executor_kind == "ssh":
            output = self._run_ssh()
        else:
            raise ValueError(f"Unknown executor kind: {self._executor_kind!r}")

        matched_success = any(marker in output for marker in self._success_markers)
        matched_failure = any(marker in output for marker in self._failure_markers)

        if matched_success and matched_failure:
            raise ReAttackParseError(
                f"Output matched BOTH success and failure markers — ambiguous, "
                f"refusing to guess. Raw output:\n{output}"
            )
        if matched_success:
            blocked = False
        elif matched_failure:
            blocked = True
        else:
            raise ReAttackParseError(
                f"Output matched neither success nor failure markers. "
                f"Raw output:\n{output}"
            )

        return ReAttackResult(
            incident_id=self.incident_id,
            scenario=self.name,
            blocked=blocked,
            evidence={
                "simulated": False,
                "executor": self._executor_kind,
                "command": self._command,
                "raw_output": output.strip(),
                "target": self._host,
            },
        )
