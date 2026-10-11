"""
WinRMEvidenceProvider — a real EvidenceProvider (Sections 10-11) backed by
a live WinRM connection to a Windows host, instead of a MockEvidenceProvider.

This replaces the manual workflow used in early Scenario 1 testing (where
a human ran PowerShell commands and relayed the output back by hand) with
direct, automatic queries against the actual machine state.

Requires: pip install pywinrm

IMPORTANT — where this runs:
    This class makes real network connections to a Windows host on your
    lab network (e.g. 192.168.50.20). It must run from a machine that can
    reach that network — i.e. your own computer, not a cloud sandbox.
    It is NOT executed as part of this project's automated test suite
    (which must stay network-independent); it is exercised by
    `experiments/scenario_1_automated.py`, which you run yourself.

Design note: every method here returns None (not False, not an exception)
when the query itself fails (host unreachable, auth failure, command
error) — consistent with EvidenceProvider's contract that None means
"insufficient evidence", which assurance/engine.py turns into UNKNOWN,
never a silent PASS.
"""

from __future__ import annotations

import json
from typing import Optional

try:
    import winrm
except ImportError:  # pragma: no cover - only hit if pywinrm isn't installed
    winrm = None


class WinRMEvidenceProvider:
    """Queries a real Windows host's live state over WinRM (HTTP/5985 by default)."""

    def __init__(self, host: str, username: str, password: str, use_ssl: bool = False):
        if winrm is None:
            raise RuntimeError(
                "pywinrm is not installed. Run: pip install pywinrm"
            )
        scheme = "https" if use_ssl else "http"
        port = 5986 if use_ssl else 5985
        self._session = winrm.Session(
            f"{scheme}://{host}:{port}/wsman",
            auth=(username, password),
            transport="ntlm",
        )
        self._host = host

    def _run_ps(self, script: str) -> Optional[str]:
        """Run a PowerShell script remotely, returning stdout or None on any failure."""
        try:
            result = self._session.run_ps(script)
        except Exception:
            return None
        if result.status_code != 0:
            return None
        return result.std_out.decode("utf-8", errors="replace").strip()

    def get_account_enabled(self, account: str) -> Optional[bool]:
        output = self._run_ps(
            f"Get-LocalUser -Name '{account}' -ErrorAction SilentlyContinue | "
            f"ConvertTo-Json -Compress"
        )
        if not output:
            return None
        try:
            data = json.loads(output)
            return bool(data["Enabled"])
        except (json.JSONDecodeError, KeyError, TypeError):
            return None

    def get_scheduled_tasks(self, host: str) -> Optional[list[str]]:
        output = self._run_ps(
            "(Get-ScheduledTask | Select-Object -ExpandProperty TaskName) -join '|'"
        )
        if output is None:
            return None
        return [name for name in output.split("|") if name]

    def get_running_processes(self, host: str) -> Optional[list[str]]:
        output = self._run_ps(
            "(Get-Process | Select-Object -ExpandProperty ProcessName) -join '|'"
        )
        if output is None:
            return None
        return [name for name in output.split("|") if name]

    def get_firewall_rules(self, host: str) -> Optional[list[str]]:
        output = self._run_ps(
            "(Get-NetFirewallRule -Enabled True | "
            "Select-Object -ExpandProperty DisplayName) -join '|'"
        )
        if output is None:
            return None
        return [name for name in output.split("|") if name]

    def get_security_agent_status(self, host: str) -> Optional[str]:
        output = self._run_ps(
            "(Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue).Status"
        )
        if not output:
            return None
        return "running" if output.strip().lower() == "running" else output.strip().lower()
