"""
KaliSSHReAttackScenario — a real ReAttackScenario (Section 13) that
replays the credential-reuse attack from the Kali VM over SSH, replacing
the manual "run this command on Kali and read the output yourself" step
used in earlier Scenario 1 testing.

Requires: pip install paramiko

IMPORTANT — where this runs: same caveat as the WinRM connectors — this
makes a real SSH connection to your Kali VM and must run from a machine
that can reach your lab network.

Design note: `blocked` is derived strictly from netexec's own reported
outcome, matched by simple, explicit substring checks on its output — not
inferred, not guessed. If the output doesn't match either a known-success
or known-failure pattern, this raises rather than silently defaulting to
either outcome, because a mis-parsed re-attack result is worse than no
result: Section 13 requires this evidence to be real, so an ambiguous
parse must be visible, not papered over.
"""

from __future__ import annotations

try:
    import paramiko
except ImportError:  # pragma: no cover
    paramiko = None

from ai_engine.schemas import ReAttackResult


class ReAttackParseError(Exception):
    """Raised when the attack tool's output can't be confidently classified."""


# netexec (and its predecessor crackmapexec) print a line starting with
# one of these markers for an SMB credential check. These are the only
# two outcomes this scenario is scoped to recognize (Section 13: a
# re-attack reproduces one narrow, specific thing, not an open-ended scan).
SUCCESS_MARKER = "[+]"
FAILURE_MARKERS = ("[-]", "STATUS_LOGON_FAILURE", "STATUS_ACCOUNT_DISABLED")


class KaliSSHReAttackScenario:
    """Re-runs the SMB credential-reuse attempt from Kali over SSH."""

    def __init__(
        self,
        incident_id: str,
        kali_host: str,
        kali_username: str,
        kali_password: str,
        target_host: str,
        account: str,
        credential: str,
        scenario_name: str = "credential_reuse_attempt_smb",
    ):
        if paramiko is None:
            raise RuntimeError("paramiko is not installed. Run: pip install paramiko")
        self.incident_id = incident_id
        self.name = scenario_name
        self._kali_host = kali_host
        self._kali_username = kali_username
        self._kali_password = kali_password
        self._target_host = target_host
        self._account = account
        self._credential = credential

    def run(self) -> ReAttackResult:
        command = f"nxc smb {self._target_host} -u {self._account} -p '{self._credential}'"

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                self._kali_host,
                username=self._kali_username,
                password=self._kali_password,
                timeout=15,
            )
            _stdin, stdout, stderr = client.exec_command(command, timeout=30)
            output = stdout.read().decode("utf-8", errors="replace")
        finally:
            client.close()

        if SUCCESS_MARKER in output:
            blocked = False
        elif any(marker in output for marker in FAILURE_MARKERS):
            blocked = True
        else:
            raise ReAttackParseError(
                f"Could not classify netexec output as success or failure. "
                f"Raw output:\n{output}"
            )

        return ReAttackResult(
            incident_id=self.incident_id,
            scenario=self.name,
            blocked=blocked,
            evidence={
                "simulated": False,
                "command": command,
                "raw_output": output.strip(),
                "target": self._target_host,
            },
        )
