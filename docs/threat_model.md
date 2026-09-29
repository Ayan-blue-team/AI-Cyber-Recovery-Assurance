# Threat Model

This document defines the attacker profile, assumptions, and boundaries
for every scenario simulated in this project. It exists to make explicit
what is — and is not — being tested, and to formalize the safety
requirements the project's master specification (Section 23) already
mandates.

## 1. Scope

**In scope:**
- The isolated VMware lab described in `docs/lab_topology.md` (or the
  README's lab section): one Windows target, one Kali attacker, one Wazuh
  server, all on a host-only network (`192.168.50.0/24`) with no route to
  the internet or any production network.
- Attack techniques limited to what is required to reproduce each
  documented scenario (Section 15 of the master specification): credential
  compromise, persistence, suspicious process execution, privilege abuse,
  lateral movement, and a non-destructive ransomware simulation.

**Out of scope (explicitly forbidden, per Section 23):**
- Any public infrastructure, third-party system, or real organization.
- Any real user account or credential.
- Any network the operator does not own and has not explicitly authorized
  for this testing.
- Destructive payloads. The ransomware simulation scenario tests recovery
  *verification*, not actual encryption of irrecoverable data — it must
  operate against disposable, snapshotted test data only.

## 2. Attacker Profile

Each scenario assumes a specific, limited attacker capability rather than
an unconstrained "advanced persistent threat." This keeps each scenario
testable and keeps the corresponding recovery/assurance/re-attack logic
scoped to a concrete, falsifiable claim.

| Scenario | Assumed initial access | Assumed capability | Explicitly NOT assumed |
|---|---|---|---|
| Credential Compromise | Valid credentials obtained (e.g. phishing, reuse) | Can authenticate as the compromised user from an attacker-controlled host | No malware execution, no privilege escalation |
| Persistence | Local code execution already achieved | Can create a scheduled task / startup entry | No lateral movement |
| Suspicious PowerShell Execution | Local code execution already achieved | Can run an encoded/obfuscated command | No persistence beyond the single execution |
| Privilege Abuse | Low-privilege local access | Can attempt a known local privilege-escalation path | No domain-wide compromise |
| Lateral Movement | Compromised low-value host/account | Can attempt to reach a second host using harvested material | No prior compromise of the second host |
| Ransomware Simulation | Local code execution already achieved | Can enumerate and read/write test files in a designated, disposable directory | No real encryption of irrecoverable data, no spreading beyond the target VM |

## 3. What Each Scenario's Re-Attack Actually Tests

Per Section 13 of the master specification, a re-attack must reproduce
only the relevant portion of the original scenario — not a generic
penetration test. For each scenario, the re-attack answers one narrow
question:

- **Credential Compromise** — "Can the same credential still be used to
  authenticate after recovery?" (tests account disable + credential
  rotation, not the entire identity system)
- **Persistence** — "Does the same persistence mechanism still execute?"
  (tests removal of that specific artifact, not general malware scanning)
- **Suspicious PowerShell Execution** — "Is the same execution path still
  available and unlogged?" (tests both blocking and telemetry coverage)
- **Privilege Abuse** — "Does the same privilege-escalation path still
  work?"
- **Lateral Movement** — "Can the recovered account/host still reach the
  second host the same way?"
- **Ransomware Simulation** — "Can the same file-access pattern still
  execute against the protected directory?"

This narrow framing is intentional: a broad, unscoped re-attack would
blur the distinction between "this specific recovery failed" and "the
environment has some unrelated vulnerability," which is not what this
project measures.

## 4. Safety Controls

- All offensive tooling runs exclusively from the Kali VM, on the
  host-only network, and is invoked manually or via scripts under version
  control in `re_attack/scenarios/` — never as unreviewed, ad hoc commands
  against anything outside the lab.
- Every VM is snapshotted immediately after a clean install
  (`Clean-Install` snapshot), so any scenario can be reverted rather than
  requiring a full rebuild.
- The AI components in this project (`ai_engine/`) never have direct
  access to the Kali VM or to any offensive tooling. Investigation and
  recovery planning are strictly separated from re-attack execution.
- No credentials, API keys, or lab-specific secrets are committed to this
  repository (enforced via `.gitignore` and `.env`).

## 5. Non-Goals

This project does not aim to:
- Build general-purpose offensive security tooling.
- Discover novel vulnerabilities or exploitation techniques.
- Provide a red-team engagement framework.

Its only goal is to test whether independent, deterministic verification
plus controlled re-attack can catch incomplete recoveries that a
completion-based workflow would otherwise report as resolved.
