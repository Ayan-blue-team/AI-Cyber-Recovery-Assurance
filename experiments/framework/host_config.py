"""
Host configuration — resolves the short host references used in scenario
YAML files ("win01", "kali") to actual connection details, read from
environment variables (never hardcoded, never committed to git).

This is the same set of environment variables used by
experiments/scenario_1_automated.py, centralized here so every scenario
YAML file can refer to a host by name without repeating connection setup.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class HostCredentials:
    host: str
    username: str
    password: str


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"ERROR: required environment variable {name} is not set.", file=sys.stderr)
        sys.exit(1)
    return value


def resolve_host(host_ref: Literal["win01", "kali"]) -> HostCredentials:
    if host_ref == "win01":
        return HostCredentials(
            host=_require_env("WIN01_HOST"),
            username=_require_env("WIN01_USER"),
            password=_require_env("WIN01_PASSWORD"),
        )
    if host_ref == "kali":
        return HostCredentials(
            host=_require_env("KALI_HOST"),
            username=_require_env("KALI_USER"),
            password=_require_env("KALI_PASSWORD"),
        )
    raise ValueError(f"Unknown host reference: {host_ref!r}")"""
Host configuration — resolves the short host references used in scenario
YAML files ("win01", "kali") to actual connection details, read from
environment variables (never hardcoded, never committed to git).

This is the same set of environment variables used by
experiments/scenario_1_automated.py, centralized here so every scenario
YAML file can refer to a host by name without repeating connection setup.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class HostCredentials:
    host: str
    username: str
    password: str


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"ERROR: required environment variable {name} is not set.", file=sys.stderr)
        sys.exit(1)
    return value


def resolve_host(host_ref: Literal["win01", "kali"]) -> HostCredentials:
    if host_ref == "win01":
        return HostCredentials(
            host=_require_env("WIN01_HOST"),
            username=_require_env("WIN01_USER"),
            password=_require_env("WIN01_PASSWORD"),
        )
    if host_ref == "kali":
        return HostCredentials(
            host=_require_env("KALI_HOST"),
            username=_require_env("KALI_USER"),
            password=_require_env("KALI_PASSWORD"),
        )
    raise ValueError(f"Unknown host reference: {host_ref!r}")
