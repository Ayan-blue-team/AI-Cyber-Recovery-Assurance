
"""
Unit tests for ai_engine.investigation.

These tests use a fake LLMClient so they run offline and deterministically —
no real API calls, no flakiness, no cost. That's the point of the LLMClient
Protocol in investigation.py.
"""

import json
from datetime import datetime

import pytest
from pydantic import ValidationError

from ai_engine.investigation import investigate
from ai_engine.schemas import Incident, Severity


def make_incident() -> Incident:
    return Incident(
        incident_id="INC-001",
        source="wazuh",
        severity=Severity.HIGH,
        host="WIN-01",
        user="user123",
        alert="Suspicious PowerShell execution",
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
    )


class FakeLLMClient:
    """Returns a fixed response, ignoring the prompts. Used to test parsing/validation."""

    def __init__(self, response: str):
        self._response = response

    def complete(self, system: str, user: str) -> str:
        return self._response


def test_investigate_returns_valid_result_on_well_formed_output():
    valid_json = json.dumps(
        {
            "incident_id": "INC-001",
            "severity": "high",
            "findings": [
                {
                    "description": "Encoded PowerShell command observed via Sysmon Event ID 1",
                    "evidence_source": "sysmon",
                    "confidence": "high",
                }
            ],
            "root_cause": "Malicious PowerShell payload executed via phishing attachment",
            "affected_assets": ["WIN-01"],
            "recommended_recovery": ["terminate_process", "disable_account"],
        }
    )
    result = investigate(make_incident(), client=FakeLLMClient(valid_json))

    assert result.incident_id == "INC-001"
    assert result.severity == Severity.HIGH
    assert len(result.findings) == 1
    assert result.root_cause is not None
    assert "disable_account" in result.recommended_recovery


def test_investigate_allows_null_root_cause_when_evidence_insufficient():
    valid_json = json.dumps(
        {
            "incident_id": "INC-001",
            "severity": "high",
            "findings": [],
            "root_cause": None,
            "affected_assets": [],
            "recommended_recovery": [],
        }
    )
    result = investigate(make_incident(), client=FakeLLMClient(valid_json))

    assert result.root_cause is None
    assert result.findings == []


def test_investigate_raises_on_non_json_output():
    with pytest.raises(ValueError, match="non-JSON"):
        investigate(make_incident(), client=FakeLLMClient("I think it's probably fine!"))


def test_investigate_raises_on_schema_violation():
    # Missing required fields (incident_id, severity) -> should fail validation, not
    # silently coerce into a "success" result.
    bad_json = json.dumps({"findings": []})
    with pytest.raises(ValueError, match="schema validation"):
        investigate(make_incident(), client=FakeLLMClient(bad_json))
