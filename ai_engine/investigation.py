"""
AI Investigation Engine (Section 7).

Responsibility: turn a normalized Incident + whatever raw telemetry we have
into a structured InvestigationResult (findings, root cause, affected
assets, recommended recovery actions).

Design rules this module must respect (Section 24/25):
    - The LLM only ever *reasons*; it has no execution capability here.
    - Output must conform to InvestigationResult — never free text.
    - If the supplied evidence does not support a root cause, root_cause
      must be left as None. The model must not invent evidence that was
      not present in the input.
    - This module is deterministic in its plumbing (parsing, validation)
      even though the LLM call itself is not — validation failures raise,
      they never get silently coerced into a "passing" result.
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional, Protocol

from pydantic import ValidationError

from ai_engine.schemas import Incident, InvestigationResult

SYSTEM_PROMPT = """\
You are a SOC investigation assistant. You analyze security incident data \
and telemetry to produce a STRICT JSON object matching this schema:

{
  "incident_id": string,
  "severity": "low" | "medium" | "high" | "critical",
  "findings": [
    {"description": string, "evidence_source": string, "confidence": "low" | "medium" | "high"}
  ],
  "root_cause": string | null,
  "affected_assets": [string],
  "recommended_recovery": [string]
}

Rules:
- Base every finding strictly on the evidence provided in the user message.
  Do not invent hosts, users, IOCs, or techniques that are not present in
  the input.
- If the evidence is insufficient to determine a root cause, set
  "root_cause" to null rather than guessing.
- "recommended_recovery" should be short human-readable action labels
  (e.g. "disable_account", "remove_scheduled_task"), not full sentences.
- Return ONLY the JSON object. No prose, no markdown fences.
"""


class LLMClient(Protocol):
    """Minimal interface the investigation engine needs from an LLM client.

    Defining this as a Protocol (rather than importing a concrete SDK class)
    keeps this module testable: unit tests can pass in a fake client that
    returns canned JSON without hitting the network.
    """

    def complete(self, system: str, user: str) -> str:
        ...


class AnthropicLLMClient:
    """Thin wrapper around the Anthropic SDK implementing LLMClient."""

    def __init__(self, model: str = "claude-sonnet-4-6", api_key: Optional[str] = None):
        import anthropic  # local import so the module can be used/tested without the SDK installed

        self._client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self._model = model

    def complete(self, system: str, user: str) -> str:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=1500,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(block.text for block in response.content if block.type == "text")


def _build_user_message(incident: Incident, telemetry: Optional[dict[str, Any]]) -> str:
    payload = {
        "incident": json.loads(incident.model_dump_json()),
        "telemetry": telemetry or {},
    }
    return (
        "Analyze the following incident and telemetry. Respond with the "
        "JSON object described in the system prompt only.\n\n"
        f"{json.dumps(payload, indent=2)}"
    )


def investigate(
    incident: Incident,
    telemetry: Optional[dict[str, Any]] = None,
    client: Optional[LLMClient] = None,
) -> InvestigationResult:
    """Run the investigation step for a single incident.

    Args:
        incident: normalized incident data (e.g. from Wazuh).
        telemetry: any additional raw evidence available (Sysmon events,
            auditd records, etc). Passed through to the model so findings
            can cite it via `evidence_source`.
        client: an LLMClient implementation. Defaults to AnthropicLLMClient.
            Injecting this is what makes the function unit-testable without
            calling the real API.

    Returns:
        A validated InvestigationResult.

    Raises:
        ValueError: if the model output is not valid JSON or does not
            conform to InvestigationResult. We fail loudly rather than
            silently returning a partially-guessed result — an
            investigation failure must be visible, not hidden.
    """
    client = client or AnthropicLLMClient()
    user_message = _build_user_message(incident, telemetry)
    raw_output = client.complete(system=SYSTEM_PROMPT, user=user_message)

    try:
        parsed = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Investigation engine returned non-JSON output: {raw_output!r}") from exc

    try:
        return InvestigationResult(**parsed)
    except ValidationError as exc:
        raise ValueError(f"Investigation engine output failed schema validation: {exc}") from exc
