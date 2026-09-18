"""
Core data contracts for AI Cyber Recovery Assurance.

These models are the shared language between every stage of the pipeline:

    Incident -> Investigation -> RecoveryPlan -> RecoveryAction (executed)
             -> AssuranceResult -> ReAttackResult -> RecoveryProof

Every module (ai_engine, recovery, assurance, re_attack) should import
from here rather than redefining its own ad-hoc dicts. Keeping this file
small and stable is what lets the rest of the project change independently.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums — controlled vocabularies used across the whole pipeline
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InvariantStatus(str, Enum):
    """Result of a single deterministic security check. No AI judgment here."""
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"  # insufficient evidence — never silently treated as PASS


class RecoveryProofStatus(str, Enum):
    PROVEN = "PROVEN"
    PARTIALLY_PROVEN = "PARTIALLY_PROVEN"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ---------------------------------------------------------------------------
# Incident ingestion (Section 7)
# ---------------------------------------------------------------------------

class Incident(BaseModel):
    """Normalized incident data as received from Wazuh (or another source)."""

    incident_id: str
    source: str
    severity: Severity
    host: str
    user: Optional[str] = None
    alert: str
    timestamp: datetime
    raw_event: Optional[dict] = Field(
        default=None,
        description="Original unmodified event payload, kept for evidence/audit purposes.",
    )


class Finding(BaseModel):
    """A single piece of evidence-backed analysis produced during investigation."""

    description: str
    evidence_source: str = Field(..., description="e.g. 'sysmon', 'wazuh_alert', 'auditd'")
    confidence: RiskLevel = RiskLevel.MEDIUM


class InvestigationResult(BaseModel):
    """Structured output of the AI Investigation Engine (Section 7).

    IMPORTANT: `findings` must be grounded in real evidence passed to the
    model. If evidence is insufficient, root_cause should be None rather
    than guessed.
    """

    incident_id: str
    severity: Severity
    findings: list[Finding] = Field(default_factory=list)
    root_cause: Optional[str] = None
    affected_assets: list[str] = Field(default_factory=list)
    recommended_recovery: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Recovery planning & execution (Sections 8-9)
# ---------------------------------------------------------------------------

class RecoveryAction(BaseModel):
    """A single proposed recovery action, before execution."""

    action_id: Optional[str] = None  # assigned by the orchestrator, not the planner
    action: str = Field(..., description="e.g. 'disable_account', 'remove_scheduled_task'")
    target: str
    reason: str
    risk: RiskLevel
    requires_approval: bool = True


class RecoveryPlan(BaseModel):
    """Full set of recovery actions proposed for one incident."""

    incident_id: str
    actions: list[RecoveryAction]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ExecutionResult(BaseModel):
    """Audit record produced by the Recovery Orchestrator after running an action."""

    action_id: str
    action: str
    target: str
    approved: bool
    executed: bool
    result: str  # e.g. "success", "failed", "skipped"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: Optional[dict] = None


# ---------------------------------------------------------------------------
# Assurance & re-attack (Sections 10-14)
# ---------------------------------------------------------------------------

class InvariantResult(BaseModel):
    """Result of one deterministic security invariant check."""

    invariant: str
    status: InvariantStatus
    evidence: Optional[dict] = None
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AssuranceReport(BaseModel):
    """Aggregate result of the Assurance Engine for one incident."""

    incident_id: str
    invariant_results: list[InvariantResult]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def any_fail(self) -> bool:
        return any(r.status == InvariantStatus.FAIL for r in self.invariant_results)

    @property
    def any_unknown(self) -> bool:
        return any(r.status == InvariantStatus.UNKNOWN for r in self.invariant_results)


class ReAttackResult(BaseModel):
    """Result of replaying the relevant TTP against the recovered environment."""

    incident_id: str
    scenario: str
    blocked: bool  # True = attack failed to reproduce, False = it succeeded again
    evidence: Optional[dict] = None
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RecoveryProof(BaseModel):
    """Final verdict combining assurance + re-attack (Section 14)."""

    incident_id: str
    status: RecoveryProofStatus
    assurance_report: AssuranceReport
    re_attack_result: Optional[ReAttackResult] = None
    rationale: str
