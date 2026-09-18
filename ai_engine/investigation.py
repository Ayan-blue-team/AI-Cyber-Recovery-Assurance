from typing import Any


class InvestigationEngine:
    """
    Analyzes normalized security incidents and produces
    a structured investigation result.
    """

    def investigate(self, incident: dict[str, Any]) -> dict[str, Any]:
        return {
            "incident_id": incident.get("incident_id"),
            "status": "pending",
            "severity": incident.get("severity", "unknown"),
            "findings": [],
            "root_cause": None,
            "affected_assets": [],
            "recommended_recovery": [],
        }
