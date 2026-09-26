"""
Phase 14: Strategic Correlation & Systemic Weakness Engine

Discovers synergies across objectives and detects recurring architectural patterns,
formulating testable SystemicWeaknessHypothesis propositions.
"""

from __future__ import annotations

from typing import Any
from runtime.strategy.models import StrategicObjective, SystemicWeaknessHypothesis


class StrategicCorrelationEngine:
    """Correlates cross-objective findings and identifies systemic architectural weaknesses."""

    def detect_systemic_weaknesses(
        self,
        mission_id: str,
        validated_findings: list[dict[str, Any]],
    ) -> list[SystemicWeaknessHypothesis]:
        """
        Analyzes multiple independent validated findings for shared architectural weaknesses.
        """
        hypotheses: list[SystemicWeaknessHypothesis] = []
        by_class: dict[str, list[dict[str, Any]]] = {}

        for f in validated_findings:
            vclass = str(f.get("vulnerability_class", "GENERIC"))
            if vclass not in by_class:
                by_class[vclass] = []
            by_class[vclass].append(f)

        for vclass, findings in by_class.items():
            if len(findings) >= 3:
                endpoints = [
                    ep for f in findings for ep in f.get("affected_endpoints", [])
                ]
                f_ids = [f.get("id", "") for f in findings if f.get("id")]
                
                h = SystemicWeaknessHypothesis(
                    mission_id=mission_id,
                    title=f"Systemic Weakness: Recurring {vclass} across {len(findings)} endpoints",
                    common_pattern=f"Multiple endpoints exhibit {vclass}; suggests shared middleware or framework deficiency.",
                    affected_endpoints=endpoints[:10],
                    supporting_findings=f_ids,
                    architectural_component="Shared Authorization / Gateway Middleware",
                    recommended_focus="Investigate centralized policy enforcement module.",
                    confidence=0.75,
                )
                hypotheses.append(h)

        return hypotheses
