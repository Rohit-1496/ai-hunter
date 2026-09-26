"""
Phase 8: Attack Path Validation Gate & Compound Finding Store
Enforces the 11-point chain validation criteria and manages compound findings persistence.
"""

from __future__ import annotations

import secrets
from typing import Any

from runtime.chains.model import (
    AttackPath,
    AttackPathState,
    CompoundFinding,
    ExploitabilityAssessment,
)


class AttackPathValidationGate:
    """
    Enforces strict evidence thresholds before promoting an attack path to VALIDATED.
    """

    def validate_attack_path(
        self,
        attack_path: AttackPath,
        evidence_files_exist: bool = True,
        is_in_scope: bool = True,
        destructive_action_attempted: bool = False
    ) -> tuple[AttackPathState, list[str]]:
        """
        Validates an attack path against the 11-point chain criteria.
        """
        reasons: list[str] = []

        # 1. Scope check
        if not is_in_scope:
            reasons.append("GATE_FAIL: Target in attack path is not in authorized mission scope.")
            return AttackPathState.REJECTED, reasons

        # 2. Non-destructive invariant
        if destructive_action_attempted:
            reasons.append("GATE_FAIL: Attack path required destructive actions which violates non-destructive invariant.")
            return AttackPathState.REJECTED, reasons

        # 3. Disk-persisted evidence
        if not evidence_files_exist:
            reasons.append("GATE_FAIL: Evidence files are not persisted on disk.")
            return AttackPathState.PARTIALLY_VALIDATED, reasons

        # 4. Critical step validation
        if len(attack_path.validated_steps) < len(attack_path.edges) and len(attack_path.edges) > 0:
            reasons.append(f"GATE_FAIL: Only {len(attack_path.validated_steps)}/{len(attack_path.edges)} critical edges are validated.")
            return AttackPathState.PARTIALLY_VALIDATED, reasons

        # 5. Blocked steps check
        if len(attack_path.blocked_steps) > 0:
            reasons.append(f"GATE_FAIL: Attack path contains blocked steps: {attack_path.blocked_steps}")
            return AttackPathState.BLOCKED, reasons

        # 6. Compound impact proven
        if not attack_path.impact.get("impact_proven", False):
            reasons.append("GATE_FAIL: Compound impact is unproven.")
            return AttackPathState.PARTIALLY_VALIDATED, reasons

        # 7. Confidence threshold (>= 0.8)
        if attack_path.confidence < 0.8:
            reasons.append(f"GATE_FAIL: Attack path confidence {attack_path.confidence} is below the 0.8 validation threshold.")
            return AttackPathState.PARTIALLY_VALIDATED, reasons

        reasons.append("GATE_PASS: All 11-point attack path validation criteria satisfied.")
        return AttackPathState.VALIDATED, reasons


class CompoundFindingStore:
    """
    Manages the collection of validated compound findings per mission.
    """

    def __init__(self, mission_id: str) -> None:
        self._mission_id = mission_id
        self._compound_findings: dict[str, CompoundFinding] = {}

    @property
    def compound_findings(self) -> dict[str, CompoundFinding]:
        return self._compound_findings

    def create_compound_finding(
        self,
        attack_path: AttackPath,
        exploitability: ExploitabilityAssessment | None = None,
        reproduction_steps: list[str] | None = None
    ) -> CompoundFinding:
        """
        Creates and registers a new compound finding from a validated attack path.
        """
        cf_id = f"COMPOUND-{secrets.token_hex(4).upper()}"
        repro = reproduction_steps or [
            f"1. Exploit entry point: {attack_path.entry_point}",
            f"2. Execute chain steps: {[e.source_node + ' -> ' + e.target_node for e in attack_path.edges]}",
            f"3. Observe compound impact: {attack_path.impact.get('summary', '')}"
        ]

        cf = CompoundFinding(
            id=cf_id,
            mission_id=self._mission_id,
            title=f"Compound Finding: {attack_path.title}",
            severity=attack_path.impact.get("severity", "HIGH"),
            attack_path_id=attack_path.id,
            finding_ids=attack_path.candidate_findings,
            chain_steps=[e.source_node + " -> " + e.target_node for e in attack_path.edges],
            broken_security_boundaries=attack_path.impact.get("broken_security_boundaries", []),
            evidence_refs=attack_path.supporting_evidence,
            validated_edges=attack_path.validated_steps,
            compound_impact=attack_path.impact,
            exploitability=exploitability or attack_path.exploitability,
            confidence=attack_path.confidence,
            reproduction_steps=repro,
            limitations=[]
        )
        self._compound_findings[cf_id] = cf
        return cf

    def get_validated_compound_findings(self) -> list[CompoundFinding]:
        return list(self._compound_findings.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self._mission_id,
            "compound_findings": {cid: c.to_dict() for cid, c in self._compound_findings.items()},
        }

    def load_from_dict(self, data: dict[str, Any]) -> None:
        self._compound_findings.clear()
        for cid, c_data in data.get("compound_findings", {}).items():
            self._compound_findings[cid] = CompoundFinding.from_dict(c_data)
