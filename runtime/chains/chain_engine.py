"""
Phase 8: Attack Chain Reasoning Engine
Generates goal-directed attack paths, manages adaptive depth, formulates competing hypotheses,
scores expected chain value, and records negative chain knowledge.
"""

from __future__ import annotations

import secrets
from typing import Any

from runtime.chains.model import (
    AttackPath,
    AttackPathState,
    ChainEdge,
    ChainEdgeStatus,
    ChainGoal,
    DependencyStrength,
    Precondition,
    PreconditionStatus,
)
from runtime.chains.preconditions import PreconditionEngine
from runtime.vulnerability.model import Finding, VulnerabilityClass


class AttackChainEngine:
    """
    Synthesizes multiple observations, vulnerabilities, identities, and workflows
    into structured, goal-directed, evidence-backed attack paths.
    """

    def __init__(self, mission_id: str) -> None:
        self._mission_id = mission_id
        self._attack_paths: dict[str, AttackPath] = {}
        self._negative_knowledge: list[dict[str, Any]] = []
        self._precondition_engine = PreconditionEngine()

    @property
    def attack_paths(self) -> dict[str, AttackPath]:
        return self._attack_paths

    @property
    def negative_knowledge(self) -> list[dict[str, Any]]:
        return self._negative_knowledge

    def generate_chain_candidates(
        self,
        findings: list[Finding],
        endpoints: list[str],
        roles: list[str] | None = None,
        tenants: list[str] | None = None
    ) -> list[AttackPath]:
        """
        Generates candidate attack paths by identifying plausible dependencies
        between observed findings and high-value security goals.
        """
        new_paths: list[AttackPath] = []
        roles = roles or []
        tenants = tenants or []

        # Find data-disclosure / IDOR findings that can enable secondary actions
        data_leak_findings = [
            f for f in findings
            if f.vulnerability_class in (VulnerabilityClass.IDOR_BOLA, VulnerabilityClass.INFORMATION_DISCLOSURE, VulnerabilityClass.AUTHENTICATION_BYPASS)
        ]

        privileged_endpoints = [
            ep for ep in endpoints
            if any(k in ep.lower() for k in ("admin", "promote", "role", "transfer", "config", "export", "delete"))
        ]

        for finding in data_leak_findings:
            for priv_ep in privileged_endpoints:
                p_id = f"PATH-{secrets.token_hex(4).upper()}"
                
                # Create Step 1: Access disclosure endpoint
                edge1 = ChainEdge(
                    id=f"EDGE-1-{secrets.token_hex(3).upper()}",
                    source_node="AUTHENTICATED_USER",
                    target_node=finding.affected_endpoints[0] if finding.affected_endpoints else "/",
                    relationship="LEAKS",
                    evidence_refs=finding.evidence_refs,
                    confidence=0.9,
                    status=ChainEdgeStatus.VALIDATED,
                    preconditions=[
                        Precondition(
                            id=f"PRE-STEP1-{secrets.token_hex(2)}",
                            category="IDENTITY",
                            statement="Requester has standard authenticated identity",
                            status=PreconditionStatus.SATISFIED
                        )
                    ]
                )

                # Create Step 2: Use leaked token/identifier on privileged endpoint
                edge2 = ChainEdge(
                    id=f"EDGE-2-{secrets.token_hex(3).upper()}",
                    source_node=finding.affected_endpoints[0] if finding.affected_endpoints else "/",
                    target_node=priv_ep,
                    relationship="DEPENDS_ON",
                    evidence_refs=[],
                    confidence=0.5,
                    status=ChainEdgeStatus.UNVERIFIED,
                    preconditions=self._precondition_engine.extract_preconditions_for_step(
                        source_node=finding.affected_endpoints[0] if finding.affected_endpoints else "/",
                        target_node=priv_ep,
                        relationship="DEPENDS_ON",
                        context={"required_role": "ADMIN", "required_token": "DISCLOSED_IDENTIFIER"}
                    ),
                    missing_evidence=[f"Verification whether disclosed identifier from {finding.affected_endpoints} satisfies authorization on {priv_ep}"]
                )

                path = AttackPath(
                    id=p_id,
                    mission_id=self._mission_id,
                    title=f"Privilege Escalation via {finding.title} to {priv_ep}",
                    entry_point=finding.affected_endpoints[0] if finding.affected_endpoints else "/",
                    goal=ChainGoal.PRIVILEGE_ESCALATION,
                    nodes=["AUTHENTICATED_USER", finding.affected_endpoints[0] if finding.affected_endpoints else "/", priv_ep, "ROLE_ADMIN"],
                    edges=[edge1, edge2],
                    preconditions=edge1.preconditions + edge2.preconditions,
                    assumptions=[
                        f"Disclosed payload from {finding.affected_endpoints} provides valid authorization on {priv_ep}",
                        f"Endpoint {priv_ep} accepts the disclosed identifier without independent identity validation"
                    ],
                    candidate_findings=[finding.id],
                    supporting_evidence=finding.evidence_refs,
                    validated_steps=[f"{edge1.source_node} -> {edge1.target_node}"],
                    confidence=0.6,
                    impact={"impact_potential": 0.95, "severity": "CRITICAL"},
                    information_gain=0.95,
                    researchability=0.9,
                    cost=0.15,
                    risk=0.1,
                    state=AttackPathState.MODELED,
                    dependency_strength=DependencyStrength.POSSIBLE
                )
                path.calculate_expected_chain_value()
                self._attack_paths[p_id] = path
                new_paths.append(path)

        return new_paths

    def get_top_attack_paths(self, limit: int = 5) -> list[AttackPath]:
        """
        Returns highest-value candidate/modeled/investigating attack paths sorted by expected chain value.
        """
        active = [
            p for p in self._attack_paths.values()
            if p.state in (AttackPathState.CANDIDATE, AttackPathState.MODELED, AttackPathState.INVESTIGATING, AttackPathState.PARTIALLY_VALIDATED, AttackPathState.VALIDATING)
        ]
        return sorted(active, key=lambda p: p.chain_value, reverse=True)[:limit]

    def block_path(self, path_id: str, step_name: str, reason: str) -> None:
        """
        Blocks an attack path and records negative chain knowledge.
        """
        path = self._attack_paths.get(path_id)
        if not path:
            return

        path.block_step(step_name, reason)
        self._negative_knowledge.append({
            "attack_path_id": path.id,
            "title": path.title,
            "goal": path.goal.value,
            "blocked_step": step_name,
            "reason": reason,
        })
        path.calculate_expected_chain_value()

    def reactivate_path(self, path_id: str, new_evidence_id: str, reason: str) -> bool:
        """
        Reactivates a blocked attack path strictly when materially new evidence arrives.
        """
        path = self._attack_paths.get(path_id)
        if not path or path.state != AttackPathState.BLOCKED:
            return False

        path.state = AttackPathState.REACTIVATED
        path.reactivation_reason = f"New evidence {new_evidence_id}: {reason}"
        path.kill_reason = None
        path.dependency_strength = DependencyStrength.POSSIBLE
        if new_evidence_id not in path.supporting_evidence:
            path.supporting_evidence.append(new_evidence_id)
        path.calculate_expected_chain_value()
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self._mission_id,
            "attack_paths": {pid: p.to_dict() for pid, p in self._attack_paths.items()},
            "negative_knowledge": self._negative_knowledge,
        }

    def load_from_dict(self, data: dict[str, Any]) -> None:
        self._attack_paths.clear()
        for pid, p_data in data.get("attack_paths", {}).items():
            self._attack_paths[pid] = AttackPath.from_dict(p_data)
        self._negative_knowledge = data.get("negative_knowledge", [])
