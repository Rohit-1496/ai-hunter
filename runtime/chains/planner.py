"""
Phase 8: Chain Experiment Planner
Plans single-edge discriminating experiments for uncertain attack paths.
"""

from __future__ import annotations

import secrets
from typing import Any

from runtime.chains.model import (
    AttackPath,
    ChainEdge,
    ChainExperiment,
)
from runtime.brain.decision import CandidateAction


class ChainExperimentPlanner:
    """
    Formulates controlled, single-edge discriminating experiments to test
    specific attack-path transitions without full-scale blind execution.
    """

    def plan_experiment_for_edge(
        self,
        attack_path: AttackPath,
        edge: ChainEdge,
        target_base_url: str,
        scope: list[str] | None = None,
        injected_token: str | None = None
    ) -> ChainExperiment:
        """
        Creates a discriminating experiment targeting a single uncertain edge in an attack path.
        """
        exp_id = f"CH-EXP-{secrets.token_hex(4).upper()}"
        target_endpoint = edge.target_node if edge.target_node.startswith("http") or edge.target_node.startswith("/") else f"/{edge.target_node}"
        full_url = target_base_url.rstrip("/") + ("/" + target_endpoint.lstrip("/") if not target_endpoint.startswith("http") else "")

        # Controlled vs manipulated variables
        controlled = {"url": full_url, "method": "GET"}
        manipulated = {"authorization_token": injected_token or "DISCLOSED_TOKEN"}
        
        headers = {}
        if injected_token:
            headers["X-Admin-Token"] = injected_token
            headers["Authorization"] = f"Bearer {injected_token}"

        baseline_req = {"url": full_url, "method": "GET", "headers": {"X-User-Role": "USER"}}
        test_req = {"url": full_url, "method": "GET", "headers": headers}

        # Validate scope via the centralized resolver (Phase A, fail-closed).
        from runtime.scope.resolver import ScopeResolver

        scope_verdict = ScopeResolver.decide(full_url, scope)
        in_scope = scope_verdict.allowed

        return ChainExperiment(
            id=exp_id,
            attack_path_id=attack_path.id,
            objective=f"Test attack-path edge {edge.source_node} -> {edge.target_node} ({edge.relationship})",
            chain_step=f"{edge.source_node} -> {edge.target_node}",
            preconditions=[p.statement for p in edge.preconditions],
            controlled_variables=controlled,
            manipulated_variables=manipulated,
            baseline_request=baseline_req,
            test_request=test_req,
            expected_outcomes=[
                "Expected secure: Server rejects unauthorized token with 401/403",
                "Expected insecure: Server accepts token and executes privileged operation with 200/201"
            ],
            discriminating_power=1.0,
            information_gain=attack_path.information_gain,
            cost=attack_path.cost,
            risk=attack_path.risk,
            scope="IN_SCOPE" if in_scope else "OUT_OF_SCOPE",
            authorization="AUTHORIZED"
        )

    def to_candidate_action(self, experiment: ChainExperiment) -> CandidateAction:
        """
        Translates a ChainExperiment into a CandidateAction for the Phase 5 execution gate.
        """
        target_url = experiment.test_request.get("url", "")
        return CandidateAction(
            id=f"ACT-CH-{experiment.id}",
            action_type="EXPERIMENT",
            objective=experiment.objective,
            target=target_url,
            capability_id="HTTP_REQUEST",
            input_parameters={
                "url": target_url,
                "method": experiment.test_request.get("method", "GET"),
                "headers": experiment.test_request.get("headers", {})
            },
            expected_information_gain=experiment.information_gain,
            expected_security_value=experiment.information_gain * experiment.discriminating_power,
            scope_alignment=experiment.scope
        )
