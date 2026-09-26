"""
Phase 12: Change Impact Propagation Engine

Propagates detected security changes through dependent graph nodes,
hypotheses, historical findings, attack paths, and PoCs.
"""

from __future__ import annotations

from typing import Any

from runtime.regression.models import ChangeCategory, SecurityChange, SecurityDiff


class ChangeImpactEngine:
    """
    Analyzes the downstream ripple effects of semantic security changes.
    """

    def propagate_impact(
        self,
        diff: SecurityDiff,
        *,
        findings: list[dict[str, Any]] | None = None,
        attack_paths: list[dict[str, Any]] | None = None,
        pocs: list[dict[str, Any]] | None = None,
        graph_relationships: dict[str, list[str]] | None = None,
    ) -> dict[str, Any]:
        """
        Calculates affected research items based on diff changes and graph dependencies.
        """
        findings = findings or []
        attack_paths = attack_paths or []
        pocs = pocs or []
        graph_relationships = graph_relationships or {}

        affected_findings: set[str] = set()
        affected_attack_paths: set[str] = set()
        stale_pocs: set[str] = set()
        affected_boundaries: set[str] = set()
        candidate_regression_targets: list[dict[str, Any]] = []

        for change in diff.changes:
            assets = set(change.affected_assets)

            # 1. Expand assets via graph relationships
            expanded_nodes = set(assets)
            for a in assets:
                expanded_nodes.update(graph_relationships.get(a, []))

            # 2. Check affected findings
            for f in findings:
                f_id = f.get("id", "")
                f_endpoints = set(f.get("affected_endpoints", []))
                f_assets = set(f.get("affected_assets", []))
                f_nodes = f_endpoints | f_assets

                # Direct match or graph match
                if f_nodes & expanded_nodes or any(a in str(f) for a in assets):
                    affected_findings.add(f_id)
                    candidate_regression_targets.append({
                        "type": "FINDING",
                        "id": f_id,
                        "change_id": change.change_id,
                        "category": change.category,
                        "relevance": change.relevance,
                    })

            # 3. Check affected attack paths
            for ap in attack_paths:
                ap_id = ap.get("id", "")
                ap_nodes = set(ap.get("nodes", []))
                if ap_nodes & expanded_nodes or any(a in str(ap) for a in assets):
                    affected_attack_paths.add(ap_id)

            # 4. Check stale PoCs
            for poc in pocs:
                poc_id = poc.get("poc_id", "")
                poc_target = poc.get("target_fingerprint", "")
                poc_reqs = set(poc.get("graph_node_refs", []))
                if poc_reqs & expanded_nodes or poc_target in expanded_nodes or any(a in poc_target for a in assets):
                    stale_pocs.add(poc_id)

            # 5. Track affected boundaries
            if change.category in (ChangeCategory.AUTH_CHANGED, ChangeCategory.AUTHORIZATION_CHANGED):
                affected_boundaries.add("AUTHENTICATION_AUTHORIZATION")
            elif change.category == ChangeCategory.TENANT_MODEL_CHANGED:
                affected_boundaries.add("TENANT_ISOLATION")
            elif change.category in (ChangeCategory.WORKFLOW_CHANGED, ChangeCategory.WORKFLOW_REMOVED):
                affected_boundaries.add("WORKFLOW_STATE")
            elif change.category in (ChangeCategory.ROLE_ADDED, ChangeCategory.ROLE_CHANGED, ChangeCategory.ROLE_REMOVED):
                affected_boundaries.add("ROLE_PRIVILEGE")

        return {
            "affected_finding_ids": sorted(affected_findings),
            "affected_attack_path_ids": sorted(affected_attack_paths),
            "stale_poc_ids": sorted(stale_pocs),
            "affected_boundaries": sorted(affected_boundaries),
            "candidate_targets": candidate_regression_targets,
            "total_impacted_items": len(affected_findings) + len(affected_attack_paths) + len(stale_pocs),
        }
