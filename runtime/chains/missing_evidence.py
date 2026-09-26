"""
Phase 8: Missing Evidence Engine
Identifies missing proof for uncertain chain edges and selects the cheapest discriminating experiment.
"""

from __future__ import annotations

from typing import Any

from runtime.chains.model import (
    AttackPath,
    ChainEdge,
    ChainEdgeStatus,
    PreconditionStatus,
)


class MissingEvidenceEngine:
    """
    Calculates exact evidence gaps in attack paths and identifies
    the cheapest high-value experiment to prove or kill the chain.
    """

    def find_next_chain_gap(self, attack_path: AttackPath) -> tuple[ChainEdge | None, str | None]:
        """
        Finds the first uncertain or unverified edge in the attack path.
        Returns the target edge and a description of the missing evidence gap.
        """
        for edge in attack_path.edges:
            if edge.status in (ChainEdgeStatus.UNVERIFIED, ChainEdgeStatus.INFERRED, ChainEdgeStatus.SUPPORTED):
                # Check for unsatisfied or unknown preconditions
                unk_preconditions = [p for p in edge.preconditions if p.status != PreconditionStatus.SATISFIED]
                if unk_preconditions:
                    gap = f"Precondition gap on {edge.source_node} -> {edge.target_node}: {unk_preconditions[0].statement}"
                    return edge, gap
                
                gap = f"Dependency gap on {edge.source_node} -> {edge.target_node}: Requires verification that {edge.relationship} transition is authorized and impactful."
                return edge, gap

        return None, None
