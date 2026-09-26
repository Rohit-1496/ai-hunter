"""
Beast Brain — Prioritization Heuristics (Phase 3)

Implements the HUNT_VALUE deterministic scoring model to select
the highest-value, safest action.
"""

from __future__ import annotations

from runtime.brain.decision import CandidateAction
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from runtime.brain.state import BrainState


class PrioritizationEngine:
    """
    Evaluates candidate actions using the deterministic HUNT_VALUE heuristic.
    """

    def __init__(self) -> None:
        # Configurable weights for Phase 3
        self.w_impact = 1.0
        self.w_prob = 1.0
        self.w_evidence = 1.0
        self.w_novelty = 1.0
        self.w_researchability = 1.0
    
    def record_action_executed(self, action_id: str, state: 'BrainState') -> None:
        """Track how many times an action ID (or similar action) has been run."""
        state.action_execution_counts[action_id] = state.action_execution_counts.get(action_id, 0) + 1

    def calculate_hunt_value(self, action: CandidateAction, state: 'BrainState') -> float:
        """
        HUNT_VALUE = 
        (impact * prob * evidence * novelty * researchability * info_gain)
        /
        (time_cost + context_cost + risk_cost)
        
        In Phase 3, we simplify this to use the expected values provided
        on the CandidateAction.
        """
        # Numerator
        # We synthesize a novelty penalty if we've run this action before
        times_run = state.action_execution_counts.get(action.id, 0)
        
        # Negative knowledge penalty
        failed_count = sum(1 for nk in state.negative_knowledge if nk.get("action_id") == action.id)
        
        novelty = max(0.01, 1.0 - (times_run * 0.4) - (failed_count * 0.5)) # Degrades quickly
        
        info_gain = action.expected_information_gain
        sec_value = action.expected_security_value
        
        numerator = sec_value * info_gain * novelty
        
        # Denominator
        cost = action.estimated_cost
        risk = action.risk
        
        # Add small base cost to prevent div by zero
        denominator = cost + risk + 0.1
        
        return numerator / denominator
