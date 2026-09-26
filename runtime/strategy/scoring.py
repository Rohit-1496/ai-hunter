"""
Phase 14: Strategic Scoring Engine

Computes explainable, multi-variable expected security value for objectives and research directions.
Enforces invariant: CURRENT EVIDENCE > CURRENT SECURITY MODEL > HISTORICAL KNOWLEDGE.
"""

from __future__ import annotations

from typing import Any
from runtime.strategy.models import StrategicObjective, StrategicObjectiveType


class StrategicScoringEngine:
    """Calculates explainable strategic priority and expected return for security objectives."""

    def __init__(self) -> None:
        self.epsilon: float = 0.05

    def score_objective(
        self,
        objective: StrategicObjective,
        *,
        has_current_evidence: bool = False,
        has_historical_prior: bool = False,
        prior_confidence: float = 0.5,
        has_contradiction: bool = False,
        current_coverage_score: float = 0.0,
    ) -> tuple[float, dict[str, Any]]:
        """
        Computes deterministic expected strategic value and detailed factor breakdown.
        """
        impact = max(0.05, min(1.0, objective.expected_impact))
        prob = max(0.05, min(1.0, objective.confidence))
        info_gain = max(0.05, min(1.0, objective.expected_information_gain))
        researchability = max(0.05, min(1.0, objective.researchability))
        novelty = max(0.05, min(1.0, objective.novelty))
        coverage_gain = max(0.05, min(1.0, objective.coverage_contribution))

        cost = max(0.01, objective.estimated_cost)
        time_cost = max(0.01, objective.estimated_time * 0.1)
        risk = max(0.01, objective.risk)
        context_cost = 0.05

        numerator = impact * prob * info_gain * researchability * novelty * coverage_gain
        denominator = cost + time_cost + context_cost + risk + self.epsilon

        base_score = numerator / denominator

        # Modifiers
        historical_bonus = 0.0
        if has_historical_prior and not has_contradiction:
            # Historical prior is an influence factor, not proof
            historical_bonus = min(0.15, prior_confidence * 0.15)

        contradiction_penalty = 0.0
        if has_contradiction:
            contradiction_penalty = 0.30

        evidence_boost = 0.0
        if has_current_evidence:
            evidence_boost = 0.25

        # Normalization and final calculation
        final_score = max(0.01, (base_score * 0.6) + historical_bonus + evidence_boost - contradiction_penalty)
        final_score = round(min(1.0, final_score), 4)

        breakdown = {
            "base_score": round(base_score, 4),
            "impact": impact,
            "probability": prob,
            "information_gain": info_gain,
            "researchability": researchability,
            "novelty": novelty,
            "coverage_gain": coverage_gain,
            "cost": cost,
            "risk": risk,
            "historical_bonus": historical_bonus,
            "evidence_boost": evidence_boost,
            "contradiction_penalty": contradiction_penalty,
            "final_score": final_score,
        }

        objective.security_value = final_score
        objective.priority = final_score
        return final_score, breakdown
