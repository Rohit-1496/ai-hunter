"""
Phase C — Adaptive Prioritization Engine

Implements deterministic, explainable, multi-factor prioritization for
candidate research actions, targets, and hypotheses.
Adheres strictly to Phase C Non-Negotiable Invariants:
- The LLM never overrides hard safety or authorization policies.
- Every priority decision is explainable through structured metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(frozen=True)
class PrioritizationWeights:
    w_exposure: float = 1.0
    w_impact: float = 1.2
    w_evidence: float = 1.0
    w_exploitability: float = 1.1
    w_auth_state: float = 0.8
    w_novelty: float = 1.0
    w_cost_penalty: float = 0.7
    w_diminishing_penalty: float = 0.9
    w_safety_penalty: float = 1.5


@dataclass
class PrioritizationFactorScore:
    exposure: float = 0.5
    potential_impact: float = 0.5
    evidence_strength: float = 0.5
    exploitability: float = 0.5
    auth_state: float = 0.5
    novelty: float = 1.0
    cost_factor: float = 0.2
    budget_headroom: float = 1.0
    diminishing_returns_penalty: float = 0.0
    safety_risk: float = 0.0

    def to_dict(self) -> dict[str, float]:
        return {
            "exposure": round(self.exposure, 4),
            "potential_impact": round(self.potential_impact, 4),
            "evidence_strength": round(self.evidence_strength, 4),
            "exploitability": round(self.exploitability, 4),
            "auth_state": round(self.auth_state, 4),
            "novelty": round(self.novelty, 4),
            "cost_factor": round(self.cost_factor, 4),
            "budget_headroom": round(self.budget_headroom, 4),
            "diminishing_returns_penalty": round(self.diminishing_returns_penalty, 4),
            "safety_risk": round(self.safety_risk, 4),
        }


@dataclass
class AdaptivePrioritizationDecision:
    action_id: str
    target: str
    final_score: float
    vetoed: bool
    veto_reason: str | None
    factors: PrioritizationFactorScore
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "target": self.target,
            "final_score": round(self.final_score, 4),
            "vetoed": self.vetoed,
            "veto_reason": self.veto_reason,
            "factors": self.factors.to_dict(),
            "rationale": self.rationale,
        }


class AdaptivePrioritizer:
    """
    Evaluates candidate security actions using deterministic, explainable
    scoring across 10 security-relevant dimensions.
    """

    def __init__(self, weights: PrioritizationWeights | None = None) -> None:
        self._weights = weights or PrioritizationWeights()
        self._execution_history: dict[str, int] = {}
        self._consecutive_zero_yields: dict[str, int] = {}

    def record_action_outcome(self, action_id: str, new_evidence_count: int, target: str = "") -> None:
        """Track history to update novelty and diminishing returns dynamically."""
        self._execution_history[action_id] = self._execution_history.get(action_id, 0) + 1
        key = target or action_id
        if new_evidence_count == 0:
            self._consecutive_zero_yields[key] = self._consecutive_zero_yields.get(key, 0) + 1
        else:
            self._consecutive_zero_yields[key] = 0

    def evaluate_candidate(
        self,
        action_id: str,
        target: str,
        candidate_meta: dict[str, Any],
        *,
        is_in_scope: bool = True,
        is_authorized: bool = True,
        remaining_budget_pct: float = 1.0,
    ) -> AdaptivePrioritizationDecision:
        """
        Calculates priority score and explains rationale.
        Enforces hard deterministic safety and scope vetoes before scoring.
        """
        # 1. Hard deterministic vetoes (LLM cannot override)
        if not is_in_scope:
            return AdaptivePrioritizationDecision(
                action_id=action_id,
                target=target,
                final_score=0.0,
                vetoed=True,
                veto_reason="OUT_OF_SCOPE: Target is outside mission scope boundary",
                factors=PrioritizationFactorScore(exposure=0.0, novelty=0.0),
                rationale="Deterministic veto: Candidate target failed scope boundary verification.",
            )

        if not is_authorized:
            return AdaptivePrioritizationDecision(
                action_id=action_id,
                target=target,
                final_score=0.0,
                vetoed=True,
                veto_reason="UNAUTHORIZED: Action requires explicit authorization not present in mission contract",
                factors=PrioritizationFactorScore(exposure=0.0, novelty=0.0),
                rationale="Deterministic veto: Action lacks valid mission authorization.",
            )

        # 2. Extract and clamp factor inputs [0.0, 1.0]
        exposure = float(candidate_meta.get("exposure", 0.5))
        potential_impact = float(candidate_meta.get("potential_impact", 0.5))
        evidence_strength = float(candidate_meta.get("evidence_strength", 0.5))
        exploitability = float(candidate_meta.get("exploitability", 0.5))
        auth_state = float(candidate_meta.get("auth_state", 0.5))
        cost = max(0.01, float(candidate_meta.get("cost", 0.2)))
        safety_risk = max(0.0, float(candidate_meta.get("safety_risk", 0.0)))

        # 3. Dynamic novelty decay
        times_run = self._execution_history.get(action_id, 0)
        novelty = max(0.05, 1.0 - (times_run * 0.25))

        # 4. Diminishing returns penalty
        zero_yields = self._consecutive_zero_yields.get(target or action_id, 0)
        diminishing_penalty = min(0.9, zero_yields * 0.3)

        # 5. Budget headroom
        budget_headroom = max(0.0, min(1.0, remaining_budget_pct))

        factors = PrioritizationFactorScore(
            exposure=min(1.0, max(0.0, exposure)),
            potential_impact=min(1.0, max(0.0, potential_impact)),
            evidence_strength=min(1.0, max(0.0, evidence_strength)),
            exploitability=min(1.0, max(0.0, exploitability)),
            auth_state=min(1.0, max(0.0, auth_state)),
            novelty=novelty,
            cost_factor=min(1.0, max(0.01, cost)),
            budget_headroom=budget_headroom,
            diminishing_returns_penalty=diminishing_penalty,
            safety_risk=min(1.0, max(0.0, safety_risk)),
        )

        # 6. Safety risk hard veto threshold
        if factors.safety_risk >= 0.85:
            return AdaptivePrioritizationDecision(
                action_id=action_id,
                target=target,
                final_score=0.0,
                vetoed=True,
                veto_reason="EXCESSIVE_SAFETY_RISK: Safety risk score exceeds maximum threshold (0.85)",
                factors=factors,
                rationale=f"Deterministic veto: Candidate poses unacceptable safety risk ({factors.safety_risk:.2f}).",
            )

        # 7. Compute weighted numerator (Benefit)
        benefit = (
            (factors.exposure * self._weights.w_exposure)
            + (factors.potential_impact * self._weights.w_impact)
            + (factors.evidence_strength * self._weights.w_evidence)
            + (factors.exploitability * self._weights.w_exploitability)
            + (factors.auth_state * self._weights.w_auth_state)
            + (factors.novelty * self._weights.w_novelty)
        )

        # 8. Compute weighted denominator (Cost & Friction)
        cost_penalty = factors.cost_factor * self._weights.w_cost_penalty
        diminishing_impact = factors.diminishing_returns_penalty * self._weights.w_diminishing_penalty
        safety_impact = factors.safety_risk * self._weights.w_safety_penalty
        budget_damping = 1.0 / max(0.1, factors.budget_headroom)

        friction = (cost_penalty + diminishing_impact + safety_impact + 0.1) * budget_damping
        final_score = max(0.0, benefit / friction)

        rationale = (
            f"Calculated score {final_score:.2f} (benefit={benefit:.2f}, friction={friction:.2f}, "
            f"novelty={factors.novelty:.2f}, diminishing_penalty={factors.diminishing_returns_penalty:.2f})"
        )

        return AdaptivePrioritizationDecision(
            action_id=action_id,
            target=target,
            final_score=final_score,
            vetoed=False,
            veto_reason=None,
            factors=factors,
            rationale=rationale,
        )

    def rank_candidates(
        self,
        candidates: list[dict[str, Any]],
        *,
        scope_validator: Callable[[str], bool] | None = None,
        auth_validator: Callable[[str], bool] | None = None,
        remaining_budget_pct: float = 1.0,
    ) -> list[AdaptivePrioritizationDecision]:
        """Rank candidates in descending order of explainable priority score."""
        decisions: list[AdaptivePrioritizationDecision] = []
        for cand in candidates:
            action_id = cand.get("action_id", "unknown_action")
            target = cand.get("target", "")

            in_scope = True
            if scope_validator is not None:
                in_scope = scope_validator(target)

            authorized = True
            if auth_validator is not None:
                authorized = auth_validator(target)

            decision = self.evaluate_candidate(
                action_id=action_id,
                target=target,
                candidate_meta=cand,
                is_in_scope=in_scope,
                is_authorized=authorized,
                remaining_budget_pct=remaining_budget_pct,
            )
            decisions.append(decision)

        # Sort: non-vetoed first, then by final_score descending
        decisions.sort(key=lambda d: (-1 if not d.vetoed else 1, -d.final_score))
        return decisions
