"""
Beast Brain — Core Loop (Phase 3)

The central cognitive loop for the Hunter.
Loads state -> identifies unknowns -> scores candidates -> safety filter -> selects action.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from runtime.brain.decision import CandidateAction
from runtime.brain.prioritization import PrioritizationEngine
from runtime.brain.rationale import DecisionRationale
from runtime.brain.state import BrainState
from runtime.executor.interface import TacticalExecutorInterface
from runtime.strategy.strategy import ResearchStrategy


class BeastBrain:
    """
    The autonomous research decision layer.
    Decides WHAT should happen based on mission state, observations, and hypotheses.
    """

    def __init__(self, project_root: Path, executor: TacticalExecutorInterface | None = None) -> None:
        self._root = project_root
        self._constitution = project_root / "hunter" / "brain.md"
        self._policy = project_root / "hunter" / "policy.md"
        self._state = BrainState()
        self._strategy = ResearchStrategy()
        self._prioritization = PrioritizationEngine()
        self._executor = executor
        
        self._ready = False
        self._error: str | None = None

    def initialize(self) -> bool:
        """Initialize the brain and verify dependencies."""
        missing = []
        if not self._constitution.is_file():
            missing.append("hunter/brain.md")
        if not self._policy.is_file():
            missing.append("hunter/policy.md")
        if missing:
            self._error = f"Missing constitution files: {', '.join(missing)}"
            self._ready = False
        else:
            self._ready = True
            self._error = None
        return self._ready

    def health(self) -> str:
        if not self._ready:
            return "UNAVAILABLE"
        if self._constitution.is_file() and self._policy.is_file():
            return "READY"
        return "ERROR"

    @property
    def state(self) -> BrainState:
        return self._state

    @property
    def strategy(self) -> ResearchStrategy:
        return self._strategy

    def load_capsule(self, capsule: dict[str, Any]) -> None:
        """Restore Brain state from a Resume Capsule."""
        self._state.load_from_capsule(capsule)

    def generate_capsule_payload(self) -> dict[str, Any]:
        """Serialize Brain state for the CheckpointEngine."""
        return self._state.to_capsule_dict()

    def set_strategy(self, strategy: ResearchStrategy) -> None:
        """Update the active research strategy."""
        self._strategy = strategy

    def decide_next_action(self, candidate_pool: list[CandidateAction] | None = None) -> tuple[CandidateAction | None, DecisionRationale | None]:
        """
        The core Brain decision loop (Phase 3 Deterministic Version).
        
        1. Takes candidate actions (either from internal state or injected pool).
        2. Scores them using PrioritizationEngine (HUNT_VALUE).
        3. Enforces safety and scope filtering.
        4. Selects the highest-value safe action.
        5. Generates structured rationale.
        """
        candidates = candidate_pool or list(self._state.candidate_actions.values())
        
        if not candidates:
            return None, None

        scored_actions = []
        for action in candidates:
            # 1. Safety / Scope Filter
            if action.scope_alignment != "IN_SCOPE":
                continue # Unconditionally reject OUT_OF_SCOPE, REQUIRES_AUTHORIZATION, and UNKNOWN
                
            # 1.5 Grounding Filter
            # Action must be explicitly tied to an objective, hypothesis, or unknown.
            if not action.related_hypotheses and not action.related_unknowns and not action.objective:
                continue
                
            # 2. Score
            score = self._prioritization.calculate_hunt_value(action, self._state)
            scored_actions.append((score, action))
            
        if not scored_actions:
            # All actions were rejected or pool was empty after filtering
            return None, None
            
        # 3. Sort by score descending
        scored_actions.sort(key=lambda x: x[0], reverse=True)
        
        best_score, selected_action = scored_actions[0]
        
        # 4. Determine decision vocabulary
        # Basic heuristic: if it targets a hypothesis, it might be DEEPEN or VALIDATE
        decision_type = "CONTINUE"
        if selected_action.related_hypotheses:
            decision_type = "DEEPEN"
        
        # Track execution momentum
        self._prioritization.record_action_executed(selected_action.id, self._state)
        
        # 5. Generate Rationale
        rejected = []
        for score, action in scored_actions[1:]:
            rejected.append({
                "action_id": action.id,
                "action_type": action.action_type,
                "reason": f"Lower information gain/security value score ({score:.2f} vs {best_score:.2f})"
            })
            
        rationale = DecisionRationale(
            action_id=selected_action.id,
            decision_type=decision_type,
            why=selected_action.reason or "Highest value safe action identified.",
            expected_value=best_score,
            risk=selected_action.risk,
            alternatives_rejected=rejected
        )
        
        return selected_action, rationale
