"""
Beast Brain — Core State (Phase 3)

Aggregates observations, hypotheses, unknowns, and candidate actions.
Handles serialization to/from Phase 2 Resume Capsules.
"""

from __future__ import annotations

from typing import Any

from runtime.brain.decision import CandidateAction
from runtime.brain.hypotheses import Hypothesis
from runtime.brain.observations import Interpretation, Observation, Unknown


class BrainState:
    """The complete cognitive state of the Beast Brain."""

    def __init__(self) -> None:
        self.observations: dict[str, Observation] = {}
        self.interpretations: dict[str, Interpretation] = {}
        self.hypotheses: dict[str, Hypothesis] = {}
        self.unknowns: dict[str, Unknown] = {}
        self.candidate_actions: dict[str, CandidateAction] = {}
        self.negative_knowledge: list[dict[str, Any]] = []
        self.action_execution_counts: dict[str, int] = {}

    def add_observation(self, obs: Observation) -> None:
        self.observations[obs.id] = obs

    def add_hypothesis(self, hyp: Hypothesis) -> None:
        self.hypotheses[hyp.id] = hyp

    def add_unknown(self, unk: Unknown) -> None:
        self.unknowns[unk.id] = unk

    def add_candidate_action(self, action: CandidateAction) -> None:
        self.candidate_actions[action.id] = action

    def to_capsule_dict(self) -> dict[str, Any]:
        """
        Serializes the Brain State into a format suitable for the Resume Capsule.
        Note: Phase 2 checkpoints were placeholders. Phase 3 injects real state.
        """
        return {
            "observations": [o.to_dict() for o in self.observations.values()],
            "interpretations": [i.to_dict() for i in self.interpretations.values()],
            "hypotheses": [h.to_dict() for h in self.hypotheses.values()],
            "unknowns": [u.to_dict() for u in self.unknowns.values()],
            "candidate_actions": [c.to_dict() for c in self.candidate_actions.values()],
            "negative_knowledge": self.negative_knowledge,
            "action_execution_counts": self.action_execution_counts,
        }

    def load_from_capsule(self, data: dict[str, Any]) -> None:
        """Restores state from a Resume Capsule."""
        if not isinstance(data, dict):
            data = {}
        self.observations.clear()
        for o_data in data.get("observations", []):
            o = Observation.from_dict(o_data)
            self.observations[o.id] = o

        self.interpretations.clear()
        for i_data in data.get("interpretations", []):
            i = Interpretation.from_dict(i_data)
            self.interpretations[i.id] = i

        self.hypotheses.clear()
        for h_data in data.get("hypotheses", []):
            h = Hypothesis.from_dict(h_data)
            self.hypotheses[h.id] = h

        self.unknowns.clear()
        for u_data in data.get("unknowns", []):
            u = Unknown.from_dict(u_data)
            self.unknowns[u.id] = u

        self.candidate_actions.clear()
        for c_data in data.get("candidate_actions", []):
            c = CandidateAction.from_dict(c_data)
            self.candidate_actions[c.id] = c

        self.negative_knowledge = data.get("negative_knowledge", [])
        self.action_execution_counts = data.get("action_execution_counts", {})
