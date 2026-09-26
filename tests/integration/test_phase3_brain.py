"""
Hunter Integration Tests — Phase 3: Beast Brain Foundation
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from runtime.bootstrap import HunterRuntime
from runtime.brain.decision import CandidateAction
from runtime.brain.hypotheses import Hypothesis
from runtime.brain.observations import Observation
from runtime.executor.interface import MockExecutor


def _make_isolated_root() -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="hunter-phase3-"))
    (tmp / "hunter").mkdir()
    (tmp / "hunter" / "brain.md").write_text("# Brain stub", encoding="utf-8")
    (tmp / "hunter" / "policy.md").write_text("# Policy stub", encoding="utf-8")
    (tmp / "runtime" / "executor").mkdir(parents=True)
    (tmp / "runtime" / "graph").mkdir(parents=True)
    (tmp / "AGENTS.md").write_text("# AGENTS stub", encoding="utf-8")
    return tmp


class TestScenarioA(unittest.TestCase):
    """Scenario A: Authorization uncertainty -> Select discriminating action."""

    def test_authorization_uncertainty_selects_high_info_action(self):
        root = _make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        
        brain = rt.brain
        
        # State: Observed resource access
        brain.state.add_observation(Observation(id="O-1", source="mock", fact="/api/res/100 -> 200"))
        brain.state.add_observation(Observation(id="O-2", source="mock", fact="/api/res/101 -> 200"))
        
        # Hypothesis: Missing authorization
        h1 = Hypothesis(id="H-1", statement="Object-level auth may be missing")
        brain.state.add_hypothesis(h1)
        
        # Action 1: Random fuzzing (low info gain)
        a1 = CandidateAction(
            id="A-FUZZ", action_type="EXPERIMENT", objective="Fuzz random endpoints",
            target="random", expected_information_gain=0.1, expected_security_value=0.2,
            scope_alignment="IN_SCOPE"
        )
        
        # Action 2: Discriminating action (high info gain)
        a2 = CandidateAction(
            id="A-DISCRIM", action_type="EXPERIMENT", objective="Test auth on specific resource",
            target="/api/res/101", expected_information_gain=0.9, expected_security_value=0.8,
            related_hypotheses=["H-1"], variable_changed="tenant",
            scope_alignment="IN_SCOPE"
        )
        
        # Decide
        selected, rationale = brain.decide_next_action([a1, a2])
        
        self.assertIsNotNone(selected)
        self.assertEqual(selected.id, "A-DISCRIM")
        self.assertEqual(rationale.decision_type, "DEEPEN")
        
        shutil.rmtree(root, ignore_errors=True)


class TestScenarioB(unittest.TestCase):
    """Scenario B: Contradictory evidence reduces confidence and kills hypothesis."""

    def test_contradictory_evidence(self):
        h = Hypothesis(id="H-1", statement="Test")
        h.add_for("Obs-1")
        self.assertEqual(h.state, "ACTIVE")
        self.assertGreater(h.confidence, 0.0)
        
        # Inject strong against evidence
        h.add_against("Obs-2")
        h.add_against("Obs-3")
        
        # Should kill hypothesis mathematically
        self.assertEqual(h.state, "KILLED")
        self.assertIn("Contradictory", h.kill_reason)


class TestScenarioC(unittest.TestCase):
    """Scenario C: Dead end causes pivot (momentum penalty)."""

    def test_repeated_action_degrades_score_and_pivots(self):
        root = _make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        
        brain = rt.brain
        
        # Two equal actions initially
        a1 = CandidateAction(
            id="A-LOOP", action_type="RECON", objective="Looping action", target="/",
            expected_information_gain=0.5, expected_security_value=0.5, scope_alignment="IN_SCOPE"
        )
        
        a2 = CandidateAction(
            id="A-PIVOT", action_type="RECON", objective="New action", target="/new",
            expected_information_gain=0.45, expected_security_value=0.45, scope_alignment="IN_SCOPE"
        )
        
        # First decision should pick A-LOOP (slightly higher base score)
        sel1, _ = brain.decide_next_action([a1, a2])
        self.assertEqual(sel1.id, "A-LOOP")
        
        # Second decision should penalize A-LOOP due to momentum tracking and pick A-PIVOT
        sel2, _ = brain.decide_next_action([a1, a2])
        self.assertEqual(sel2.id, "A-PIVOT")
        
        shutil.rmtree(root, ignore_errors=True)


class TestScenarioD(unittest.TestCase):
    """Scenario D: Scope violation is unconditionally rejected."""

    def test_scope_violation_rejected(self):
        root = _make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        
        brain = rt.brain
        
        a1 = CandidateAction(
            id="A-OUT", action_type="EXPLOIT", objective="Massive value but out of scope",
            target="google.com", expected_information_gain=1.0, expected_security_value=1.0,
            scope_alignment="OUT_OF_SCOPE", related_hypotheses=["H-1"]
        )
        
        a2 = CandidateAction(
            id="A-IN", action_type="RECON", objective="Low value but safe",
            target="internal.app", expected_information_gain=0.1, expected_security_value=0.1,
            scope_alignment="IN_SCOPE", related_hypotheses=["H-1"]
        )
        
        selected, _ = brain.decide_next_action([a1, a2])
        self.assertEqual(selected.id, "A-IN")
        
        shutil.rmtree(root, ignore_errors=True)


class TestScenarioE(unittest.TestCase):
    """Scenario E: Deterministic restart/recovery of Brain State."""

    def test_brain_state_survives_restart(self):
        root = _make_isolated_root()
        
        try:
            # Instance 1
            rt1 = HunterRuntime(root)
            rt1.start()
            rt1.mission_create("Brain test", custom_id="M-BRAIN")
            
            obs = Observation(id="O-TEST", source="mock", fact="Test fact")
            rt1.brain.state.add_observation(obs)
            
            hyp = Hypothesis(id="H-TEST", statement="Test hyp", state="ACTIVE")
            rt1.brain.state.add_hypothesis(hyp)
            
            # Serialize into capsule by checkpointing mission
            rt1.mission_checkpoint("M-BRAIN")
            
            del rt1
            
            # Instance 2
            rt2 = HunterRuntime(root)
            rt2.start()
            capsule = rt2.mission_resume("M-BRAIN")
            
            # Load brain state from capsule
            brain_state = capsule.get("brain_state", {})
            rt2.brain.load_capsule(brain_state)
            
            self.assertIn("O-TEST", rt2.brain.state.observations)
            self.assertEqual(rt2.brain.state.observations["O-TEST"].fact, "Test fact")
            
            self.assertIn("H-TEST", rt2.brain.state.hypotheses)
            self.assertEqual(rt2.brain.state.hypotheses["H-TEST"].state, "ACTIVE")
            
        finally:
            shutil.rmtree(root, ignore_errors=True)

class TestScenarioFGrounding(unittest.TestCase):
    """Scenario F: Candidate Grounding."""
    def test_ungrounded_action_rejected(self):
        root = _make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        
        # High value but completely ungrounded (no objective, no hypothesis, no unknown)
        a1 = CandidateAction(
            id="A-UNGROUNDED", action_type="EXPLOIT", objective="",
            target="target", expected_information_gain=1.0, expected_security_value=1.0,
            scope_alignment="IN_SCOPE"
        )
        
        selected, _ = rt.brain.decide_next_action([a1])
        self.assertIsNone(selected)
        shutil.rmtree(root, ignore_errors=True)

class TestScenarioGPersistedMomentum(unittest.TestCase):
    """Scenario G: Persisted Momentum."""
    def test_momentum_persists_across_restarts(self):
        root = _make_isolated_root()
        rt1 = HunterRuntime(root)
        rt1.start()
        rt1.mission_create("Brain test", custom_id="M-MOMENTUM")
        
        a1 = CandidateAction(
            id="A-LOOP", action_type="RECON", objective="Loop", target="t",
            expected_information_gain=0.5, expected_security_value=0.5, scope_alignment="IN_SCOPE"
        )
        
        # Execute it 5 times to tank its novelty score
        for _ in range(5):
            rt1.brain.decide_next_action([a1])
            
        rt1.mission_checkpoint("M-MOMENTUM")
        
        # Restart
        rt2 = HunterRuntime(root)
        rt2.start()
        capsule = rt2.mission_resume("M-MOMENTUM")
        rt2.brain.load_capsule(capsule.get("brain_state", {}))
        
        a2 = CandidateAction(
            id="A-FRESH", action_type="RECON", objective="Fresh", target="t2",
            expected_information_gain=0.1, expected_security_value=0.1, scope_alignment="IN_SCOPE"
        )
        
        # Even though A-FRESH has much lower base score, A-LOOP's momentum is tanked
        selected, _ = rt2.brain.decide_next_action([a1, a2])
        self.assertEqual(selected.id, "A-FRESH")
        
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
