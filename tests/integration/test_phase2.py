"""
Hunter Integration Tests — Phase 2: Persistent Mission State
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from runtime.bootstrap import HunterRuntime


def _make_isolated_root() -> Path:
    """Create a fully isolated project root with required Phase 1 structures."""
    tmp = Path(tempfile.mkdtemp(prefix="hunter-phase2-"))
    (tmp / "hunter").mkdir()
    (tmp / "hunter" / "brain.md").write_text("# Brain stub", encoding="utf-8")
    (tmp / "hunter" / "policy.md").write_text("# Policy stub", encoding="utf-8")
    (tmp / "runtime" / "executor").mkdir(parents=True)
    (tmp / "runtime" / "graph").mkdir(parents=True)
    (tmp / "AGENTS.md").write_text("# AGENTS stub", encoding="utf-8")
    return tmp


class TestMissionManager(unittest.TestCase):
    """Test mission creation, persistence, and event logging."""

    def setUp(self):
        self.root = _make_isolated_root()
        self.rt = HunterRuntime(self.root)
        self.rt.start()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_create_mission_initializes_state(self):
        state = self.rt.mission_create(
            operator_objective="Test mission",
            target_scope=["example.com"],
            custom_id="M-TEST1"
        )
        self.assertEqual(state["mission_id"], "M-TEST1")
        self.assertEqual(state["operator_objective"], "Test mission")
        self.assertEqual(state["status"], "ACTIVE")

        # Verify disk state
        state_file = self.root / "state" / "missions" / "M-TEST1" / "state.json"
        self.assertTrue(state_file.exists())
        with state_file.open() as f:
            disk_state = json.load(f)
        self.assertEqual(disk_state["mission_id"], "M-TEST1")

    def test_mission_events_are_appended(self):
        self.rt.mission_create(operator_objective="Test events", custom_id="M-TEST2")
        events_file = self.root / "state" / "missions" / "M-TEST2" / "events.jsonl"
        self.assertTrue(events_file.exists())
        
        # Read lines
        lines = events_file.read_text().strip().split("\n")
        self.assertGreaterEqual(len(lines), 1)
        event1 = json.loads(lines[0])
        self.assertEqual(event1["event"], "mission_created")
        self.assertEqual(event1["mission"], "M-TEST2")

    def test_active_mission_tracking(self):
        self.rt.mission_create("Obj 1", custom_id="M-ONE")
        self.assertEqual(self.rt.health()["active_mission"], "M-ONE")
        
        self.rt.mission_create("Obj 2", custom_id="M-TWO")
        self.assertEqual(self.rt.health()["active_mission"], "M-TWO")


class TestCheckpointEngine(unittest.TestCase):
    """Test checkpoint creation and resume capsule generation."""

    def setUp(self):
        self.root = _make_isolated_root()
        self.rt = HunterRuntime(self.root)
        self.rt.start()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_create_checkpoint_generates_resume_capsule(self):
        self.rt.mission_create(operator_objective="Checkpoint test", custom_id="M-CHK")
        
        # Manually update state to simulate progress
        self.rt._mission_manager.update_mission("M-CHK", {
            "current_mode": "DEEP-DIVE",
            "active_objectives": ["Find bugs"],
        })
        
        capsule = self.rt.mission_checkpoint("M-CHK")
        self.assertEqual(capsule["mission_id"], "M-CHK")
        self.assertEqual(capsule["active_objectives"], ["Find bugs"])
        
        # Verify it's on disk
        capsule_file = self.root / "state" / "missions" / "M-CHK" / "resume_capsule.json"
        self.assertTrue(capsule_file.exists())


class TestDeterministicRecovery(unittest.TestCase):
    """
    Critical End-to-End Test: Deterministic Recovery
    Proves state survives process death and is reconstructed correctly.
    """

    def test_mission_recovery_across_runtime_instantiations(self):
        root = _make_isolated_root()
        try:
            # 1. Start first runtime
            rt1 = HunterRuntime(root)
            rt1.start()
            
            # 2. Create mission and update state
            rt1.mission_create(
                operator_objective="authorization-research",
                target_scope=["internal.app"],
                custom_id="M-RECOV"
            )
            rt1._mission_manager.update_mission("M-RECOV", {
                "current_mode": "DEEP-DIVE",
                "active_objectives": ["authorization-research"],
            })
            
            # 3. Create checkpoint
            rt1.mission_checkpoint("M-RECOV")
            
            # 4. Simulate process death (destroy rt1)
            del rt1
            
            # 5. Start second runtime instance
            rt2 = HunterRuntime(root)
            rt2.start()
            
            # 6. Resume mission
            capsule = rt2.mission_resume("M-RECOV")
            
            # 7. Verify meaningful state was recovered
            self.assertEqual(capsule["mission_id"], "M-RECOV")
            self.assertEqual(capsule["active_objectives"], ["authorization-research"])
            
            # Verify it's marked as active again
            self.assertEqual(rt2.health()["active_mission"], "M-RECOV")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_corruption_fallback(self):
        root = _make_isolated_root()
        try:
            rt = HunterRuntime(root)
            rt.start()
            rt.mission_create(operator_objective="Test", custom_id="M-CORRUPT")
            rt.mission_checkpoint("M-CORRUPT")
            
            # Simulate corrupted JSON write
            capsule_file = root / "state" / "missions" / "M-CORRUPT" / "resume_capsule.json"
            capsule_file.write_text("{ broken json: ", encoding="utf-8")
            
            # Resume should detect corruption and gracefully rebuild the capsule from state
            capsule = rt.mission_resume("M-CORRUPT")
            self.assertEqual(capsule["mission_id"], "M-CORRUPT")
            # Phase A: integrity-sealed schema (v2) — still a valid capsule after rebuild.
            self.assertEqual(capsule["_schema"], "resume_capsule_v2")
            self.assertTrue(capsule.get("integrity_digest"))
        finally:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
