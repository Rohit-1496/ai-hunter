"""
Hunter Phase 2 Integrity Audit Tests

Verifies requirements around atomicity, consistency, isolation, and recovery.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from runtime.bootstrap import HunterRuntime

def _make_isolated_root() -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="hunter-audit-"))
    (tmp / "hunter").mkdir()
    (tmp / "hunter" / "brain.md").write_text("# Brain stub", encoding="utf-8")
    (tmp / "hunter" / "policy.md").write_text("# Policy stub", encoding="utf-8")
    (tmp / "runtime" / "executor").mkdir(parents=True)
    (tmp / "runtime" / "graph").mkdir(parents=True)
    (tmp / "AGENTS.md").write_text("# AGENTS stub", encoding="utf-8")
    return tmp


class TestEventIntegrity(unittest.TestCase):
    def test_events_have_required_fields_and_ids(self):
        root = _make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        
        rt.mission_create("Event test", custom_id="M-EV")
        rt.mission_checkpoint("M-EV")
        
        events_file = root / "state" / "missions" / "M-EV" / "events.jsonl"
        lines = events_file.read_text(encoding="utf-8").strip().split("\n")
        # mission_created, SEC_SCOPE_MISSING (scope verdict),
        # SEC_AUTH_INVALID (authorization issuance verdict), checkpoint_saved.
        # Assert presence (not brittle exact count) plus field integrity.
        kinds = [json.loads(line)["event"] for line in lines]
        for expected in ("mission_created", "checkpoint_saved"):
            self.assertIn(expected, kinds)
        self.assertTrue(any(k.startswith("SEC_") for k in kinds))
        
        event_ids = set()
        for line in lines:
            event = json.loads(line)
            self.assertIn("event_id", event)
            self.assertIn("timestamp", event)
            self.assertEqual(event["mission"], "M-EV")
            self.assertIn("event", event)
            self.assertIn("data", event)
            self.assertEqual(event["_schema"], "event_v1")
            
            # Ensure unique IDs
            self.assertNotIn(event["event_id"], event_ids)
            event_ids.add(event["event_id"])
            
        shutil.rmtree(root, ignore_errors=True)


class TestSchemaValidation(unittest.TestCase):
    def test_unknown_schema_version_fails_closed(self):
        root = _make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        
        rt.mission_create("Schema test", custom_id="M-SCH")
        state_file = root / "state" / "missions" / "M-SCH" / "state.json"
        
        # Corrupt schema manually
        state = json.loads(state_file.read_text(encoding="utf-8"))
        state["_schema"] = "mission_state_v99"
        state_file.write_text(json.dumps(state), encoding="utf-8")
        
        # Attempt to load
        with self.assertRaises(ValueError) as ctx:
            rt.mission_get("M-SCH")
        self.assertIn("Unknown schema version", str(ctx.exception))
        
        shutil.rmtree(root, ignore_errors=True)

    def test_missing_required_fields_fails_closed(self):
        root = _make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        
        rt.mission_create("Schema test 2", custom_id="M-SCH2")
        state_file = root / "state" / "missions" / "M-SCH2" / "state.json"
        
        # Remove required field manually
        state = json.loads(state_file.read_text(encoding="utf-8"))
        del state["operator_objective"]
        state_file.write_text(json.dumps(state), encoding="utf-8")
        
        with self.assertRaises(ValueError) as ctx:
            rt.mission_get("M-SCH2")
        self.assertIn("missing 'operator_objective'", str(ctx.exception))
        
        shutil.rmtree(root, ignore_errors=True)


class TestRecoveryAndFallback(unittest.TestCase):
    def test_corrupt_capsule_falls_back_to_authoritative_state(self):
        root = _make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        
        rt.mission_create("Fallback test", custom_id="M-FB")
        rt.mission_checkpoint("M-FB")
        
        capsule_file = root / "state" / "missions" / "M-FB" / "resume_capsule.json"
        
        # Corrupt it
        capsule_file.write_text("{ broken: ", encoding="utf-8")
        
        # Should gracefully rebuild
        capsule = rt.mission_resume("M-FB")
        self.assertEqual(capsule["mission_id"], "M-FB")
        # Phase A: integrity-sealed schema (v2) after corruption rebuild.
        self.assertEqual(capsule["_schema"], "resume_capsule_v2")
        self.assertTrue(capsule.get("integrity_digest"))
        
        # Check event log to see if it logged the fallback
        events_file = root / "state" / "missions" / "M-FB" / "events.jsonl"
        lines = events_file.read_text(encoding="utf-8").strip().split("\n")
        # create, checkpoint, fallback-resume, checkpoint, scope-revalidation...
        # locate the fallback mission_resumed event explicitly.
        fallback_events = [
            json.loads(line) for line in lines
            if json.loads(line)["event"] == "mission_resumed"
            and json.loads(line)["data"].get("fallback_to_state")
        ]
        self.assertTrue(fallback_events, "fallback mission_resumed event missing")
        fallback_event = fallback_events[0]
        self.assertEqual(fallback_event["event"], "mission_resumed")
        self.assertTrue(fallback_event["data"].get("fallback_to_state"))
        
        shutil.rmtree(root, ignore_errors=True)
        
    def test_stale_active_pointer(self):
        root = _make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        
        # Fake a stale active.json
        active_file = root / "state" / "missions" / "active.json"
        active_file.parent.mkdir(parents=True, exist_ok=True)
        active_file.write_text(json.dumps({"mission_id": "M-GHOST", "updated_at": "xxx"}))
        
        # Runtime should not crash, and should report NONE for active mission
        self.assertIsNone(rt.health()["active_mission"])
        
        shutil.rmtree(root, ignore_errors=True)


class TestMissionIsolation(unittest.TestCase):
    def test_no_cross_contamination(self):
        root = _make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        
        rt.mission_create("Obj A", custom_id="M-A")
        rt._mission_manager.update_mission("M-A", {"current_mode": "MAPPING"})
        
        rt.mission_create("Obj B", custom_id="M-B")
        rt._mission_manager.update_mission("M-B", {"current_mode": "RECON"})
        
        state_a = rt.mission_get("M-A")
        state_b = rt.mission_get("M-B")
        
        self.assertEqual(state_a["current_mode"], "MAPPING")
        self.assertEqual(state_b["current_mode"], "RECON")
        
        # Check active pointer is updated to the latest
        self.assertEqual(rt.health()["active_mission"], "M-B")
        
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
