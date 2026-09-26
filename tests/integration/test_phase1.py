"""
Phase 1 Integration Tests

Tests required by IMPLEMENTATION_INSTRUCTIONS.md §9:

  Test 1 — Runtime starts without exceptions.
  Test 2 — State directories exist after initialization.
  Test 3 — Adapter connection (CLI adapter reaches the runtime).
  Test 4 — 'hi' produces the hunter handshake.
  Test 5 — 'hunter status' returns real subsystem health.
  Test 6 — Failure visibility: disabling a subsystem causes status to show ERROR/UNAVAILABLE, not READY.
  Test 7 — Restart: persistent state survives a runtime restart.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure project root is on path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from runtime.bootstrap import HunterRuntime
from runtime.memory.persistence import PersistenceManager


def _make_isolated_root() -> Path:
    """
    Create a temporary isolated project root for each test.
    Copies the essential hunter/ constitution files so stubs can find them.
    """
    tmp = Path(tempfile.mkdtemp(prefix="ai-hunter-test-"))

    # Create hunter/ constitution files (needed by brain/scope stubs)
    hunter_dir = tmp / "hunter"
    hunter_dir.mkdir(parents=True)
    (hunter_dir / "brain.md").write_text("# Brain stub for testing", encoding="utf-8")
    (hunter_dir / "policy.md").write_text("# Policy stub for testing", encoding="utf-8")

    # Create runtime directories needed by executor/graph stubs
    (tmp / "runtime" / "executor").mkdir(parents=True)
    (tmp / "runtime" / "graph").mkdir(parents=True)

    # Create AGENTS.md so _find_project_root() finds the root
    (tmp / "AGENTS.md").write_text("# Hunter AGENTS", encoding="utf-8")

    return tmp


class TestPhase1RuntimeStarts(unittest.TestCase):
    """Test 1: Runtime starts without exceptions."""

    def test_runtime_starts_cleanly(self):
        root = _make_isolated_root()
        try:
            runtime = HunterRuntime(project_root=root)
            result = runtime.start()
            self.assertTrue(result, "HunterRuntime.start() should return True")
            self.assertTrue(runtime.is_running, "runtime.is_running should be True after start()")
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_runtime_start_returns_false_on_unwritable_root(self):
        """
        Runtime must not silently succeed when it cannot write state.

        Strategy: use a regular FILE as the project root.
        mkdir() inside a file always fails on all platforms.
        """
        import tempfile
        # Create a real temp file, then use it as the "root" (not a dir)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".not-a-dir") as fh:
            fake_root = Path(fh.name)
        try:
            runtime = HunterRuntime(project_root=fake_root)
            result = runtime.start()
            self.assertFalse(result, "Runtime should fail when root is a file, not a directory")
            self.assertFalse(runtime.is_running)
        finally:
            fake_root.unlink(missing_ok=True)


class TestPhase1StateDirectories(unittest.TestCase):
    """Test 2: Required state directories exist after initialization."""

    REQUIRED = [
        "state/missions",
        "state/global",
        "workspace/raw",
        "workspace/evidence",
        "workspace/artifacts",
        "workspace/logs",
        "workspace/reports",
    ]

    def test_all_required_directories_created(self):
        root = _make_isolated_root()
        try:
            runtime = HunterRuntime(project_root=root)
            self.assertTrue(runtime.start())
            for rel in self.REQUIRED:
                path = root / rel
                self.assertTrue(
                    path.is_dir(),
                    f"Required directory missing after init: {rel}",
                )
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_directories_are_writable(self):
        root = _make_isolated_root()
        try:
            runtime = HunterRuntime(project_root=root)
            self.assertTrue(runtime.start())
            for rel in self.REQUIRED:
                path = root / rel
                probe = path / ".write_test"
                probe.write_text("ok", encoding="utf-8")
                self.assertTrue(probe.is_file(), f"Directory not writable: {rel}")
                probe.unlink()
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)


class TestPhase1AdapterConnection(unittest.TestCase):
    """Test 3: The CLI adapter successfully reaches the runtime."""

    def test_adapter_can_reach_runtime(self):
        """Verify the adapter dispatch function can reach the runtime after start()."""
        from runtime.adapter.cli import _dispatch
        root = _make_isolated_root()
        try:
            runtime = HunterRuntime(project_root=root)
            self.assertTrue(runtime.start())
            # If dispatch works without exception, adapter is connected to runtime
            response = _dispatch(runtime, "hunter status")
            self.assertIsNotNone(response)
            self.assertIn("Hunter:", response)
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)


class TestPhase1Handshake(unittest.TestCase):
    """Test 4: 'hi' produces the hunter handshake."""

    def test_hi_returns_hunter_online(self):
        root = _make_isolated_root()
        try:
            runtime = HunterRuntime(project_root=root)
            runtime.start()
            response = runtime.handshake()
            self.assertIn("Hunter online.", response)
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_hi_contains_runtime_section(self):
        root = _make_isolated_root()
        try:
            runtime = HunterRuntime(project_root=root)
            runtime.start()
            response = runtime.handshake()
            self.assertIn("Runtime:", response)
            self.assertIn("Brain", response)
            self.assertIn("Memory", response)
            self.assertIn("Scope", response)
            self.assertIn("Executor", response)
            self.assertIn("Graph", response)
            self.assertIn("Checkpoints", response)
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_hi_contains_mission_section(self):
        root = _make_isolated_root()
        try:
            runtime = HunterRuntime(project_root=root)
            runtime.start()
            response = runtime.handshake()
            self.assertIn("Mission:", response)
            self.assertIn("NONE", response)  # No active mission in Phase 1
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_hi_does_not_contain_hardcoded_all_ready(self):
        """
        CRITICAL: The handshake must NOT be a hardcoded string.
        We verify this by checking that when the executor dir is missing,
        the status changes accordingly (not stuck at READY).
        """
        root = _make_isolated_root()
        try:
            # Remove executor dir to force UNAVAILABLE
            import shutil
            shutil.rmtree(root / "runtime" / "executor", ignore_errors=True)
            runtime = HunterRuntime(project_root=root)
            runtime.start()
            response = runtime.handshake()
            # Executor should NOT show READY since its directory is gone
            # The response must contain UNAVAILABLE or ERROR for executor
            self.assertNotRegex(
                response,
                r"Executor\s+READY",
                "Executor should not be READY when its directory is missing",
            )
        finally:
            shutil.rmtree(root, ignore_errors=True)


class TestPhase1Status(unittest.TestCase):
    """Test 5: 'hunter status' returns real subsystem health."""

    def test_status_shows_online_when_ready(self):
        root = _make_isolated_root()
        try:
            runtime = HunterRuntime(project_root=root)
            runtime.start()
            report = runtime.status_report()
            self.assertIn("Hunter: ONLINE", report)
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_status_shows_offline_when_not_started(self):
        root = _make_isolated_root()
        try:
            runtime = HunterRuntime(project_root=root)
            # Do NOT call start()
            report = runtime.status_report()
            self.assertIn("OFFLINE", report)
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_status_contains_all_subsystems(self):
        root = _make_isolated_root()
        try:
            runtime = HunterRuntime(project_root=root)
            runtime.start()
            report = runtime.status_report()
            for item in ["Brain:", "Persistent memory:", "Scope gate:", "Executor:", "Security graph:", "Checkpoint engine:"]:
                self.assertIn(item, report, f"Status missing: {item}")
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)


class TestPhase1FailureVisibility(unittest.TestCase):
    """Test 6: Breaking a subsystem causes status to show failure, not READY."""

    def test_broken_brain_shows_unavailable(self):
        root = _make_isolated_root()
        try:
            import shutil
            # Remove brain.md to break the brain stub
            (root / "hunter" / "brain.md").unlink()
            runtime = HunterRuntime(project_root=root)
            runtime.start()
            h = runtime.health()
            self.assertNotEqual(
                h["subsystems"]["brain"], "READY",
                "Brain should not be READY when brain.md is missing",
            )
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_broken_executor_shows_unavailable(self):
        root = _make_isolated_root()
        try:
            import shutil
            shutil.rmtree(root / "runtime" / "executor")
            runtime = HunterRuntime(project_root=root)
            runtime.start()
            h = runtime.health()
            self.assertNotEqual(
                h["subsystems"]["executor"], "READY",
                "Executor should not be READY when its directory is missing",
            )
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_broken_scope_shows_unavailable(self):
        root = _make_isolated_root()
        try:
            import shutil
            (root / "hunter" / "policy.md").unlink()
            runtime = HunterRuntime(project_root=root)
            runtime.start()
            h = runtime.health()
            self.assertNotEqual(
                h["subsystems"]["scope"], "READY",
                "Scope should not be READY when policy.md is missing",
            )
        finally:
            shutil.rmtree(root, ignore_errors=True)


class TestPhase1PersistenceAndRestart(unittest.TestCase):
    """Test 7: Persistent state survives a runtime restart."""

    def test_event_log_persists_across_restarts(self):
        root = _make_isolated_root()
        try:
            # First boot
            runtime1 = HunterRuntime(project_root=root)
            runtime1.start()
            runtime1.handshake()
            runtime1.status_report()

            log_path = root / "workspace" / "logs" / "runtime.jsonl"
            self.assertTrue(log_path.is_file(), "Event log should exist after first boot")

            lines_after_first_boot = log_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertGreater(len(lines_after_first_boot), 0, "Event log should have entries")

            # Second boot (simulating restart)
            runtime2 = HunterRuntime(project_root=root)
            runtime2.start()
            runtime2.handshake()

            lines_after_restart = log_path.read_text(encoding="utf-8").strip().splitlines()
            # Log must have MORE entries after the second boot (append-only)
            self.assertGreater(
                len(lines_after_restart),
                len(lines_after_first_boot),
                "Event log should grow on restart (append-only)",
            )
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_event_log_entries_are_valid_json(self):
        root = _make_isolated_root()
        try:
            runtime = HunterRuntime(project_root=root)
            runtime.start()
            runtime.handshake()
            runtime.status_report()

            log_path = root / "workspace" / "logs" / "runtime.jsonl"
            for line in log_path.read_text(encoding="utf-8").strip().splitlines():
                try:
                    entry = json.loads(line)
                    self.assertIn("event", entry)
                    self.assertIn("timestamp", entry)
                    self.assertIn("_schema", entry)
                except json.JSONDecodeError as e:
                    self.fail(f"Event log contains invalid JSON: {e}\nLine: {line}")
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_state_directories_persist_after_restart(self):
        root = _make_isolated_root()
        try:
            runtime1 = HunterRuntime(project_root=root)
            runtime1.start()

            # Second boot should not fail even if dirs already exist
            runtime2 = HunterRuntime(project_root=root)
            result = runtime2.start()
            self.assertTrue(result, "Runtime should start successfully when directories already exist")
            self.assertTrue(runtime2.is_running)
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
