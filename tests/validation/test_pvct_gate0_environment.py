"""
Tests for Gate 0 — Environment Readiness.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from runtime.validation.environment import EnvironmentReadinessAuditor
from runtime.validation.models import GateId, GateStatus
from runtime.validation.persistence import ValidationPersistenceManager


class TestPVCTGate0Environment(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.tmp_path = Path(self.tmp_dir)

        # Create minimal required files
        hunter_dir = self.tmp_path / "hunter"
        hunter_dir.mkdir(parents=True, exist_ok=True)
        (hunter_dir / "policy.md").write_text("# Policy\nAllowed targets: 127.0.0.1\n", encoding="utf-8")
        (hunter_dir / "brain.md").write_text("# Brain\n", encoding="utf-8")
        (hunter_dir / "schemas.md").write_text("# Schemas\n", encoding="utf-8")
        (self.tmp_path / "AGENTS.md").write_text("# Agents\n", encoding="utf-8")

        adapter_dir = self.tmp_path / "runtime" / "adapter"
        adapter_dir.mkdir(parents=True, exist_ok=True)
        (adapter_dir / "mcp_server.py").write_text("# MCP Server stub\n", encoding="utf-8")

        self.pm = ValidationPersistenceManager(self.tmp_path)
        self.auditor = EnvironmentReadinessAuditor(self.pm)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_gate0_generates_all_four_manifests(self):
        """1. Gate 0 creates environment_manifest, configuration_snapshot, connectivity_result, readiness_report."""
        run_id = "VRUN-G0-TEST"
        gate, evidence = self.auditor.audit_environment(run_id)

        env_dir = self.pm.environments_dir / run_id
        self.assertTrue((env_dir / "environment_manifest.json").exists())
        self.assertTrue((env_dir / "configuration_snapshot.json").exists())
        self.assertTrue((env_dir / "connectivity_result.json").exists())
        self.assertTrue((env_dir / "readiness_report.json").exists())

        self.assertEqual(gate.gate_id, GateId.GATE_0)
        self.assertEqual(gate.status, GateStatus.PASSED)
        self.assertEqual(len(evidence), 2)

    def test_02_gate0_fails_on_missing_mandatory_file(self):
        """2. Gate 0 fails if a required file like AGENTS.md is deleted."""
        (self.tmp_path / "AGENTS.md").unlink()
        run_id = "VRUN-G0-FAIL"
        gate, evidence = self.auditor.audit_environment(run_id)

        self.assertEqual(gate.status, GateStatus.FAILED)
        self.assertTrue(len(gate.blockers) > 0)
        self.assertTrue(any("AGENTS.md" in b for b in gate.blockers))


if __name__ == "__main__":
    unittest.main()
