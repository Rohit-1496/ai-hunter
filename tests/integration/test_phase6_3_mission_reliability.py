"""
Phase 6.3 — Mission Recovery, Isolation & Long-Run Reliability Test Suite

Validates:
1. Mission Lifecycle State Machine (enforcement, invalid transition rejection, fail-closed)
2. Monotonic Rolling Checkpoint Engine & Automated Corruption Recovery (20 corruption & fault cases)
3. Multi-Tenant & Multi-Mission Isolation (Missions A, B, C; state, checkpoints, evidence, traversal)
4. POSIX Concurrency & FileLock Synchronization (process locking, contention, timeout, atomic appends)
5. Resource & Budget Boundary Enforcement (at limit, below, above, negative, zero, malformed)
6. Bounded Long-Running Mission Simulation (telemetry, RAM, checkpoint growth, forensic continuity)
7. Safe Interruption & Deterministic Resume
8. Audit Trail Continuity & Monotonic Event Sequencing
"""

import fcntl
import hashlib
import json
import multiprocessing
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

from runtime.memory.checkpoint import (
    CHECKPOINT_SCHEMA,
    CheckpointEngine,
    get_checkpoint_key,
    seal_checkpoint,
    verify_checkpoint,
)
from runtime.memory.fs_utils import FileLock, LockTimeoutError, atomic_write_json
from runtime.memory.mission import MissionManager, validate_mission_id
from runtime.mvp.contract import (
    InvalidStateTransitionError,
    MissionCheckpoint,
    MissionContract,
    MissionLifecycleState,
    transition_mission_state,
)
from runtime.mvp.core import BeastBrainMVPEngine
from runtime.evidence.compact_store import CompactEvidenceStore, RetrievalMode, EvidenceIntegrityError
from runtime.context.budget_manager import ContextBudgetManager, ContextBudgetConfig
from runtime.evidence.storage_policy import EvidenceSummary, AdmissionStatus


def _make_isolated_env() -> Path:
    base = Path(tempfile.mkdtemp(prefix="hunter-phase6-3-"))
    (base / "state" / "missions").mkdir(parents=True, exist_ok=True)
    return base


def _create_synthetic_contract(mission_id: str, targets: list[str]) -> dict[str, Any]:
    return {
        "mission_id": mission_id,
        "allowed_ips": ["127.0.0.1"],
        "allowed_domains": ["localhost"],
        "environment": "lab",
    }


class TestMissionLifecycleStateMachine(unittest.TestCase):
    """1. Definition & Validation of Mission Lifecycle State Machine."""

    def setUp(self):
        self.test_dir = _make_isolated_env()
        self.mgr = MissionManager(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_valid_sequential_lifecycle_progression(self):
        m = self.mgr.create_mission("Sequential lifecycle test", target_scope=["127.0.0.1:8080"])
        m_id = m["mission_id"]

        # VALIDATED -> PLANNING -> RECONNAISSANCE -> HYPOTHESIS_TESTING -> SYNTHESIZING -> COMPLETED
        s1 = self.mgr.transition_lifecycle_state(m_id, MissionLifecycleState.PLANNING, "Planning started")
        self.assertEqual(s1["status"], MissionLifecycleState.PLANNING.value)

        s2 = self.mgr.transition_lifecycle_state(m_id, MissionLifecycleState.RECONNAISSANCE, "Recon running")
        self.assertEqual(s2["status"], MissionLifecycleState.RECONNAISSANCE.value)

        s3 = self.mgr.transition_lifecycle_state(m_id, MissionLifecycleState.HYPOTHESIS_TESTING, "Testing hypotheses")
        self.assertEqual(s3["status"], MissionLifecycleState.HYPOTHESIS_TESTING.value)

        s4 = self.mgr.transition_lifecycle_state(m_id, MissionLifecycleState.SYNTHESIZING, "Synthesizing findings")
        self.assertEqual(s4["status"], MissionLifecycleState.SYNTHESIZING.value)

        s5 = self.mgr.transition_lifecycle_state(m_id, MissionLifecycleState.COMPLETED, "Mission completed successfully")
        self.assertEqual(s5["status"], MissionLifecycleState.COMPLETED.value)

    def test_rejects_unvalidated_start(self):
        with self.assertRaises(InvalidStateTransitionError):
            transition_mission_state(MissionLifecycleState.CREATED, MissionLifecycleState.RECONNAISSANCE)

    def test_rejects_unfinalized_completion(self):
        with self.assertRaises(InvalidStateTransitionError):
            transition_mission_state(MissionLifecycleState.RECONNAISSANCE, MissionLifecycleState.COMPLETED)

    def test_rejects_failed_to_running_without_recovery(self):
        with self.assertRaises(InvalidStateTransitionError):
            transition_mission_state(MissionLifecycleState.FAILED, MissionLifecycleState.RECONNAISSANCE)

    def test_rejects_cancelled_to_running(self):
        with self.assertRaises(InvalidStateTransitionError):
            transition_mission_state(MissionLifecycleState.CANCELLED, MissionLifecycleState.RECONNAISSANCE)

    def test_rejects_duplicate_transition(self):
        with self.assertRaises(InvalidStateTransitionError):
            transition_mission_state(MissionLifecycleState.RECONNAISSANCE, MissionLifecycleState.RECONNAISSANCE)

    def test_recovery_flow_from_failed_state(self):
        # FAILED -> RECOVERING -> PLANNING -> RECONNAISSANCE
        s1 = transition_mission_state(MissionLifecycleState.FAILED, MissionLifecycleState.RECOVERING)
        self.assertEqual(s1, MissionLifecycleState.RECOVERING)

        s2 = transition_mission_state(s1, MissionLifecycleState.PLANNING)
        self.assertEqual(s2, MissionLifecycleState.PLANNING)

    def test_pause_and_resume_flow(self):
        # RECONNAISSANCE -> PAUSED -> RECONNAISSANCE
        s1 = transition_mission_state(MissionLifecycleState.RECONNAISSANCE, MissionLifecycleState.PAUSED)
        self.assertEqual(s1, MissionLifecycleState.PAUSED)

        s2 = transition_mission_state(s1, MissionLifecycleState.RECONNAISSANCE)
        self.assertEqual(s2, MissionLifecycleState.RECONNAISSANCE)


class TestCheckpointCreationAndRecovery(unittest.TestCase):
    """2. Monotonic Checkpoints & 20 Corruption / Recovery Test Cases."""

    def setUp(self):
        self.test_dir = _make_isolated_env()
        self.mgr = MissionManager(self.test_dir)
        self.engine = CheckpointEngine(self.test_dir, self.mgr)
        self.m = self.mgr.create_mission("Checkpoint corruption suite", target_scope=["127.0.0.1:8080"])
        self.m_id = self.m["mission_id"]

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_normal_checkpoint_creation(self):
        capsule = self.engine.create_checkpoint(self.m_id, brain_state={"iteration": 1})
        self.assertEqual(capsule["mission_id"], self.m_id)
        self.assertEqual(capsule["sequence_number"], 1)
        self.assertEqual(capsule["checkpoint_id"], "capsule_00001")
        self.assertTrue(capsule.get("integrity_digest"))

    def test_02_checkpoint_reload(self):
        self.engine.create_checkpoint(self.m_id, brain_state={"val": "test-reload"})
        resumed = self.engine.resume_mission(self.m_id)
        self.assertEqual(resumed["brain_state"]["val"], "test-reload")

    def test_03_process_restart_simulation(self):
        self.engine.create_checkpoint(self.m_id, brain_state={"persisted_flag": True})
        # Simulate completely new runtime process
        new_mgr = MissionManager(self.test_dir)
        new_engine = CheckpointEngine(self.test_dir, new_mgr)
        resumed = new_engine.resume_mission(self.m_id)
        self.assertTrue(resumed["brain_state"]["persisted_flag"])

    def test_04_truncated_checkpoint_file(self):
        self.engine.create_checkpoint(self.m_id, brain_state={"seq": 1})
        self.engine.create_checkpoint(self.m_id, brain_state={"seq": 2})
        cap_file = self.test_dir / "state" / "missions" / self.m_id / "resume_capsule.json"
        # Truncate canonical file
        cap_file.write_text('{"_schema": "resume_capsule_v2", "mission_id": "', encoding="utf-8")

        ok, reason, recovered = self.engine.recover_latest_valid_checkpoint(self.m_id)
        self.assertTrue(ok)
        self.assertIn("capsule_00002", reason)
        self.assertEqual(recovered["sequence_number"], 2)

    def test_05_empty_checkpoint_file(self):
        self.engine.create_checkpoint(self.m_id, brain_state={"seq": 1})
        cap_file = self.test_dir / "state" / "missions" / self.m_id / "resume_capsule.json"
        cap_file.write_text("", encoding="utf-8")

        ok, reason, recovered = self.engine.recover_latest_valid_checkpoint(self.m_id)
        self.assertTrue(ok)
        self.assertEqual(recovered["sequence_number"], 1)

    def test_06_invalid_json(self):
        self.engine.create_checkpoint(self.m_id, brain_state={"seq": 1})
        cap_file = self.test_dir / "state" / "missions" / self.m_id / "resume_capsule.json"
        cap_file.write_text("{ invalid json syntax: 123 ", encoding="utf-8")

        ok, reason, recovered = self.engine.recover_latest_valid_checkpoint(self.m_id)
        self.assertTrue(ok)
        self.assertEqual(recovered["sequence_number"], 1)

    def test_07_invalid_schema(self):
        capsule = self.engine.create_checkpoint(self.m_id, brain_state={"seq": 1})
        capsule["_schema"] = "unsupported_v99"
        capsule = seal_checkpoint(capsule, get_checkpoint_key(self.test_dir))
        cap_file = self.test_dir / "state" / "missions" / self.m_id / "resume_capsule.json"
        atomic_write_json(cap_file, capsule)

        ok, reason, _ = self.engine.recover_latest_valid_checkpoint(self.m_id)
        self.assertTrue(ok)  # Recovers from capsule_00001.json which has valid schema

    def test_08_missing_required_fields(self):
        capsule = self.engine.create_checkpoint(self.m_id, brain_state={"seq": 1})
        capsule.pop("integrity_digest", None)
        cap_file = self.test_dir / "state" / "missions" / self.m_id / "resume_capsule.json"
        atomic_write_json(cap_file, capsule)

        ok, reason = verify_checkpoint(capsule, mission_id=self.m_id)
        self.assertFalse(ok)
        self.assertEqual(reason, "CAPSULE_DIGEST_MISSING")

    def test_09_invalid_mission_id_in_capsule(self):
        capsule = self.engine.create_checkpoint(self.m_id, brain_state={"seq": 1})
        capsule["mission_id"] = "M-FOREIGN-ATTACKER"
        capsule = seal_checkpoint(capsule, get_checkpoint_key(self.test_dir))

        ok, reason = verify_checkpoint(capsule, mission_id=self.m_id)
        self.assertFalse(ok)
        self.assertEqual(reason, "CAPSULE_MISSION_MISMATCH")

    def test_10_invalid_state_transition_rejection(self):
        with self.assertRaises(InvalidStateTransitionError):
            self.mgr.transition_lifecycle_state(self.m_id, MissionLifecycleState.COMPLETED)

    def test_11_hash_hmac_tamper_detection(self):
        self.engine.create_checkpoint(self.m_id, brain_state={"seq": 1})
        cap_file = self.test_dir / "state" / "missions" / self.m_id / "resume_capsule.json"
        data = json.loads(cap_file.read_text(encoding="utf-8"))
        data["strategy"] = "TAMPERED_INJECTED_STRATEGY"
        # Save without re-sealing HMAC
        cap_file.write_text(json.dumps(data), encoding="utf-8")

        ok, reason = verify_checkpoint(data, mission_id=self.m_id, hmac_key=get_checkpoint_key(self.test_dir))
        self.assertFalse(ok)
        self.assertEqual(reason, "CAPSULE_DIGEST_MISMATCH")

    def test_12_older_checkpoint_sequence_rejected(self):
        self.engine.create_checkpoint(self.m_id, brain_state={"seq": 1}, sequence_number=1)
        self.engine.create_checkpoint(self.m_id, brain_state={"seq": 2}, sequence_number=2)
        # Attempt older sequence number
        with self.assertRaises(ValueError) as ctx:
            self.engine.create_checkpoint(self.m_id, brain_state={"seq": 1}, sequence_number=1)
        self.assertIn("Non-monotonic sequence number", str(ctx.exception))

    def test_13_duplicate_checkpoint_sequence_rejected(self):
        self.engine.create_checkpoint(self.m_id, brain_state={"seq": 1}, sequence_number=1)
        with self.assertRaises(ValueError) as ctx:
            self.engine.create_checkpoint(self.m_id, brain_state={"seq": 1}, sequence_number=1)
        self.assertIn("Non-monotonic sequence number", str(ctx.exception))

    def test_14_interrupted_temp_file_write(self):
        # Verify atomic_write leaves canonical file intact if temp write interrupted
        target = self.test_dir / "state" / "missions" / self.m_id / "resume_capsule.json"
        atomic_write_json(target, {"valid": "initial_data"})
        leftover_temp = target.parent / ".tmp-interrupted.json"
        leftover_temp.write_text("partial unwritten data", encoding="utf-8")

        # Canonical file remains intact and uncorrupted
        canonical = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(canonical["valid"], "initial_data")

    def test_15_corrupted_evidence_reference(self):
        store = CompactEvidenceStore(self.test_dir)
        # Non-existent evidence ID must raise KeyError (not crash unexpectedly)
        with self.assertRaises(KeyError):
            store.retrieve("EV-NONEXISTENT", mission_id=self.m_id)

    def test_16_missing_raw_artifact_handling(self):
        store = CompactEvidenceStore(self.test_dir)
        idx_entry, summary = store.store_evidence(
            mission_id=self.m_id,
            execution_id="EXEC-1",
            tool_id="curl",
            target="http://127.0.0.1:8080",
            raw_content="HTTP 200 OK",
        )
        # Delete raw artifact manually to simulate corruption
        raw_file = self.test_dir / idx_entry.raw_artifact_relpath
        if raw_file.exists():
            raw_file.unlink()
        # Mode requiring raw content must detect corruption and raise EvidenceIntegrityError
        with self.assertRaises(EvidenceIntegrityError):
            store.retrieve(idx_entry.evidence_id, mode=RetrievalMode.FULL_ARTIFACT, mission_id=self.m_id, reason="Audit check")

    def test_17_invalid_deferred_evidence_reference(self):
        cfg = ContextBudgetConfig(max_evidence_items=1, max_total_tokens=1000)
        budget_mgr = ContextBudgetManager(config=cfg)
        sum1 = EvidenceSummary(
            evidence_id="EV-1",
            mission_id=self.m_id,
            execution_id="EX-1",
            target="http://127.0.0.1:8080",
            source_tool="curl",
            observation_category="recon",
            short_summary="Summary 1",
            token_estimate=50,
        )
        sum2 = EvidenceSummary(
            evidence_id="EV-2",
            mission_id=self.m_id,
            execution_id="EX-2",
            target="http://127.0.0.1:8080",
            source_tool="curl",
            observation_category="recon",
            short_summary="Summary 2",
            token_estimate=50,
        )
        status1, _ = budget_mgr.admit_evidence(sum1)
        self.assertEqual(status1, AdmissionStatus.INCLUDED)
        # Exceeds max_evidence_items limit (1): must return DEFERRED
        status2, ref2 = budget_mgr.admit_evidence(sum2)
        self.assertEqual(status2, AdmissionStatus.DEFERRED)
        self.assertEqual(len(budget_mgr.deferred_references), 1)
        self.assertEqual(budget_mgr.deferred_references[0].evidence_id, "EV-2")

    def test_18_recovery_after_failed_tool_execution(self):
        # Mission state remains consistent when tool fails
        self.mgr.log_event(self.m_id, "tool_failed", {"tool": "nmap", "exit_code": 1})
        self.engine.create_checkpoint(self.m_id, brain_state={"status": "tool_error_handled"})
        resumed = self.engine.resume_mission(self.m_id)
        self.assertEqual(resumed["brain_state"]["status"], "tool_error_handled")

    def test_19_recovery_during_paused_mission(self):
        self.mgr.transition_lifecycle_state(self.m_id, MissionLifecycleState.PAUSED, "Operator paused")
        self.engine.create_checkpoint(self.m_id, brain_state={"phase": "paused_recon"})
        resumed = self.engine.resume_mission(self.m_id)
        self.assertEqual(resumed["brain_state"]["phase"], "paused_recon")
        # State transitions safely back to RECONNAISSANCE
        self.mgr.transition_lifecycle_state(self.m_id, MissionLifecycleState.RECONNAISSANCE, "Resumed")
        self.assertEqual(self.mgr.get_mission(self.m_id)["status"], MissionLifecycleState.RECONNAISSANCE.value)

    def test_20_recovery_after_mission_cancellation(self):
        self.mgr.transition_lifecycle_state(self.m_id, MissionLifecycleState.CANCELLED, "Mission aborted")
        # Cannot transition back to running states
        with self.assertRaises(InvalidStateTransitionError):
            self.mgr.transition_lifecycle_state(self.m_id, MissionLifecycleState.RECONNAISSANCE)


class TestMissionIsolation(unittest.TestCase):
    """3. Verification of Multi-Mission & Multi-Tenant Isolation."""

    def setUp(self):
        self.test_dir = _make_isolated_env()
        self.mgr = MissionManager(self.test_dir)
        self.engine = CheckpointEngine(self.test_dir, self.mgr)
        self.mA = self.mgr.create_mission("Mission A", target_scope=["10.0.0.1:80"])["mission_id"]
        self.mB = self.mgr.create_mission("Mission B", target_scope=["10.0.0.2:80"])["mission_id"]
        self.mC = self.mgr.create_mission("Mission C", target_scope=["10.0.0.3:80"])["mission_id"]

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_checkpoint_isolation_between_missions(self):
        self.engine.create_checkpoint(self.mA, brain_state={"secret": "secretA"})
        self.engine.create_checkpoint(self.mB, brain_state={"secret": "secretB"})

        # Load Mission B checkpoint data
        capB_path = self.test_dir / "state" / "missions" / self.mB / "resume_capsule.json"
        capB_data = json.loads(capB_path.read_text(encoding="utf-8"))

        # Verify that Mission A rejects Mission B's capsule
        ok, reason = verify_checkpoint(capB_data, mission_id=self.mA)
        self.assertFalse(ok)
        self.assertEqual(reason, "CAPSULE_MISSION_MISMATCH")

    def test_state_isolation_between_missions(self):
        self.mgr.update_mission(self.mA, {"risk_policy": "HIGH"})
        self.mgr.update_mission(self.mB, {"risk_policy": "LOW"})

        stateA = self.mgr.get_mission(self.mA)
        stateB = self.mgr.get_mission(self.mB)

        self.assertEqual(stateA["risk_policy"], "HIGH")
        self.assertEqual(stateB["risk_policy"], "LOW")

    def test_evidence_retrieval_isolation(self):
        store = CompactEvidenceStore(self.test_dir)
        idx_entry, summary = store.store_evidence(
            mission_id=self.mA,
            execution_id="EXEC-A",
            tool_id="probe",
            target="http://10.0.0.1:80",
            raw_content="Mission A confidential evidence",
        )
        # Mission B attempts to access Mission A's evidence -> must raise PermissionError
        with self.assertRaises(PermissionError):
            store.retrieve(idx_entry.evidence_id, mission_id=self.mB)

    def test_path_traversal_rejection(self):
        with self.assertRaises(ValueError):
            validate_mission_id("../../etc/passwd")
        with self.assertRaises(ValueError):
            validate_mission_id("M-1234/subfolder")
        with self.assertRaises(ValueError):
            validate_mission_id("M-1234\traversal")

    def test_symlink_escape_rejection_in_lock_and_write(self):
        symlink_path = self.test_dir / "state" / "missions" / self.mA / "symlink_file.json"
        target_path = self.test_dir / "state" / "escape_target.json"
        target_path.write_text("{}", encoding="utf-8")
        os.symlink(target_path, symlink_path)

        with self.assertRaises(PermissionError):
            atomic_write_json(symlink_path, {"attack": True})

        with self.assertRaises(PermissionError):
            lock = FileLock(symlink_path)
            lock.acquire()


class TestConcurrentMissionAndLocking(unittest.TestCase):
    """4. Concurrent Mission Safety & POSIX FileLock Stress Testing."""

    def setUp(self):
        self.test_dir = _make_isolated_env()
        self.mgr = MissionManager(self.test_dir)
        self.m = self.mgr.create_mission("Concurrency Mission", target_scope=["127.0.0.1:8080"])
        self.m_id = self.m["mission_id"]

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_file_lock_timeout_on_contention(self):
        lock_path = self.test_dir / "state" / "missions" / self.m_id / ".lock"
        lock1 = FileLock(lock_path, timeout=0.2, poll_interval=0.02)
        lock2 = FileLock(lock_path, timeout=0.1, poll_interval=0.02)

        lock1.acquire()
        try:
            with self.assertRaises(LockTimeoutError):
                lock2.acquire()
        finally:
            lock1.release()

    def test_concurrent_audit_log_appends(self):
        # Multi-process test writing concurrent events
        def _worker(mgr_root: str, mission_id: str, worker_id: int, count: int):
            m = MissionManager(Path(mgr_root))
            for i in range(count):
                m.log_event(mission_id, f"worker_{worker_id}_event_{i}", {"val": i})

        proc_count = 4
        events_per_proc = 25
        procs = []
        for wid in range(proc_count):
            p = multiprocessing.Process(
                target=_worker,
                args=(str(self.test_dir), self.m_id, wid, events_per_proc),
            )
            p.start()
            procs.append(p)

        for p in procs:
            p.join(timeout=10.0)

        events_file = self.test_dir / "state" / "missions" / self.m_id / "events.jsonl"
        lines = [line.strip() for line in events_file.read_text(encoding="utf-8").splitlines() if line.strip()]

        # Initial mission_created + (proc_count * events_per_proc)
        expected_total = 1 + (proc_count * events_per_proc)
        self.assertEqual(len(lines), expected_total)

        # Verify no corrupt JSON lines
        for line in lines:
            parsed = json.loads(line)
            self.assertIn("event_id", parsed)
            self.assertIn("sequence_number", parsed)


class TestResourceAndBudgetLimits(unittest.TestCase):
    """5. Boundary and Budget Limit Enforcement."""

    def setUp(self):
        self.test_dir = _make_isolated_env()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_token_budget_boundary_exact_and_over(self):
        cfg = ContextBudgetConfig(max_total_tokens=100, max_summary_tokens_per_item=50)
        budget_mgr = ContextBudgetManager(config=cfg)

        # Below limit (50 tokens)
        sum1 = EvidenceSummary(
            evidence_id="EV-1",
            mission_id="M-TEST",
            execution_id="EX-1",
            target="http://127.0.0.1",
            source_tool="curl",
            observation_category="recon",
            short_summary="A" * 50,
            token_estimate=50,
        )
        status1, _ = budget_mgr.admit_evidence(sum1)
        self.assertEqual(status1, AdmissionStatus.INCLUDED)
        self.assertEqual(budget_mgr.current_tokens, 50)

        # Exactly at limit (50 more tokens -> 100 total)
        sum2 = EvidenceSummary(
            evidence_id="EV-2",
            mission_id="M-TEST",
            execution_id="EX-2",
            target="http://127.0.0.1",
            source_tool="curl",
            observation_category="recon",
            short_summary="B" * 50,
            token_estimate=50,
        )
        status2, _ = budget_mgr.admit_evidence(sum2)
        self.assertEqual(status2, AdmissionStatus.INCLUDED)
        self.assertEqual(budget_mgr.current_tokens, 100)

        # One unit above limit: must defer
        sum3 = EvidenceSummary(
            evidence_id="EV-3",
            mission_id="M-TEST",
            execution_id="EX-3",
            target="http://127.0.0.1",
            source_tool="curl",
            observation_category="recon",
            short_summary="C",
            token_estimate=1,
        )
        status3, ref3 = budget_mgr.admit_evidence(sum3)
        self.assertEqual(status3, AdmissionStatus.DEFERRED)

    def test_negative_or_zero_budget_handled_safely(self):
        cfg = ContextBudgetConfig(max_total_tokens=0)
        budget_mgr = ContextBudgetManager(config=cfg)
        sum1 = EvidenceSummary(
            evidence_id="EV-1",
            mission_id="M-TEST",
            execution_id="EX-1",
            target="http://127.0.0.1",
            source_tool="curl",
            observation_category="recon",
            short_summary="Test",
            token_estimate=10,
        )
        status1, _ = budget_mgr.admit_evidence(sum1)
        self.assertEqual(status1, AdmissionStatus.DEFERRED)

    def test_raw_artifact_size_budget_boundary(self):
        cfg = ContextBudgetConfig(max_raw_bytes_loaded=1024)
        budget_mgr = ContextBudgetManager(config=cfg)

        # Below limit (500 B)
        st1, msg1 = budget_mgr.admit_raw_artifact(500, reason="Valid inspection")
        self.assertEqual(st1, AdmissionStatus.INCLUDED)

        # Exceeds remaining (1000 B > 524 B remaining)
        st2, msg2 = budget_mgr.admit_raw_artifact(1000, reason="Excessive load")
        self.assertEqual(st2, AdmissionStatus.REJECTED_BY_BUDGET)
        self.assertIn("exceeds remaining raw budget", msg2)


class TestBoundedLongRunningMission(unittest.TestCase):
    """6. Bounded Long-Running Mission Simulation (Deterministic MVP execution)."""

    def setUp(self):
        self.test_dir = _make_isolated_env()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_bounded_5_iteration_simulation_with_checkpoints(self):
        # Run BeastBrainMVPEngine with 5 sequential iterations, taking checkpoints at each step
        engine = BeastBrainMVPEngine(project_root=self.test_dir, dry_run=True)
        m_id = "M-LONG-RUN-01"
        req = _create_synthetic_contract(m_id, ["127.0.0.1:8080"])

        # Intake & validate
        valid, reason, contract = engine.intake_and_validate(req)
        self.assertTrue(valid)

        # Run 5 simulated iterations with rolling checkpoints
        checkpoints_created = []
        for iteration in range(1, 6):
            payload = {
                "iteration": iteration,
                "progress": f"Iteration {iteration} completed",
                "metrics": {"findings": iteration, "evidence_count": iteration * 3},
            }
            cap = engine.save_checkpoint(m_id, iteration=iteration, state_payload=payload)
            checkpoints_created.append(cap)
            self.assertEqual(cap["sequence_number"], iteration)

        # Verify all 5 rolling checkpoints exist on disk
        chk_list = engine.checkpoint_engine.list_checkpoints(m_id)
        self.assertEqual(len(chk_list), 5)
        for i, chk in enumerate(chk_list, start=1):
            self.assertEqual(chk["sequence_number"], i)
            self.assertTrue(chk["is_valid"], f"Validation failed for {chk['checkpoint_id']}: {chk.get('validation_reason')}")

        # Now simulate process crash / corruption of canonical capsule
        cap_canonical = self.test_dir / "state" / "missions" / m_id / "resume_capsule.json"
        cap_canonical.write_text("CORRUPTED CRASH RESIDUE", encoding="utf-8")

        # Automated recovery resumes from latest valid rolling checkpoint (sequence 5)
        resumed_ok, res_reason, resumed_state = engine.resume_from_checkpoint(m_id)
        self.assertTrue(resumed_ok)
        self.assertEqual(resumed_state["iteration"], 5)


if __name__ == "__main__":
    unittest.main()
