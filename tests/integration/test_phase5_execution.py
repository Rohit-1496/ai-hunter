import json
import shutil
import tempfile
import unittest
import threading
import time
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

from runtime.bootstrap import HunterRuntime
from runtime.brain.decision import CandidateAction
from runtime.capabilities.discovery import ToolDiscovery

class DummyTargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        
        # Emit something the Graph Ingester will catch
        self.wfile.write(b"Targeting endpoint /api/resource/100\n")
        self.wfile.write(b"USER_alice belongs to TENANT_corp\n")

    def log_message(self, format, *args):
        pass

class TestPhase5Execution(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start a local deterministic target
        cls.server = HTTPServer(('127.0.0.1', 0), DummyTargetHandler)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _make_isolated_root(self) -> Path:
        root = Path(tempfile.mkdtemp())
        (root / "hunter").mkdir()
        (root / "hunter" / "brain.md").write_text("Dummy constitution")
        (root / "hunter" / "policy.md").write_text("Dummy policy")
        return root

    def test_e2e_real_tool_execution(self):
        """End-to-End proof: Real curl process -> Evidence -> Graph -> Brain"""
        root = self._make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        
        # Verify curl is available in the environment. If not, skip test safely.
        tool = rt._capability_registry.get_tool("curl")
        if ToolDiscovery.check_availability(tool) == "UNAVAILABLE":
            self.skipTest("curl not installed, skipping real execution test")
            
        rt.mission_create("Phase 5 Real Execution", custom_id="M-P5-E2E", target_scope=["127.0.0.1"])
        
        # 1. Create a Candidate Action identifying the capability and input
        a1 = CandidateAction(
            id="A-REAL-1", 
            action_type="RECON", 
            objective="Phase 5 Real Execution",
            target=f"http://127.0.0.1:{self.port}",
            capability_id="HTTP_REQUEST",
            input_parameters={"url": f"http://127.0.0.1:{self.port}"},
            expected_information_gain=1.0, 
            expected_security_value=1.0,
            scope_alignment="IN_SCOPE"
        )
        rt.brain.state.candidate_actions[a1.id] = a1
        
        # 2. Step the mission.
        # This will select curl, plan it, execute real process, write raw to disk, extract, update graph.
        res = rt.step_mission("M-P5-E2E")
        
        self.assertEqual(res["status"], "STEP_COMPLETE", f"Step failed: {res.get('reason')}")
        self.assertEqual(res["observations_extracted"], 2)
        
        # 3. Verify Graph Update
        self.assertEqual(res["graph_nodes_added"], 3)
        
        # 4. Verify the raw evidence was truly written to disk, not injected as string.
        evidence_file = root / "workspace" / "raw" / "M-P5-E2E" / "execution" / f"{res['evidence_id']}.txt"
        self.assertTrue(evidence_file.is_file(), "Raw evidence file was not created on disk")
        content = evidence_file.read_text()
        self.assertIn("Targeting endpoint /api/resource/100", content)
        
        shutil.rmtree(root, ignore_errors=True)

    def test_safety_gate_blocking(self):
        root = self._make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        rt.mission_create("Safety Test", custom_id="M-SAFE")
        
        # Out of scope action
        a1 = CandidateAction(
            id="A-OUT", 
            action_type="RECON", 
            objective="Test",
            target="http://example.com",
            capability_id="HTTP_REQUEST",
            input_parameters={"url": "http://example.com"},
            scope_alignment="OUT_OF_SCOPE"
        )
        rt.brain.state.candidate_actions[a1.id] = a1
        
        res = rt.step_mission("M-SAFE")
        # The Brain correctly pre-filters OUT_OF_SCOPE actions and refuses to decide on them.
        self.assertEqual(res["status"], "NO_ACTION")
        
        shutil.rmtree(root, ignore_errors=True)

    def test_missing_capability(self):
        root = self._make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        rt.mission_create("Capability Test", custom_id="M-CAP", target_scope=["example.com"])
        
        # Unknown capability
        a1 = CandidateAction(
            id="A-UNAVAIL", 
            action_type="RECON", 
            objective="Test",
            target="http://example.com",
            capability_id="DOES_NOT_EXIST",
            scope_alignment="IN_SCOPE"
        )
        rt.brain.state.candidate_actions[a1.id] = a1
        
        res = rt.step_mission("M-CAP")
        self.assertEqual(res["status"], "BLOCKED")
        # Unknown capability is denied by the authorization gate before tool
        # dispatch (capability binding is part of mission authorization).
        self.assertEqual(res["reason"], "AUTHZ_DENIED")
        
        shutil.rmtree(root, ignore_errors=True)
        
    def test_shell_injection_prevention(self):
        root = self._make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        
        tool = rt._capability_registry.get_tool("curl")
        if ToolDiscovery.check_availability(tool) == "UNAVAILABLE":
            self.skipTest("curl not installed")
            
        rt.mission_create("Shell Test", custom_id="M-SHELL", target_scope=["127.0.0.1"])
        
        # Adversarial target url attempting command injection
        # If shell=True, this would run `echo VULNERABLE`
        malicious_url = "http://127.0.0.1; echo VULNERABLE"
        
        a1 = CandidateAction(
            id="A-INJECT", 
            action_type="RECON", 
            objective="Test",
            target="target",
            capability_id="HTTP_REQUEST",
            input_parameters={"url": malicious_url},
            scope_alignment="IN_SCOPE"
        )
        rt.brain.state.candidate_actions[a1.id] = a1
        
        res = rt.step_mission("M-SHELL")

        # Phase A: the injection payload is denied by the centralized scope
        # gate before any process is spawned. It must NEVER execute.
        self.assertEqual(res["status"], "BLOCKED")
        
        # Verify no evidence was written (because it failed process execution)
        evidence_file = root / "workspace" / "raw" / "M-SHELL" / "execution"
        if evidence_file.exists():
            for f in evidence_file.glob("*.txt"):
                content = f.read_text()
                self.assertNotIn("VULNERABLE", content, "Shell injection succeeded! shell=True was likely used.")
            
        shutil.rmtree(root, ignore_errors=True)

    def test_malicious_url_scheme_blocked(self):
        root = self._make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        
        rt.mission_create("Scheme Test", custom_id="M-SCHEME", target_scope=["example.com"])
        
        # Action with file:// scheme
        a1 = CandidateAction(
            id="A-FILE", 
            action_type="RECON", 
            objective="Test",
            target="example.com",
            capability_id="HTTP_REQUEST",
            input_parameters={"url": "file:///etc/passwd"},
            scope_alignment="IN_SCOPE"
        )
        rt.brain.state.candidate_actions[a1.id] = a1
        
        res = rt.step_mission("M-SCHEME")

        self.assertEqual(res["status"], "BLOCKED")
        # Phase A: unsupported scheme is denied by the centralized scope gate
        # (effective execution URL) before adapter planning.
        self.assertIn("UNSUPPORTED_TARGET", res["reason"])
        
        shutil.rmtree(root, ignore_errors=True)

    def test_process_timeout(self):
        root = self._make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        
        # Verify dig is available
        dig_tool = rt._capability_registry.get_tool("dig")
        if ToolDiscovery.check_availability(dig_tool) == "UNAVAILABLE":
            self.skipTest("dig not installed, skipping timeout test")
            
        # Override dig tool timeout to 0 for forced timeout
        dig_tool.timeout_defaults = 0
        
        rt.mission_create("Timeout Test", custom_id="M-TIMEOUT", target_scope=["example.com"])
        
        a1 = CandidateAction(
            id="A-DIG", 
            action_type="RECON", 
            objective="Test",
            target="example.com",
            capability_id="DNS_LOOKUP",
            input_parameters={"domain": "example.com"},
            scope_alignment="IN_SCOPE"
        )
        rt.brain.state.candidate_actions[a1.id] = a1
        
        res = rt.step_mission("M-TIMEOUT")
        
        self.assertEqual(res["status"], "TIMEOUT")
        
        shutil.rmtree(root, ignore_errors=True)

    def test_negative_result_brain_update(self):
        root = self._make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        
        rt.mission_create("Neg Result Test", custom_id="M-NEG", target_scope=["127.0.0.1"])
        
        # Action that will fail (assuming localhost:9999 is dead)
        a1 = CandidateAction(
            id="A-FAIL", 
            action_type="RECON", 
            objective="Test",
            target="http://127.0.0.1:9999",
            capability_id="HTTP_REQUEST",
            input_parameters={"url": "http://127.0.0.1:9999"},
            scope_alignment="IN_SCOPE"
        )
        rt.brain.state.candidate_actions[a1.id] = a1
        
        # Should fail execution, returning FAILED status but updating Brain with the failure
        res = rt.step_mission("M-NEG")
        
        self.assertEqual(res["status"], "FAILED")
        
        # Verify brain state learned about the failure
        obs = list(rt.brain.state.observations.values())
        self.assertGreater(len(obs), 0, "Brain should have learned about the failure")
        self.assertIn("failed", obs[0].fact.lower())
        
        shutil.rmtree(root, ignore_errors=True)

    def test_tool_selection_dynamic_scoring(self):
        root = self._make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        
        # Register a fake tool for HTTP that is high risk but supports it
        from runtime.capabilities.model import Tool
        rt._capability_registry.register_tool(Tool(
            id="bad_curl", name="Bad cURL", binary="curl", supported_capabilities=["HTTP_REQUEST"],
            risk_level="HIGH"
        ))
        
        # The selector should pick curl over bad_curl because bad_curl has higher risk
        tool = rt._tool_selector.select_tool("HTTP_REQUEST")
        self.assertEqual(tool.id, "curl")
        
        shutil.rmtree(root, ignore_errors=True)

    def test_execution_restart_recovery(self):
        root = self._make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        
        rt.mission_create("Restart Test", custom_id="M-RESTART", target_scope=["example.com"])
        
        # We manually add a node to the Graph Store to prove graph recovery works
        rt.graph_store.add_node(node_type="ENDPOINT", identity_string="test.example.com")
        
        capsule = rt.mission_checkpoint("M-RESTART")
        
        # New runtime
        rt2 = HunterRuntime(root)
        rt2.start()
        rt2.mission_resume("M-RESTART")
        
        # Verify graph state restored
        self.assertEqual(len(rt2.graph_store._nodes), 1)
        node = list(rt2.graph_store._nodes.values())[0]
        self.assertEqual(node.identity_string, "test.example.com")
        
        shutil.rmtree(root, ignore_errors=True)

    def test_process_cancellation(self):
        # We can test ProcessExecutor directly to cancel a slow process
        root = self._make_isolated_root()
        from runtime.executor.process import ProcessExecutor
        from runtime.executor.planner import ExecutionPlan
        
        # Using a ping to simulate long running process (since cross-platform)
        # We will use timeout=0.1 to force cancellation
        executor = ProcessExecutor(workspace_root=root)
        plan = ExecutionPlan(
            execution_id="EXEC-CANCEL", mission_id="M1", action_id="A1", capability_id="C1",
            tool_id="T1", target="localhost", binary_path="python",
            validated_arguments=["-c", "import time; time.sleep(5)"], timeout=1
        )
        
        result = executor.execute(plan)
        self.assertEqual(result.status, "TIMEOUT")
        
        shutil.rmtree(root, ignore_errors=True)

    def test_unavailable_tool_fallback(self):
        root = self._make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        
        # Register a fake capability and tools pointing to fake binaries so discovery fails
        from runtime.capabilities.model import Capability
        rt._capability_registry.register_capability(Capability(
            id="FAKE_CAP", name="Fake", description="Fake", category="WEB", risk_level="LOW", network_effect=False, required_authorization=False
        ))
        
        from runtime.capabilities.model import Tool
        rt._capability_registry.register_tool(Tool(
            id="fake1", name="Fake 1", binary="does_not_exist_xyz123", supported_capabilities=["FAKE_CAP"]
        ))
        rt._capability_registry.register_tool(Tool(
            id="fake2", name="Fake 2", binary="does_not_exist_abc987", supported_capabilities=["FAKE_CAP"]
        ))
        
        tool2 = rt._tool_selector.select_tool("FAKE_CAP")
        self.assertIsNone(tool2)
        
        shutil.rmtree(root, ignore_errors=True)

    def test_resource_budget_limits(self):
        root = self._make_isolated_root()
        from runtime.executor.process import ProcessExecutor
        from runtime.executor.planner import ExecutionPlan
        
        # Executor with very small output limit (10 bytes)
        executor = ProcessExecutor(workspace_root=root, output_limit_bytes=10)
        plan = ExecutionPlan(
            execution_id="EXEC-BUDGET", mission_id="M1", action_id="A1", capability_id="C1",
            tool_id="T1", target="localhost", binary_path="python",
            validated_arguments=["-c", "print('A' * 100)"], timeout=5
        )
        
        result = executor.execute(plan)
        self.assertEqual(result.status, "COMPLETED_TRUNCATED")
        
        # Verify file size
        path = Path(result.stdout_reference)
        content = path.read_text()
        self.assertTrue("TRUNCATED" in content)
        self.assertTrue(content.startswith("AAAAAAAAAA"))
        
        shutil.rmtree(root, ignore_errors=True)

    def test_execution_result_changes_decision(self):
        # A test to show the Brain evaluates observations
        root = self._make_isolated_root()
        rt = HunterRuntime(root)
        rt.start()
        
        rt.mission_create("Decisions", custom_id="M-DEC", target_scope=["example.com"])
        
        # We don't have LLM to generate actions, but we can verify PriorityEngine scores
        # change if an action was already executed.
        a1 = CandidateAction(
            id="A-DEC-1", action_type="RECON", objective="Test", target="example.com",
            capability_id="HTTP_REQUEST", scope_alignment="IN_SCOPE",
            expected_information_gain=1.0, expected_security_value=1.0
        )
        rt.brain.state.candidate_actions[a1.id] = a1
        
        # Score before
        score1 = rt.brain._prioritization.calculate_hunt_value(a1, rt.brain.state)
        
        # Tell PriorityEngine it was executed
        rt.brain._prioritization.record_action_executed(a1.id, rt.brain.state)
        
        # Score after
        score2 = rt.brain._prioritization.calculate_hunt_value(a1, rt.brain.state)
        self.assertLess(score2, score1, "Action score did not drop after execution")
        
        shutil.rmtree(root, ignore_errors=True)

if __name__ == '__main__':
    unittest.main()
