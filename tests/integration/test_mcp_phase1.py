"""
MCP Adapter Integration Tests — Phase 1

Tests the genuine executable bridge:
  Test runner → subprocess (MCP server) → HunterRuntime → real state

These tests communicate with the MCP server over stdio exactly as OpenCode does,
using the MCP protocol (JSON-RPC 2.0).

IMPORTANT SCOPE SEPARATION
───────────────────────────
Layer 1 — MCP PROTOCOL TESTS (these tests):
    Run via subprocess + stdin/stdout. Prove that the MCP server:
    - starts correctly
    - handles MCP initialization (capabilities negotiation)
    - exposes hunter_hi and hunter_status tools via tools/list
    - correctly dispatches tools/call → HunterRuntime
    - returns real subsystem health
    - reports broken subsystems as UNAVAILABLE (not READY)
    These DO NOT require OpenCode to be installed.

Layer 2 — OPENCODE END-TO-END (NOT TESTED HERE):
    OpenCode is NOT installed in this environment (confirmed Phase 0).
    Full end-to-end verification (OpenCode → MCP → runtime) must be
    performed manually once OpenCode is installed and configured with
    hunter-opencode.jsonc. See README.md for instructions.
    We do NOT claim Layer 2 passed.
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

PYTHON = sys.executable
MCP_MODULE = "runtime.adapter.mcp_server"


# ---------------------------------------------------------------------------
# MCP Protocol helpers — exact protocol used by OpenCode
# ---------------------------------------------------------------------------

def _send(proc: subprocess.Popen, msg: dict) -> None:
    """Send one MCP JSON-RPC message to the server over stdin."""
    line = json.dumps(msg) + "\n"
    proc.stdin.write(line)
    proc.stdin.flush()


def _recv(proc: subprocess.Popen, timeout: float = 10.0) -> dict:
    """
    Read one MCP JSON-RPC message from the server stdout.

    Raises TimeoutError if no response within `timeout` seconds.
    Skips non-JSON lines (e.g. server startup messages on stdout).
    """
    import selectors
    deadline = time.monotonic() + timeout
    buf = ""
    while time.monotonic() < deadline:
        # Non-blocking read with 0.1s poll
        try:
            proc.stdout.fileno()  # ensure it's a real fd
        except Exception:
            break
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.05)
            continue
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            # Skip non-JSON output (e.g. logging lines)
            continue
    raise TimeoutError(f"No MCP response within {timeout}s")


def _mcp_initialize(proc: subprocess.Popen) -> dict:
    """
    Perform MCP initialization handshake.
    Returns the server's initialize response.
    """
    _send(proc, {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "hunter-test-client", "version": "1.0.0"},
        },
    })
    resp = _recv(proc)
    # Send initialized notification
    _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
    return resp


def _mcp_list_tools(proc: subprocess.Popen, req_id: int = 2) -> dict:
    _send(proc, {"jsonrpc": "2.0", "id": req_id, "method": "tools/list", "params": {}})
    return _recv(proc)


def _mcp_call_tool(proc: subprocess.Popen, tool_name: str, req_id: int = 3) -> dict:
    _send(proc, {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": {}},
    })
    return _recv(proc)


def _start_mcp_server(project_root: Path) -> subprocess.Popen:
    """Start the MCP server subprocess with the given project root."""
    env = os.environ.copy()
    env["HUNTER_PROJECT_ROOT"] = str(project_root)
    proc = subprocess.Popen(
        [PYTHON, "-m", MCP_MODULE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(_PROJECT_ROOT),
        env=env,
    )
    # Give the server a moment to start
    time.sleep(0.3)
    return proc


def _make_isolated_root() -> Path:
    """Create a fully isolated project root with all required files."""
    tmp = Path(tempfile.mkdtemp(prefix="hunter-mcp-test-"))
    (tmp / "hunter").mkdir()
    (tmp / "hunter" / "brain.md").write_text("# Brain test stub", encoding="utf-8")
    (tmp / "hunter" / "policy.md").write_text("# Policy test stub", encoding="utf-8")
    (tmp / "runtime" / "executor").mkdir(parents=True)
    (tmp / "runtime" / "graph").mkdir(parents=True)
    (tmp / "AGENTS.md").write_text("# Hunter AGENTS", encoding="utf-8")
    return tmp


# ---------------------------------------------------------------------------
# Test 1: MCP Server Startup
# ---------------------------------------------------------------------------

class TestMCPServerStartup(unittest.TestCase):
    """MCP server starts as a subprocess and responds to initialization."""

    def test_server_starts_and_initializes(self):
        root = _make_isolated_root()
        proc = None
        try:
            proc = _start_mcp_server(root)
            self.assertIsNone(proc.poll(), "MCP server process should be running")

            resp = _mcp_initialize(proc)
            self.assertIn("result", resp, f"Expected result in init response, got: {resp}")
            result = resp["result"]
            self.assertIn("protocolVersion", result)
            self.assertIn("serverInfo", result)
            self.assertEqual(result["serverInfo"]["name"], "hunter-runtime")
        finally:
            if proc:
                proc.terminate()
                proc.wait(timeout=5)
            shutil.rmtree(root, ignore_errors=True)

    def test_server_exposes_tools(self):
        root = _make_isolated_root()
        proc = None
        try:
            proc = _start_mcp_server(root)
            _mcp_initialize(proc)
            resp = _mcp_list_tools(proc)

            self.assertIn("result", resp, f"tools/list failed: {resp}")
            tools = resp["result"]["tools"]
            tool_names = {t["name"] for t in tools}
            self.assertIn("hunter_hi", tool_names, f"hunter_hi not in tools: {tool_names}")
            self.assertIn("hunter_status", tool_names, f"hunter_status not in tools: {tool_names}")
        finally:
            if proc:
                proc.terminate()
                proc.wait(timeout=5)
            shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Test 2: hunter_hi via MCP
# ---------------------------------------------------------------------------

class TestMCPHunterHi(unittest.TestCase):
    """hunter_hi tool returns real hunter handshake through the MCP path."""

    def _call_hi(self, root: Path) -> str:
        proc = _start_mcp_server(root)
        try:
            _mcp_initialize(proc)
            resp = _mcp_call_tool(proc, "hunter_hi", req_id=3)
            self.assertIn("result", resp, f"hunter_hi failed: {resp}")
            content = resp["result"]["content"]
            self.assertIsInstance(content, list)
            self.assertGreater(len(content), 0)
            return content[0]["text"]
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_hi_contains_hunter_online(self):
        root = _make_isolated_root()
        try:
            text = self._call_hi(root)
            self.assertIn("Hunter online.", text)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_hi_contains_runtime_section(self):
        root = _make_isolated_root()
        try:
            text = self._call_hi(root)
            self.assertIn("Runtime:", text)
            self.assertIn("Brain", text)
            self.assertIn("Memory", text)
            self.assertIn("Scope", text)
            self.assertIn("Executor", text)
            self.assertIn("Checkpoints", text)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_hi_contains_mission_none(self):
        root = _make_isolated_root()
        try:
            text = self._call_hi(root)
            self.assertIn("NONE", text)
        finally:
            shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Test 3: hunter_status via MCP — healthy state
# ---------------------------------------------------------------------------

class TestMCPHunterStatusHealthy(unittest.TestCase):
    """hunter_status returns REAL healthy state through MCP path."""

    def _call_status(self, root: Path) -> str:
        proc = _start_mcp_server(root)
        try:
            _mcp_initialize(proc)
            resp = _mcp_call_tool(proc, "hunter_status", req_id=3)
            self.assertIn("result", resp, f"hunter_status failed: {resp}")
            content = resp["result"]["content"]
            return content[0]["text"]
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_status_shows_online(self):
        root = _make_isolated_root()
        try:
            text = self._call_status(root)
            self.assertIn("Hunter: ONLINE", text)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_status_contains_all_subsystems(self):
        root = _make_isolated_root()
        try:
            text = self._call_status(root)
            for label in [
                "Brain:", "Persistent memory:", "Scope gate:",
                "Executor:", "Security graph:", "Checkpoint engine:",
            ]:
                self.assertIn(label, text, f"Missing in status: {label}")
        finally:
            shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Test 4: DIVERGENCE TEST — broken subsystem → real UNAVAILABLE via MCP
# ---------------------------------------------------------------------------

class TestMCPDivergence(unittest.TestCase):
    """
    CRITICAL: Prove the MCP path returns REAL state, not hardcoded values.

    This is the test that distinguishes a genuine executable adapter
    from an instruction-based illusion.

    Sequence:
      1. Healthy root → MCP → status → READY for executor
      2. Delete executor dir → MCP → status → UNAVAILABLE for executor
      3. Restore executor dir → MCP → status → READY again
    """

    def _status_via_mcp(self, root: Path) -> str:
        proc = _start_mcp_server(root)
        try:
            _mcp_initialize(proc)
            resp = _mcp_call_tool(proc, "hunter_status", req_id=3)
            content = resp["result"]["content"]
            return content[0]["text"]
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_healthy_executor_shows_ready_via_mcp(self):
        root = _make_isolated_root()
        try:
            text = self._status_via_mcp(root)
            self.assertIn("Executor: READY", text,
                "Executor should be READY when directory exists — via MCP path")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_broken_executor_shows_unavailable_via_mcp(self):
        """
        DIVERGENCE TEST:
        Deletes executor dir → MCP server → real runtime → UNAVAILABLE.
        An instruction-based system would still say READY.
        """
        root = _make_isolated_root()
        try:
            shutil.rmtree(root / "runtime" / "executor")
            text = self._status_via_mcp(root)
            self.assertNotIn("Executor: READY", text,
                "Executor MUST NOT be READY when its directory is deleted — via MCP path")
            self.assertIn("Executor: UNAVAILABLE", text,
                "Executor MUST show UNAVAILABLE when directory is missing — via MCP path")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_broken_brain_shows_unavailable_via_mcp(self):
        root = _make_isolated_root()
        try:
            (root / "hunter" / "brain.md").unlink()
            text = self._status_via_mcp(root)
            self.assertNotIn("Brain: READY", text,
                "Brain MUST NOT be READY when brain.md is deleted — via MCP path")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_restore_returns_healthy_via_mcp(self):
        """
        After restoring deleted executor dir, next MCP call reports READY again.
        """
        root = _make_isolated_root()
        try:
            # Break
            executor_dir = root / "runtime" / "executor"
            shutil.rmtree(executor_dir)
            broken_text = self._status_via_mcp(root)
            self.assertIn("Executor: UNAVAILABLE", broken_text)

            # Restore
            executor_dir.mkdir(parents=True)
            restored_text = self._status_via_mcp(root)
            self.assertIn("Executor: READY", restored_text,
                "Executor MUST return READY after directory is restored — via MCP path")
        finally:
            shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Test 5: MCP request/response protocol correctness
# ---------------------------------------------------------------------------

class TestMCPProtocol(unittest.TestCase):
    """MCP protocol compliance: jsonrpc, id echoing, result structure."""

    def test_response_echoes_request_id(self):
        root = _make_isolated_root()
        proc = None
        try:
            proc = _start_mcp_server(root)
            _send(proc, {
                "jsonrpc": "2.0",
                "id": 42,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0"},
                },
            })
            resp = _recv(proc)
            self.assertEqual(resp.get("id"), 42, "Response must echo the request id")
        finally:
            if proc:
                proc.terminate()
                proc.wait(timeout=5)
            shutil.rmtree(root, ignore_errors=True)

    def test_tool_response_has_content_list(self):
        root = _make_isolated_root()
        proc = None
        try:
            proc = _start_mcp_server(root)
            _mcp_initialize(proc)
            resp = _mcp_call_tool(proc, "hunter_status", req_id=99)
            result = resp.get("result", {})
            self.assertIn("content", result)
            self.assertIsInstance(result["content"], list)
            self.assertGreater(len(result["content"]), 0)
            self.assertEqual(result["content"][0]["type"], "text")
        finally:
            if proc:
                proc.terminate()
                proc.wait(timeout=5)
            shutil.rmtree(root, ignore_errors=True)

    def test_unknown_tool_returns_error(self):
        root = _make_isolated_root()
        proc = None
        try:
            proc = _start_mcp_server(root)
            _mcp_initialize(proc)
            resp = _mcp_call_tool(proc, "nonexistent_tool", req_id=5)
            # Should be an error response, not a result
            has_error = "error" in resp or resp.get("result", {}).get("isError")
            self.assertTrue(has_error,
                f"Unknown tool should return error, got: {resp}")
        finally:
            if proc:
                proc.terminate()
                proc.wait(timeout=5)
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
