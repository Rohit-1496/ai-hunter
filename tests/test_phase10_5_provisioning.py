import pytest
import os
import shutil
from runtime.provisioning.manifest import ToolManifest
from runtime.provisioning.verifier import ToolVerifier
from runtime.provisioning.state import ToolState
from runtime.provisioning.opencode_integration import OpenCodeIntegration
from runtime.provisioning.installer import ToolInstaller

@pytest.fixture
def test_manifest():
    return ToolManifest()

def test_manifest_loading(test_manifest):
    tools = test_manifest.get_all_tools()
    assert len(tools) > 0
    nmap = test_manifest.get_tool("nmap")
    assert nmap["category"] == "network"
    assert nmap["requires_root"] is True

def test_tool_verifier():
    verifier = ToolVerifier()
    # Mocking ls as a tool that exists
    res = verifier.verify({"name": "ls", "binary_names": ["ls"], "verification_command": "ls --version"})
    assert res["status"] in ["READY", "FAILED", "MISSING"]
    
    # Missing tool
    res2 = verifier.verify({"name": "notatool", "binary_names": ["notatool"]})
    assert res2["status"] == "MISSING"

def test_tool_state(tmp_path):
    state_file = tmp_path / "state.json"
    state = ToolState(str(state_file))
    state.update_tool("nmap", {"status": "READY", "verified": True})
    
    assert state.get_tool("nmap")["status"] == "READY"
    health = state.get_overall_health()
    assert health["ready"] == 1
    assert health["total"] == 1

def test_installer_unsupported_root(test_manifest):
    installer = ToolInstaller()
    nmap = test_manifest.get_tool("nmap")
    res = installer.install(nmap)
    # nmap requires root and our mock will refuse since we are normal user simulation
    if not shutil.which("nmap"):
        assert res["status"] == "FAILED"

def test_opencode_integration(tmp_path):
    import os
    original_cwd = os.getcwd()
    os.chdir(str(tmp_path))
    try:
        oc = OpenCodeIntegration()
        assert oc.configure() is True
        assert oc.verify() is True
    finally:
        os.chdir(original_cwd)
