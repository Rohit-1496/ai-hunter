import subprocess
import shutil

class ToolVerifier:
    def __init__(self):
        pass
        
    def verify(self, manifest_entry: dict) -> dict:
        binaries = manifest_entry.get("binary_names", [])
        if not binaries:
            return {"status": "FAILED", "reason": "No binary names specified"}
            
        executable = shutil.which(binaries[0])
        if not executable:
            return {"status": "MISSING", "reason": f"Binary {binaries[0]} not found"}
            
        cmd = manifest_entry.get("verification_command")
        if not cmd:
            return {"status": "READY", "path": executable, "verified": True}
            
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return {"status": "READY", "path": executable, "verified": True, "output": result.stdout[:100]}
            else:
                return {"status": "FAILED", "path": executable, "verified": False, "reason": "Verification command failed"}
        except Exception as e:
            return {"status": "FAILED", "path": executable, "verified": False, "reason": str(e)}
