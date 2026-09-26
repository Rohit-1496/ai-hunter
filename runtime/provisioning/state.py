import json
from pathlib import Path

class ToolState:
    def __init__(self, state_path: str = "state/tool-status.json"):
        self.state_path = Path(state_path)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state = {}
        self.load()
        
    def load(self):
        if self.state_path.exists():
            try:
                with open(self.state_path, "r") as f:
                    self.state = json.load(f)
            except:
                self.state = {}
                
    def save(self):
        with open(self.state_path, "w") as f:
            json.dump(self.state, f, indent=2)
            
    def update_tool(self, tool_name: str, status: dict):
        self.state[tool_name] = status
        self.save()
        
    def get_tool(self, tool_name: str) -> dict:
        return self.state.get(tool_name, {})
        
    def get_overall_health(self):
        ready = sum(1 for t in self.state.values() if t.get("status") == "READY")
        failed = sum(1 for t in self.state.values() if t.get("status") == "FAILED")
        missing = sum(1 for t in self.state.values() if t.get("status") == "MISSING")
        unsupported = sum(1 for t in self.state.values() if t.get("status") == "UNSUPPORTED")
        return {
            "ready": ready,
            "failed": failed,
            "missing": missing,
            "unsupported": unsupported,
            "total": len(self.state)
        }
