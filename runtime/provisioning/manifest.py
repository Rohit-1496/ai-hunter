import yaml
from pathlib import Path
from typing import List, Dict

class ToolManifest:
    def __init__(self, manifest_path: str = "config/tools-manifest.yaml"):
        self.manifest_path = Path(manifest_path)
        self.tools = []
        if self.manifest_path.exists():
            with open(self.manifest_path, "r") as f:
                data = yaml.safe_load(f)
                self.tools = data.get("tools", [])
                
    def get_tool(self, name: str) -> dict:
        for t in self.tools:
            if t["name"] == name:
                return t
        return None
        
    def get_all_tools(self) -> List[Dict]:
        return self.tools
