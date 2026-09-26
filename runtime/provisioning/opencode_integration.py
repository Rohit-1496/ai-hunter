from pathlib import Path

class OpenCodeIntegration:
    def __init__(self):
        self.dot_dir = Path(".opencode")
        
    def configure(self) -> bool:
        self.dot_dir.mkdir(exist_ok=True)
        config = self.dot_dir / "config.json"
        config.write_text("{\"project_id\": \"ai-hunter\", \"brain\": \"Beast Brain\"}")
        return True
        
    def verify(self) -> bool:
        return (self.dot_dir / "config.json").exists()
