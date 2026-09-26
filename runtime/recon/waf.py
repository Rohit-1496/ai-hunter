class WAFHandler:
    """Handles WAF/CDN detection without unauthorized bypass."""
    
    def __init__(self):
        self.blocked_targets = set()
        
    def detect_block(self, response: dict) -> bool:
        status = response.get("status_code", 200)
        headers = response.get("headers", {})
        
        if status in [403, 406, 429]:
            if "cf-ray" in headers or "x-sucuri-id" in headers:
                return True
        return False
        
    def handle_block(self, target: str):
        # Replanning after a block
        self.blocked_targets.add(target)
        return {
            "status": "REPLAN",
            "message": f"WAF block detected for {target}. Reducing request rate and evaluating benign behavior."
        }
