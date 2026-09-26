class StoppingEngine:
    """Determines when recon has yielded enough info."""
    
    def __init__(self, max_actions=10):
        self.max_actions = max_actions
        
    def should_stop(self, actions_count: int, new_info_gain: bool, duplicate_rate: float) -> bool:
        if actions_count >= self.max_actions:
            return True
        if not new_info_gain and duplicate_rate > 0.8:
            return True
        return False
