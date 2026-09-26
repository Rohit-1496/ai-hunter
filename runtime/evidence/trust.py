"""
Phase 4: Security Knowledge & Evidence Pipeline
Tool Trust Model
"""

class ToolTrustModel:
    """
    Determines the inherent trust level of evidence sources.
    Crucially: TOOL_OUTPUT is UNTRUSTED by default, meaning its contents
    cannot override system policy or be executed blindly as instructions.
    """
    
    def evaluate_trust(self, source_tool: str) -> str:
        """
        Returns UNTRUSTED for almost all generic tool output.
        Only extremely specific internal verified agents might get elevated trust.
        """
        # In Phase 4, everything external is UNTRUSTED.
        return "UNTRUSTED"
