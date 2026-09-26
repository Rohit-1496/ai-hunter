"""
Phase 5 Tool Discovery.

Determines if a tool is actually installed and executable on the host.
"""

import shutil
from pathlib import Path
from runtime.capabilities.model import Tool

class ToolDiscovery:
    """Verifies that tools are executable and healthy."""
    
    @staticmethod
    def check_availability(tool: Tool) -> str:
        """
        Checks if the tool's binary exists and is executable in the current PATH.
        Returns 'AVAILABLE' or 'UNAVAILABLE'.
        """
        if not tool.binary:
            return "UNAVAILABLE"
            
        # shutil.which works cross-platform (Windows & Linux)
        binary_path = shutil.which(tool.binary)
        if binary_path is not None:
            return "AVAILABLE"
            
        # Fallback to direct path check if binary was absolute
        path = Path(tool.binary)
        if path.is_file():
            # Basic sanity check (doesn't check execution permissions on windows well, but good enough for prototype)
            return "AVAILABLE"
            
        return "UNAVAILABLE"
