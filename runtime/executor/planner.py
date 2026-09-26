"""
Phase 5 Execution Planner.

Takes a CandidateAction, Capability, and Tool and structures it into a safe
ExecutionPlan ready for the process executor.
"""

from dataclasses import dataclass, field
from typing import Any
import uuid

@dataclass
class ExecutionPlan:
    execution_id: str
    mission_id: str
    action_id: str
    capability_id: str = ""
    tool_id: str = ""
    target: str = ""
    binary_path: str = ""
    validated_arguments: list[str] = field(default_factory=list)
    timeout: int = 30
    resource_limits: dict[str, Any] = field(default_factory=dict)
    environment: dict[str, str] = field(default_factory=dict)
    expected_evidence_types: list[str] = field(default_factory=list)
    working_directory: str = ""

class ExecutionPlanner:
    """Transforms a selected action and tool into a concrete process plan."""
    
    @staticmethod
    def create_plan(
        mission_id: str,
        action_id: str,
        target: str,
        capability_id: str,
        tool_id: str,
        binary_path: str,
        arguments: list[str],
        timeout: int,
        expected_evidence_types: list[str]
    ) -> ExecutionPlan:
        return ExecutionPlan(
            execution_id=f"EXEC-{uuid.uuid4().hex[:8]}",
            mission_id=mission_id,
            action_id=action_id,
            capability_id=capability_id,
            tool_id=tool_id,
            target=target,
            binary_path=binary_path,
            validated_arguments=arguments,
            timeout=timeout,
            expected_evidence_types=expected_evidence_types
        )
