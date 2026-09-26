"""
Tactical Executor Interface (Phase 3)

Defines the boundary between the Beast Brain (decides WHAT to do)
and the Tactical Executor (decides HOW to do it).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from runtime.brain.decision import CandidateAction
from runtime.executor.planner import ExecutionPlan


@dataclass
class ExecutionResult:
    """The structured result of an executed action, returned to the Brain."""
    execution_id: str
    mission_id: str
    action_id: str
    tool_id: str
    status: str  # COMPLETED, FAILED, TIMEOUT, BLOCKED
    started_at: str = ""
    finished_at: str = ""
    duration_sec: float = 0.0
    exit_code: int | None = None
    stdout_reference: str | None = None
    stderr_reference: str | None = None
    error_type: str | None = None
    raw_output: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "mission_id": self.mission_id,
            "action_id": self.action_id,
            "tool_id": self.tool_id,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_sec": self.duration_sec,
            "exit_code": self.exit_code,
            "stdout_reference": self.stdout_reference,
            "stderr_reference": self.stderr_reference,
            "error_type": self.error_type
        }


class TacticalExecutorInterface:
    """
    Contract for executing ExecutionPlans.
    """
    def execute(self, plan: ExecutionPlan) -> ExecutionResult:
        raise NotImplementedError()


class MockExecutor(TacticalExecutorInterface):
    """
    A deterministic executor for testing the Brain Loop without side effects.
    """
    def __init__(self) -> None:
        self.call_count = 0
        self.last_action: CandidateAction | None = None
        self.mock_responses: dict[str, ExecutionResult] = {}

    def execute(self, plan: ExecutionPlan) -> ExecutionResult:
        self.call_count += 1
        
        if plan.action_id in self.mock_responses:
            return self.mock_responses[plan.action_id]
            
        return ExecutionResult(
            execution_id=plan.execution_id,
            mission_id=plan.mission_id,
            action_id=plan.action_id,
            tool_id=plan.tool_id,
            status="COMPLETED",
            duration_sec=0.1
        )
