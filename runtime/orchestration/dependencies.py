"""
Phase 10: Thread Dependency Graph
Tracks inter-thread and inter-objective prerequisites.
Enforces strict rule: UNKNOWN != SATISFIED and propagates blockage/invalidation.
"""

from __future__ import annotations

import secrets
from typing import Any

from runtime.orchestration.models import (
    DependencyStatus,
    ThreadDependency,
)


class ThreadDependencyGraph:
    """
    Manages dependency relationships between threads, objectives, and security conditions.
    """

    def __init__(self) -> None:
        self._dependencies: dict[str, ThreadDependency] = {}

    @property
    def dependencies(self) -> dict[str, ThreadDependency]:
        return self._dependencies

    def add_dependency(
        self,
        source_thread_id: str,
        target_thread_id: str,
        dependency_type: str,
        custom_id: str | None = None
    ) -> ThreadDependency:
        """
        Registers that target_thread_id depends on source_thread_id fulfilling dependency_type.
        """
        dep_id = custom_id or f"DEP-{secrets.token_hex(4).upper()}"
        dep = ThreadDependency(
            id=dep_id,
            source_thread_id=source_thread_id,
            target_thread_id=target_thread_id,
            dependency_type=dependency_type,
            status=DependencyStatus.UNSATISFIED
        )
        self._dependencies[dep_id] = dep
        return dep

    def check_dependencies_satisfied(self, target_thread_id: str) -> tuple[bool, list[str]]:
        """
        Checks whether all prerequisites for target_thread_id are strictly SATISFIED.
        Enforces rule: UNKNOWN / UNSATISFIED / PARTIALLY_SATISFIED != SATISFIED.
        """
        unsatisfied: list[str] = []
        for dep in self._dependencies.values():
            if dep.target_thread_id == target_thread_id:
                if dep.status != DependencyStatus.SATISFIED:
                    unsatisfied.append(f"Dependency {dep.id} ({dep.dependency_type}) is {dep.status.value}")

        return (len(unsatisfied) == 0, unsatisfied)

    def satisfy_dependency(self, dependency_id: str, evidence_ref: str) -> bool:
        dep = self._dependencies.get(dependency_id)
        if not dep:
            return False
        dep.status = DependencyStatus.SATISFIED
        dep.required_evidence_ref = evidence_ref
        return True

    def invalidate_dependency(self, dependency_id: str) -> bool:
        dep = self._dependencies.get(dependency_id)
        if not dep:
            return False
        dep.status = DependencyStatus.INVALIDATED
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "dependencies": {did: dep.to_dict() for did, dep in self._dependencies.items()},
        }

    def load_from_dict(self, data: dict[str, Any]) -> None:
        self._dependencies.clear()
        for did, d_data in data.get("dependencies", {}).items():
            self._dependencies[did] = ThreadDependency.from_dict(d_data)
