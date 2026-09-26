"""
Phase 14: Resource Allocation Engine

Translates strategic priorities into budget and time allocations for P10 research threads.
Preserves strict budget invariants (never mints or resets resources).
"""

from __future__ import annotations

from typing import Any
from runtime.strategy.models import StrategicObjective, StrategyAllocation


class ResourceAllocationEngine:
    """Calculates strategic resource allocations without violating P10 budget authority."""

    def allocate_resources(
        self,
        objectives: list[StrategicObjective],
        available_budget: float,
        available_time: float,
        *,
        reservation_fraction: float = 0.10,
    ) -> list[StrategyAllocation]:
        """
        Distributes available resources proportionally based on objective security_value.
        """
        allocations: list[StrategyAllocation] = []
        if available_budget <= 0.0 or not objectives:
            return allocations

        reserved = available_budget * reservation_fraction
        allocatable_budget = max(0.0, available_budget - reserved)

        total_weight = sum(o.security_value for o in objectives)
        if total_weight <= 0:
            total_weight = float(len(objectives))

        for obj in objectives:
            weight_fraction = obj.security_value / total_weight
            budget_share = round(allocatable_budget * weight_fraction, 4)
            time_share = round(available_time * weight_fraction, 2)

            thread_ref = obj.research_thread_refs[0] if obj.research_thread_refs else f"THREAD-{obj.objective_id}"
            
            alloc = StrategyAllocation(
                objective_id=obj.objective_id,
                thread_id=thread_ref,
                allocated_budget=budget_share,
                allocated_time=time_share,
                priority=obj.priority,
                reservation=round(reserved / len(objectives), 4),
                expected_return=obj.security_value,
                allocation_reason=f"Proportional allocation for {obj.objective_type.value} (weight: {weight_fraction:.2f})",
            )
            allocations.append(alloc)

        return allocations
