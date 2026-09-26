"""
Phase 14: Strategy Performance Tracker & Prior Learner

Records execution outcomes for macro strategies and builds context-aware priors.
"""

from __future__ import annotations

from typing import Any
from runtime.strategy.models import StrategyMode, StrategyPerformanceRecord


class StrategyPerformanceTracker:
    """Tracks historical efficacy of strategies across targets and tech contexts."""

    def __init__(self) -> None:
        self._records: list[StrategyPerformanceRecord] = []

    def record_performance(
        self,
        record: StrategyPerformanceRecord,
    ) -> None:
        """Appends a new performance record."""
        self._records.append(record)

    def get_strategy_prior(
        self,
        mode: StrategyMode,
        context: dict[str, Any] | None = None,
    ) -> float:
        """
        Calculates context-aware strategic prior multiplier (0.5 to 1.5).
        """
        relevant = [r for r in self._records if r.strategy_mode == mode]
        if not relevant:
            return 1.0

        total_usefulness = sum(r.usefulness for r in relevant)
        avg = total_usefulness / len(relevant)
        return round(max(0.5, min(1.5, avg * 1.5)), 3)

    def get_all_records(self) -> list[StrategyPerformanceRecord]:
        return list(self._records)
