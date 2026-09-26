"""
Phase 12: Regression Scheduler & P10 MissionDirector Integration

Bridges regression candidates into P10 MissionDirector research threads.
Ensures Phase 12 does NOT act as a second scheduler.
"""

from __future__ import annotations

import secrets
from typing import Any

from runtime.orchestration.director import MissionDirector
from runtime.orchestration.models import ResearchThread, ThreadStatus, Objective
from runtime.regression.models import RegressionHypothesis


class RegressionScheduler:
    """
    Translates regression hypotheses into P10 ResearchThread objects managed by MissionDirector.
    """

    def schedule_regression_thread(
        self,
        director: MissionDirector,
        hypothesis: RegressionHypothesis,
        *,
        objective_id: str | None = None,
    ) -> ResearchThread:
        """
        Creates a ResearchThread within the MissionDirector's portfolio.
        """
        # Get or create objective
        if not objective_id:
            active_objs = director.portfolio.get_active_objectives()
            if active_objs:
                objective_id = active_objs[0].id
            else:
                obj = director.portfolio.create_objective(
                    title=f"Continuous Validation: {hypothesis.title}",
                    description=hypothesis.statement,
                )
                objective_id = obj.id

        thread = director.thread_manager.create_thread(
            objective_id=objective_id,
            title=f"[Regression] {hypothesis.title}",
            impact_potential=hypothesis.priority,
        )
        thread.priority = hypothesis.priority

        return thread
