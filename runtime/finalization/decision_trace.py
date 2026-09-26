"""
Phase 15: Final Decision Trace Builder

Establishes full provenance tracing from macro strategy down to verified finding and final decision.
"""

from __future__ import annotations

from typing import Any
from runtime.finalization.models import FinalDecisionTrace


class DecisionTraceBuilder:
    """Constructs decision traces linking strategic decisions to verified outcomes."""

    def build_trace(
        self,
        strategy_mode: str,
        objective_id: str,
        thread_id: str = "",
        hypothesis_id: str = "",
        experiment_id: str = "",
        evidence_id: str = "",
        finding_id: str = "",
        validation_status: str = "CONFIRMED",
        final_decision: str = "FINALIZE",
    ) -> FinalDecisionTrace:
        """
        Creates a structured FinalDecisionTrace.
        """
        return FinalDecisionTrace(
            strategy_mode=strategy_mode,
            objective_id=objective_id,
            thread_id=thread_id,
            hypothesis_id=hypothesis_id,
            experiment_id=experiment_id,
            evidence_id=evidence_id,
            finding_id=finding_id,
            validation_status=validation_status,
            final_decision=final_decision,
        )
