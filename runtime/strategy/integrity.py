"""
Phase 14: Strategic Integrity Verifier

Validates SHA256 content digests for all strategic state and objective records.
Fails closed if corruption or unauthorized tampering is detected.
"""

from __future__ import annotations

from typing import Any
from runtime.strategy.models import StrategicObjective, StrategicState


class StrategicIntegrityVerifier:
    """Verifies cryptographic integrity of strategic artifacts."""

    @staticmethod
    def verify_objective(objective: StrategicObjective) -> bool:
        return objective.verify_integrity()

    @staticmethod
    def verify_state(state: StrategicState) -> bool:
        return state.verify_integrity()
