"""
Phase 9: Failure Diagnostician & Negative Learning Engine
Analyzes failed experiments, diagnoses root causes, extracts reusable negative knowledge,
and detects dead-ends and diminishing returns.
"""

from __future__ import annotations

import secrets
from typing import Any

from runtime.adaptive.model import (
    FailureCause,
    FailureDiagnosis,
)


class FailureDiagnostician:
    """
    Transforms failed experiments into structured security learning and actionable research gaps.
    """

    def __init__(self) -> None:
        self._diagnoses: list[FailureDiagnosis] = []
        self._action_failure_counts: dict[str, int] = {}

    @property
    def diagnoses(self) -> list[FailureDiagnosis]:
        return self._diagnoses

    def diagnose_failure(
        self,
        action_id: str,
        target: str,
        status_code: int,
        response_body: str,
        tested_hypothesis_statement: str | None = None,
        evidence_id: str | None = None
    ) -> FailureDiagnosis:
        """
        Diagnoses why an action failed and formulates structured learning.
        """
        d_id = f"DIAG-{secrets.token_hex(4).upper()}"
        invalidated_asms: list[str] = []
        remaining_unks: list[str] = []
        suggested_pivots: list[str] = []

        # Track failure count per target
        self._action_failure_counts[target] = self._action_failure_counts.get(target, 0) + 1

        # Classify Failure Cause
        if status_code == 403:
            cause = FailureCause.AUTHORIZATION_BLOCK
            learning = f"Authorization block on {target}: Server enforces independent server-side permission check rejecting unprivileged or transferred credentials."
            if tested_hypothesis_statement:
                invalidated_asms.append(f"Assumption invalidated: '{tested_hypothesis_statement}' was rejected by server-side authorization enforcement.")
            remaining_unks.append(f"Does an alternate API version or workflow route exist that omits this authorization gate?")
            suggested_pivots.extend(["API_VERSION_PIVOT", "WORKFLOW_STATE_PIVOT", "IDENTITY_PIVOT"])

        elif status_code == 401:
            cause = FailureCause.AUTHENTICATION_BLOCK
            learning = f"Authentication block on {target}: Endpoint strictly requires valid session token or rejects expired/tampered credentials."
            remaining_unks.append(f"Can a fresh authenticated session be established to probe secondary permissions?")
            suggested_pivots.extend(["IDENTITY_PIVOT", "TOKEN_REFRESH_PIVOT"])

        elif status_code == 404:
            cause = FailureCause.ENDPOINT_MISMATCH
            learning = f"Endpoint {target} was not found (404), indicating the route does not exist or access is masked."
            remaining_unks.append(f"What active endpoint variant corresponds to this resource?")
            suggested_pivots.extend(["ENDPOINT_VARIANT_PIVOT", "API_VERSION_PIVOT"])

        elif status_code == 429:
            cause = FailureCause.RATE_LIMIT
            learning = f"Rate limit encountered on {target}; transient request throttling active."
            suggested_pivots.append("RATE_LIMIT_BACKOFF")

        else:
            cause = FailureCause.UNKNOWN
            learning = f"Unexpected response HTTP {status_code} on {target} without confirmed vulnerability behavior."
            suggested_pivots.append("ALTERNATIVE_HYPOTHESIS_PIVOT")

        diag = FailureDiagnosis(
            diagnosis_id=d_id,
            action_id=action_id,
            target=target,
            failure_cause=cause,
            observed_status=status_code,
            learning=learning,
            invalidated_assumptions=invalidated_asms,
            remaining_unknowns=remaining_unks,
            suggested_pivots=suggested_pivots,
            evidence_id=evidence_id
        )
        self._diagnoses.append(diag)
        return diag

    def is_dead_end(self, target: str, threshold: int = 2) -> bool:
        """
        Determines whether a research target has become a dead end due to repeated failures.
        """
        return self._action_failure_counts.get(target, 0) >= threshold
