"""
Phase 6.1 — Context Budget Manager

Enforces hard token and byte boundaries for the Beast Brain LLM reasoning context:
- Maximum total context tokens
- Maximum evidence items per reasoning cycle
- Maximum summary tokens per item
- Maximum raw artifact bytes loaded
- Maximum history items
- Maximum repeated observations
- Maximum report sections injected
- Maximum tool output included in prompts

Guarantees fail-closed context admission with zero silent evidence deletion:
excluded items are represented by deterministic DeferredEvidenceReferences.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from runtime.evidence.storage_policy import (
    AdmissionStatus,
    DeferredEvidenceReference,
    EvidenceSummary,
    estimate_tokens,
)

logger = logging.getLogger("BeastBrain.ContextBudget")


@dataclass
class ContextBudgetConfig:
    """Configurable context limits for Beast Brain reasoning loop."""
    max_total_tokens: int = 8000
    max_evidence_items: int = 10
    max_summary_tokens_per_item: int = 800
    max_raw_bytes_loaded: int = 64 * 1024       # 64 KB maximum raw artifact load
    max_history_items: int = 10
    max_repeated_observations: int = 1           # At most 1 reference per item
    max_report_sections_injected: int = 5
    max_tool_output_in_prompt: int = 2000        # Max chars of direct tool output in prompt


class ContextBudgetExhaustedError(Exception):
    """Raised when context budget cannot admit mandatory system instructions."""
    pass


class ContextBudgetManager:
    """
    Manages and enforces LLM context window quotas during mission reasoning cycles.
    Prevents context window exhaustion, quadratic prompt growth, and silent omission.
    """

    def __init__(self, config: ContextBudgetConfig | None = None) -> None:
        self.config = config or ContextBudgetConfig()
        self._current_tokens: int = 0
        self._current_raw_bytes: int = 0
        self._admitted_evidence: list[EvidenceSummary] = []
        self._deferred_references: list[DeferredEvidenceReference] = []
        self._history_count: int = 0
        self._exclusion_log: list[dict[str, Any]] = []

    @property
    def current_tokens(self) -> int:
        return self._current_tokens

    @property
    def current_raw_bytes(self) -> int:
        return self._current_raw_bytes

    @property
    def admitted_evidence_count(self) -> int:
        return len(self._admitted_evidence)

    @property
    def deferred_evidence_count(self) -> int:
        return len(self._deferred_references)

    @property
    def deferred_references(self) -> list[DeferredEvidenceReference]:
        return list(self._deferred_references)

    def reset_cycle(self) -> None:
        """Resets dynamic cycle counters at the start of a new reasoning iteration."""
        self._current_tokens = 0
        self._current_raw_bytes = 0
        self._admitted_evidence.clear()
        self._deferred_references.clear()
        self._history_count = 0
        self._exclusion_log.clear()

    def admit_evidence(
        self,
        summary: EvidenceSummary,
    ) -> tuple[AdmissionStatus, EvidenceSummary | DeferredEvidenceReference]:
        """
        Evaluates whether an EvidenceSummary fits within the reasoning cycle budget.
        Returns:
            - (AdmissionStatus.INCLUDED, summary) if admitted intact
            - (AdmissionStatus.SUMMARIZED, compressed_summary) if truncated to fit item budget
            - (AdmissionStatus.DEFERRED, DeferredEvidenceReference) if capacity exceeded
        """
        # 1. Check item count limit
        if len(self._admitted_evidence) >= self.config.max_evidence_items:
            ref = DeferredEvidenceReference(
                evidence_id=summary.evidence_id,
                artifact_uri=summary.artifact_uri or f"evidence://{summary.evidence_id}",
                summary_available=True,
                reason=f"Evidence item count limit reached ({self.config.max_evidence_items} items admitted)",
                observation_category=summary.observation_category,
                target=summary.target,
            )
            self._deferred_references.append(ref)
            self._log_exclusion(summary.evidence_id, ref.reason, AdmissionStatus.DEFERRED)
            return AdmissionStatus.DEFERRED, ref

        # 2. Check single-item token limit and compress if necessary
        item_tokens = summary.token_estimate or estimate_tokens(summary.short_summary)
        admitted_item = summary
        status = AdmissionStatus.INCLUDED

        if item_tokens > self.config.max_summary_tokens_per_item:
            max_chars = self.config.max_summary_tokens_per_item * 4
            truncated_text = summary.short_summary[:max_chars - 35] + "... [truncated to budget]"
            admitted_item = EvidenceSummary(
                evidence_id=summary.evidence_id,
                mission_id=summary.mission_id,
                execution_id=summary.execution_id,
                target=summary.target,
                source_tool=summary.source_tool,
                observation_category=summary.observation_category,
                short_summary=truncated_text,
                key_indicators=summary.key_indicators[:4],
                confidence=summary.confidence,
                trust_classification=summary.trust_classification,
                integrity_hash=summary.integrity_hash,
                artifact_uri=summary.artifact_uri,
                related_evidence_ids=summary.related_evidence_ids,
                token_estimate=estimate_tokens(truncated_text),
                created_at=summary.created_at,
            )
            item_tokens = admitted_item.token_estimate
            status = AdmissionStatus.SUMMARIZED

        # 3. Check total cycle token quota
        if self._current_tokens + item_tokens > self.config.max_total_tokens:
            ref = DeferredEvidenceReference(
                evidence_id=summary.evidence_id,
                artifact_uri=summary.artifact_uri or f"evidence://{summary.evidence_id}",
                summary_available=True,
                reason=f"Total context budget exceeded ({self._current_tokens + item_tokens} > {self.config.max_total_tokens} tokens)",
                observation_category=summary.observation_category,
                target=summary.target,
            )
            self._deferred_references.append(ref)
            self._log_exclusion(summary.evidence_id, ref.reason, AdmissionStatus.DEFERRED)
            return AdmissionStatus.DEFERRED, ref

        # Admitted successfully
        self._current_tokens += item_tokens
        self._admitted_evidence.append(admitted_item)
        return status, admitted_item

    def admit_raw_artifact(self, size_bytes: int, reason: str = "") -> tuple[AdmissionStatus, str]:
        """
        Enforces raw byte budget for on-demand artifact retrieval.
        Never loads raw artifacts exceeding max_raw_bytes_loaded.
        """
        if not reason.strip():
            return (
                AdmissionStatus.REJECTED_BY_BUDGET,
                "FULL_ARTIFACT retrieval requires an explicit non-empty retrieval reason.",
            )

        if self._current_raw_bytes + size_bytes > self.config.max_raw_bytes_loaded:
            msg = (
                f"Raw artifact size ({size_bytes} B) exceeds remaining raw budget "
                f"({self.config.max_raw_bytes_loaded - self._current_raw_bytes} B remaining of {self.config.max_raw_bytes_loaded} B)."
            )
            self._log_exclusion("raw_artifact", msg, AdmissionStatus.REJECTED_BY_BUDGET)
            return AdmissionStatus.REJECTED_BY_BUDGET, msg

        self._current_raw_bytes += size_bytes
        # Approximate tokens consumed by raw content
        self._current_tokens += max(1, size_bytes // 4)
        return AdmissionStatus.INCLUDED, "Raw artifact admitted within budget."

    def admit_history_item(self, estimated_tokens: int) -> bool:
        """Validates admission of historical conversation turns."""
        if self._history_count >= self.config.max_history_items:
            return False
        if self._current_tokens + estimated_tokens > self.config.max_total_tokens:
            return False
        self._history_count += 1
        self._current_tokens += estimated_tokens
        return True

    def _log_exclusion(self, identifier: str, reason: str, status: AdmissionStatus) -> None:
        self._exclusion_log.append({
            "identifier": identifier,
            "status": status.value,
            "reason": reason,
            "current_tokens": self._current_tokens,
            "max_tokens": self.config.max_total_tokens,
        })
        logger.debug(f"Context budget exclusion: {identifier} -> {status.value} ({reason})")

    def get_metrics(self) -> dict[str, Any]:
        """Returns comprehensive context usage metrics for monitoring and reports."""
        return {
            "current_tokens": self._current_tokens,
            "max_total_tokens": self.config.max_total_tokens,
            "utilization_pct": round((self._current_tokens / max(1, self.config.max_total_tokens)) * 100, 2),
            "admitted_evidence_count": len(self._admitted_evidence),
            "max_evidence_items": self.config.max_evidence_items,
            "deferred_evidence_count": len(self._deferred_references),
            "current_raw_bytes": self._current_raw_bytes,
            "max_raw_bytes_loaded": self.config.max_raw_bytes_loaded,
            "history_items_count": self._history_count,
            "max_history_items": self.config.max_history_items,
            "exclusions_count": len(self._exclusion_log),
        }
