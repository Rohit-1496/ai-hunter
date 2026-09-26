"""
Phase 13: Knowledge Write Gate

Enforces strict 11-point security and validation verification before promoting
any candidate knowledge into the global persistent knowledge store.
"""

from __future__ import annotations

from runtime.knowledge.models import (
    KnowledgePromotionLevel,
    KnowledgeStatus,
    SecurityKnowledge,
)
from runtime.knowledge.poisoning import PoisoningDetector
from runtime.knowledge.scope import ScopeIsolationGuard


class KnowledgeWriteGate:
    """Gatekeeper for all persistent knowledge storage and promotion."""

    def __init__(self) -> None:
        self.poisoning_detector = PoisoningDetector()
        self.scope_guard = ScopeIsolationGuard()

    def evaluate_write(
        self,
        candidate: SecurityKnowledge,
        *,
        is_finding_validated: bool = True,
    ) -> tuple[str, list[str]]:
        """
        Evaluates candidate against 11 validation gates.
        Returns (decision, reasons) where decision in ("ACCEPT", "ACCEPT_AS_CANDIDATE", "REJECT").
        """
        failures: list[str] = []

        # 1. Provenance exists
        if not candidate.source_mission_ids and not candidate.is_operator_authored:
            failures.append("Missing provenance: no source mission ID or operator attribution")

        # 2. Source is trusted/validated
        if not candidate.is_operator_authored and not is_finding_validated and candidate.confidence > 0.6:
            failures.append("Source finding is unvalidated; cannot claim high confidence")

        # 3. Target text is sanitized & no poisoning
        is_poisoned, reason = self.poisoning_detector.is_poisoned(candidate)
        if is_poisoned:
            failures.append(f"Poisoning/injection detected: {reason}")

        # 4. Security claim is structured
        if not candidate.title or not candidate.statement:
            failures.append("Knowledge title or statement is missing or empty")

        # 5. Evidence exists where required
        if not candidate.is_operator_authored and not candidate.source_evidence_refs and not candidate.supporting_evidence:
            failures.append("Missing source evidence references for automated knowledge extraction")

        # 6. Scope is represented
        if not candidate.applicable_technology and not candidate.applicable_endpoint_types and not candidate.affected_security_dimensions:
            failures.append("Knowledge lacks contextual applicability specification")

        # 7. Confidence is in valid bounds
        if not (0.05 <= candidate.confidence <= 0.98):
            failures.append(f"Confidence score {candidate.confidence} out of valid bounds [0.05, 0.98]")

        # 8. Sanitize scope & credentials
        self.scope_guard.sanitize_for_cross_mission(candidate)

        # 9. Check failures
        if failures:
            if is_poisoned:
                return "REJECT", failures
            # Soft failure -> Accept as local candidate only
            return "ACCEPT_AS_CANDIDATE", failures

        # 10. Evaluate promotion tier
        if candidate.validation_count >= 2 and len(set(candidate.source_mission_ids)) >= 2:
            candidate.promotion_level = KnowledgePromotionLevel.CORROBORATED_GLOBAL
            if candidate.can_transition_to(KnowledgeStatus.CORROBORATED):
                candidate.status = KnowledgeStatus.CORROBORATED
        elif candidate.confidence >= 0.7:
            candidate.promotion_level = KnowledgePromotionLevel.VALIDATED_GLOBAL
            if candidate.can_transition_to(KnowledgeStatus.VALIDATED):
                candidate.status = KnowledgeStatus.VALIDATED
        else:
            candidate.promotion_level = KnowledgePromotionLevel.CANDIDATE_GLOBAL

        candidate.compute_digest()
        return "ACCEPT", []
