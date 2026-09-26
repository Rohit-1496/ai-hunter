"""
Phase 13: Core Knowledge Models

Structured, provenance-backed, confidence-aware persistent security knowledge models.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class KnowledgeType(str, Enum):
    """Types of reusable security knowledge."""
    MISSION_FACT = "MISSION_FACT"
    SECURITY_PATTERN = "SECURITY_PATTERN"
    VULNERABILITY_PATTERN = "VULNERABILITY_PATTERN"
    ATTACK_PATTERN = "ATTACK_PATTERN"
    ATTACK_CHAIN_PATTERN = "ATTACK_CHAIN_PATTERN"
    AUTHORIZATION_PATTERN = "AUTHORIZATION_PATTERN"
    AUTHENTICATION_PATTERN = "AUTHENTICATION_PATTERN"
    TENANT_ISOLATION_PATTERN = "TENANT_ISOLATION_PATTERN"
    WORKFLOW_PATTERN = "WORKFLOW_PATTERN"
    API_PATTERN = "API_PATTERN"
    TECHNOLOGY_PATTERN = "TECHNOLOGY_PATTERN"
    RESEARCH_HEURISTIC = "RESEARCH_HEURISTIC"
    HYPOTHESIS_PRIOR = "HYPOTHESIS_PRIOR"
    NEGATIVE_KNOWLEDGE = "NEGATIVE_KNOWLEDGE"
    ENVIRONMENTAL_KNOWLEDGE = "ENVIRONMENTAL_KNOWLEDGE"
    TOOL_BEHAVIOR = "TOOL_BEHAVIOR"
    FALSE_POSITIVE_PATTERN = "FALSE_POSITIVE_PATTERN"
    REMEDIATION_PATTERN = "REMEDIATION_PATTERN"


class KnowledgeStatus(str, Enum):
    """Validation and lifecycle status of a knowledge item."""
    CANDIDATE = "CANDIDATE"
    UNVALIDATED = "UNVALIDATED"
    VALIDATED = "VALIDATED"
    CORROBORATED = "CORROBORATED"
    CONTRADICTED = "CONTRADICTED"
    STALE = "STALE"
    DEPRECATED = "DEPRECATED"
    REJECTED = "REJECTED"
    ARCHIVED = "ARCHIVED"


class KnowledgeFreshness(str, Enum):
    """Context-aware freshness level of knowledge."""
    FRESH = "FRESH"
    AGING = "AGING"
    STALE = "STALE"
    EXPIRED = "EXPIRED"


class KnowledgePromotionLevel(str, Enum):
    """Promotion tier from mission-local to global corroboration."""
    MISSION_LOCAL = "MISSION_LOCAL"
    CANDIDATE_GLOBAL = "CANDIDATE_GLOBAL"
    VALIDATED_GLOBAL = "VALIDATED_GLOBAL"
    CORROBORATED_GLOBAL = "CORROBORATED_GLOBAL"


class KnowledgeUsageOutcome(str, Enum):
    """Outcome observed when applying a knowledge prior in a mission."""
    HELPFUL = "HELPFUL"
    NEUTRAL = "NEUTRAL"
    MISLEADING = "MISLEADING"
    CONTRADICTED = "CONTRADICTED"
    STALE = "STALE"
    IRRELEVANT = "IRRELEVANT"


class KnowledgeRelationshipType(str, Enum):
    """Directed relationships between knowledge graph nodes."""
    KNOWLEDGE_SUPPORTS = "KNOWLEDGE_SUPPORTS"
    KNOWLEDGE_CONTRADICTS = "KNOWLEDGE_CONTRADICTS"
    KNOWLEDGE_APPLIES_TO = "KNOWLEDGE_APPLIES_TO"
    KNOWLEDGE_DERIVED_FROM = "KNOWLEDGE_DERIVED_FROM"
    KNOWLEDGE_RELATED_TO = "KNOWLEDGE_RELATED_TO"
    KNOWLEDGE_REFINED_BY = "KNOWLEDGE_REFINED_BY"
    KNOWLEDGE_INVALIDATED_BY = "KNOWLEDGE_INVALIDATED_BY"
    KNOWLEDGE_CORROBORATED_BY = "KNOWLEDGE_CORROBORATED_BY"
    KNOWLEDGE_USED_BY = "KNOWLEDGE_USED_BY"


# Allowed status transitions to prevent arbitrary invalid jumps
ALLOWED_STATUS_TRANSITIONS: dict[KnowledgeStatus, set[KnowledgeStatus]] = {
    KnowledgeStatus.CANDIDATE: {
        KnowledgeStatus.UNVALIDATED,
        KnowledgeStatus.VALIDATED,
        KnowledgeStatus.CONTRADICTED,
        KnowledgeStatus.STALE,
        KnowledgeStatus.DEPRECATED,
        KnowledgeStatus.REJECTED,
        KnowledgeStatus.ARCHIVED,
    },
    KnowledgeStatus.UNVALIDATED: {
        KnowledgeStatus.VALIDATED,
        KnowledgeStatus.CONTRADICTED,
        KnowledgeStatus.STALE,
        KnowledgeStatus.REJECTED,
        KnowledgeStatus.ARCHIVED,
    },
    KnowledgeStatus.VALIDATED: {
        KnowledgeStatus.CORROBORATED,
        KnowledgeStatus.CONTRADICTED,
        KnowledgeStatus.STALE,
        KnowledgeStatus.DEPRECATED,
        KnowledgeStatus.ARCHIVED,
    },
    KnowledgeStatus.CORROBORATED: {
        KnowledgeStatus.CONTRADICTED,
        KnowledgeStatus.STALE,
        KnowledgeStatus.DEPRECATED,
        KnowledgeStatus.ARCHIVED,
    },
    KnowledgeStatus.CONTRADICTED: {
        KnowledgeStatus.VALIDATED,
        KnowledgeStatus.CORROBORATED,
        KnowledgeStatus.STALE,
        KnowledgeStatus.DEPRECATED,
        KnowledgeStatus.ARCHIVED,
    },
    KnowledgeStatus.STALE: {
        KnowledgeStatus.VALIDATED,
        KnowledgeStatus.CORROBORATED,
        KnowledgeStatus.DEPRECATED,
        KnowledgeStatus.ARCHIVED,
    },
    KnowledgeStatus.DEPRECATED: {
        KnowledgeStatus.ARCHIVED,
    },
    KnowledgeStatus.REJECTED: {
        KnowledgeStatus.ARCHIVED,
    },
    KnowledgeStatus.ARCHIVED: set(),
}


@dataclass
class KnowledgeVersion:
    """Immutable version snapshot of an evolving knowledge item."""
    version_id: str
    knowledge_id: str
    version_number: int
    statement: str
    rationale: str
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class SecurityKnowledge:
    """
    Core structured persistent security knowledge model.

    Every instance is provenance-backed, confidence-scored, and integrity-verified.
    """
    knowledge_id: str = field(default_factory=lambda: f"SKN-{secrets.token_hex(4).upper()}")
    knowledge_type: KnowledgeType = KnowledgeType.SECURITY_PATTERN
    title: str = ""
    statement: str = ""
    normalized_pattern: str = ""
    status: KnowledgeStatus = KnowledgeStatus.CANDIDATE
    promotion_level: KnowledgePromotionLevel = KnowledgePromotionLevel.MISSION_LOCAL
    confidence: float = 0.5
    
    # Provenance
    source_mission_ids: list[str] = field(default_factory=list)
    source_evidence_refs: list[str] = field(default_factory=list)
    source_finding_ids: list[str] = field(default_factory=list)
    source_hypothesis_ids: list[str] = field(default_factory=list)
    source_attack_path_ids: list[str] = field(default_factory=list)
    source_poc_ids: list[str] = field(default_factory=list)
    is_operator_authored: bool = False
    operator_id: str | None = None

    # Contextual Applicability
    affected_security_dimensions: list[str] = field(default_factory=list)
    applicable_asset_types: list[str] = field(default_factory=list)
    applicable_endpoint_types: list[str] = field(default_factory=list)
    applicable_technology: list[str] = field(default_factory=list)
    applicable_auth_model: list[str] = field(default_factory=list)
    applicable_role_model: list[str] = field(default_factory=list)
    applicable_tenant_model: list[str] = field(default_factory=list)
    applicable_workflow_model: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)

    # Validation & Evidence Counts
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    validation_count: int = 1
    contradiction_count: int = 0

    # Freshness & Decay
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_validated: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    freshness: KnowledgeFreshness = KnowledgeFreshness.FRESH
    decay_state: str = "ACTIVE"
    applicability_score: float = 1.0
    retrieval_score: float = 0.5

    # Usage & Feedback History
    usage_count: int = 0
    successful_use_count: int = 0
    failed_use_count: int = 0

    # Explainability & Metadata
    limitations: list[str] = field(default_factory=list)
    rationale: str = ""
    schema_version: str = "1.0.0"
    version: int = 1
    content_digest: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def compute_digest(self) -> str:
        """Computes deterministic SHA256 digest over canonical knowledge content."""
        canonical_data = {
            "knowledge_id": self.knowledge_id,
            "knowledge_type": self.knowledge_type.value if isinstance(self.knowledge_type, KnowledgeType) else self.knowledge_type,
            "title": self.title,
            "statement": self.statement,
            "normalized_pattern": self.normalized_pattern,
            "status": self.status.value if isinstance(self.status, KnowledgeStatus) else self.status,
            "promotion_level": self.promotion_level.value if isinstance(self.promotion_level, KnowledgePromotionLevel) else self.promotion_level,
            "source_mission_ids": sorted(self.source_mission_ids),
            "source_evidence_refs": sorted(self.source_evidence_refs),
            "applicable_technology": sorted(self.applicable_technology),
            "applicable_auth_model": sorted(self.applicable_auth_model),
            "preconditions": sorted(self.preconditions),
            "schema_version": self.schema_version,
            "version": self.version,
        }
        serialized = json.dumps(canonical_data, sort_keys=True, separators=(",", ":"))
        self.content_digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        return self.content_digest

    def verify_integrity(self) -> bool:
        """Verifies content digest matches current content."""
        stored = self.content_digest
        recomputed = self.compute_digest()
        return stored == recomputed

    def can_transition_to(self, target_status: KnowledgeStatus) -> bool:
        """Checks whether transition to target status is permitted."""
        allowed = ALLOWED_STATUS_TRANSITIONS.get(self.status, set())
        return target_status in allowed

    def to_dict(self) -> dict[str, Any]:
        """Serializes knowledge item to structured dictionary."""
        if not self.content_digest:
            self.compute_digest()
        return {
            "knowledge_id": self.knowledge_id,
            "knowledge_type": self.knowledge_type.value if isinstance(self.knowledge_type, KnowledgeType) else self.knowledge_type,
            "title": self.title,
            "statement": self.statement,
            "normalized_pattern": self.normalized_pattern,
            "status": self.status.value if isinstance(self.status, KnowledgeStatus) else self.status,
            "promotion_level": self.promotion_level.value if isinstance(self.promotion_level, KnowledgePromotionLevel) else self.promotion_level,
            "confidence": round(self.confidence, 4),
            "source_mission_ids": self.source_mission_ids,
            "source_evidence_refs": self.source_evidence_refs,
            "source_finding_ids": self.source_finding_ids,
            "source_hypothesis_ids": self.source_hypothesis_ids,
            "source_attack_path_ids": self.source_attack_path_ids,
            "source_poc_ids": self.source_poc_ids,
            "is_operator_authored": self.is_operator_authored,
            "operator_id": self.operator_id,
            "affected_security_dimensions": self.affected_security_dimensions,
            "applicable_asset_types": self.applicable_asset_types,
            "applicable_endpoint_types": self.applicable_endpoint_types,
            "applicable_technology": self.applicable_technology,
            "applicable_auth_model": self.applicable_auth_model,
            "applicable_role_model": self.applicable_role_model,
            "applicable_tenant_model": self.applicable_tenant_model,
            "applicable_workflow_model": self.applicable_workflow_model,
            "preconditions": self.preconditions,
            "supporting_evidence": self.supporting_evidence,
            "contradicting_evidence": self.contradicting_evidence,
            "validation_count": self.validation_count,
            "contradiction_count": self.contradiction_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "last_validated": self.last_validated,
            "freshness": self.freshness.value if isinstance(self.freshness, KnowledgeFreshness) else self.freshness,
            "decay_state": self.decay_state,
            "applicability_score": round(self.applicability_score, 4),
            "retrieval_score": round(self.retrieval_score, 4),
            "usage_count": self.usage_count,
            "successful_use_count": self.successful_use_count,
            "failed_use_count": self.failed_use_count,
            "limitations": self.limitations,
            "rationale": self.rationale,
            "schema_version": self.schema_version,
            "version": self.version,
            "content_digest": self.content_digest,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecurityKnowledge:
        """Constructs SecurityKnowledge from dictionary."""
        ktype_raw = data.get("knowledge_type", KnowledgeType.SECURITY_PATTERN.value)
        ktype = KnowledgeType(ktype_raw) if ktype_raw in [e.value for e in KnowledgeType] else KnowledgeType.SECURITY_PATTERN

        kstatus_raw = data.get("status", KnowledgeStatus.CANDIDATE.value)
        kstatus = KnowledgeStatus(kstatus_raw) if kstatus_raw in [e.value for e in KnowledgeStatus] else KnowledgeStatus.CANDIDATE

        kprom_raw = data.get("promotion_level", KnowledgePromotionLevel.MISSION_LOCAL.value)
        kprom = KnowledgePromotionLevel(kprom_raw) if kprom_raw in [e.value for e in KnowledgePromotionLevel] else KnowledgePromotionLevel.MISSION_LOCAL

        kfresh_raw = data.get("freshness", KnowledgeFreshness.FRESH.value)
        kfresh = KnowledgeFreshness(kfresh_raw) if kfresh_raw in [e.value for e in KnowledgeFreshness] else KnowledgeFreshness.FRESH

        item = cls(
            knowledge_id=data.get("knowledge_id", f"SKN-{secrets.token_hex(4).upper()}"),
            knowledge_type=ktype,
            title=data.get("title", ""),
            statement=data.get("statement", ""),
            normalized_pattern=data.get("normalized_pattern", ""),
            status=kstatus,
            promotion_level=kprom,
            confidence=float(data.get("confidence", 0.5)),
            source_mission_ids=list(data.get("source_mission_ids", [])),
            source_evidence_refs=list(data.get("source_evidence_refs", [])),
            source_finding_ids=list(data.get("source_finding_ids", [])),
            source_hypothesis_ids=list(data.get("source_hypothesis_ids", [])),
            source_attack_path_ids=list(data.get("source_attack_path_ids", [])),
            source_poc_ids=list(data.get("source_poc_ids", [])),
            is_operator_authored=bool(data.get("is_operator_authored", False)),
            operator_id=data.get("operator_id"),
            affected_security_dimensions=list(data.get("affected_security_dimensions", [])),
            applicable_asset_types=list(data.get("applicable_asset_types", [])),
            applicable_endpoint_types=list(data.get("applicable_endpoint_types", [])),
            applicable_technology=list(data.get("applicable_technology", [])),
            applicable_auth_model=list(data.get("applicable_auth_model", [])),
            applicable_role_model=list(data.get("applicable_role_model", [])),
            applicable_tenant_model=list(data.get("applicable_tenant_model", [])),
            applicable_workflow_model=list(data.get("applicable_workflow_model", [])),
            preconditions=list(data.get("preconditions", [])),
            supporting_evidence=list(data.get("supporting_evidence", [])),
            contradicting_evidence=list(data.get("contradicting_evidence", [])),
            validation_count=int(data.get("validation_count", 1)),
            contradiction_count=int(data.get("contradiction_count", 0)),
            first_seen=data.get("first_seen", datetime.now(timezone.utc).isoformat()),
            last_seen=data.get("last_seen", datetime.now(timezone.utc).isoformat()),
            last_validated=data.get("last_validated", datetime.now(timezone.utc).isoformat()),
            freshness=kfresh,
            decay_state=data.get("decay_state", "ACTIVE"),
            applicability_score=float(data.get("applicability_score", 1.0)),
            retrieval_score=float(data.get("retrieval_score", 0.5)),
            usage_count=int(data.get("usage_count", 0)),
            successful_use_count=int(data.get("successful_use_count", 0)),
            failed_use_count=int(data.get("failed_use_count", 0)),
            limitations=list(data.get("limitations", [])),
            rationale=data.get("rationale", ""),
            schema_version=data.get("schema_version", "1.0.0"),
            version=int(data.get("version", 1)),
            content_digest=data.get("content_digest", ""),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=data.get("updated_at", datetime.now(timezone.utc).isoformat()),
        )
        if not item.content_digest:
            item.compute_digest()
        return item


@dataclass
class KnowledgeUsageRecord:
    """Feedback tracking record for a knowledge item used in a mission."""
    usage_id: str = field(default_factory=lambda: f"USE-{secrets.token_hex(4).upper()}")
    knowledge_id: str = ""
    mission_id: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    retrieved_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    used_for: str = ""
    resulting_hypothesis_id: str | None = None
    resulting_experiment_id: str | None = None
    outcome: KnowledgeUsageOutcome = KnowledgeUsageOutcome.NEUTRAL
    useful: bool = False
    confidence_delta: float = 0.0
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "usage_id": self.usage_id,
            "knowledge_id": self.knowledge_id,
            "mission_id": self.mission_id,
            "context": self.context,
            "retrieved_at": self.retrieved_at,
            "used_for": self.used_for,
            "resulting_hypothesis_id": self.resulting_hypothesis_id,
            "resulting_experiment_id": self.resulting_experiment_id,
            "outcome": self.outcome.value if isinstance(self.outcome, KnowledgeUsageOutcome) else self.outcome,
            "useful": self.useful,
            "confidence_delta": round(self.confidence_delta, 4),
            "notes": self.notes,
        }


@dataclass
class MissionKnowledgeReference:
    """Traceable linkage between a mission decision and a retrieved knowledge item."""
    reference_id: str = field(default_factory=lambda: f"REF-KN-{secrets.token_hex(4).upper()}")
    mission_id: str = ""
    knowledge_id: str = ""
    retrieved_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    relevance: float = 0.5
    applicability: float = 0.5
    confidence: float = 0.5
    freshness: KnowledgeFreshness = KnowledgeFreshness.FRESH
    statement_summary: str = ""
    role_label: str = "HISTORICAL_PRIOR"
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "reference_id": self.reference_id,
            "mission_id": self.mission_id,
            "knowledge_id": self.knowledge_id,
            "retrieved_at": self.retrieved_at,
            "relevance": round(self.relevance, 4),
            "applicability": round(self.applicability, 4),
            "confidence": round(self.confidence, 4),
            "freshness": self.freshness.value if isinstance(self.freshness, KnowledgeFreshness) else self.freshness,
            "statement_summary": self.statement_summary,
            "role_label": self.role_label,
            "rationale": self.rationale,
        }


@dataclass
class KnowledgeRationale:
    """Explainable rationale detailing why knowledge was created or retrieved."""
    rationale_id: str = field(default_factory=lambda: f"RAT-KN-{secrets.token_hex(4).upper()}")
    knowledge_id: str = ""
    reason_created: str = ""
    source_evidence_summary: str = ""
    abstraction_performed: str = ""
    why_reusable: str = ""
    applicable_contexts: list[str] = field(default_factory=list)
    non_applicable_contexts: list[str] = field(default_factory=list)
    confidence_explanation: str = ""
    freshness_explanation: str = ""
    contradictions_noted: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "rationale_id": self.rationale_id,
            "knowledge_id": self.knowledge_id,
            "reason_created": self.reason_created,
            "source_evidence_summary": self.source_evidence_summary,
            "abstraction_performed": self.abstraction_performed,
            "why_reusable": self.why_reusable,
            "applicable_contexts": self.applicable_contexts,
            "non_applicable_contexts": self.non_applicable_contexts,
            "confidence_explanation": self.confidence_explanation,
            "freshness_explanation": self.freshness_explanation,
            "contradictions_noted": self.contradictions_noted,
            "limitations": self.limitations,
            "created_at": self.created_at,
        }


@dataclass
class KnowledgeMetrics:
    """Global aggregate metrics for the persistent security knowledge subsystem."""
    total_knowledge_items: int = 0
    candidate_items: int = 0
    validated_items: int = 0
    corroborated_items: int = 0
    stale_items: int = 0
    contradicted_items: int = 0
    deprecated_items: int = 0
    knowledge_by_type: dict[str, int] = field(default_factory=dict)
    knowledge_by_confidence: dict[str, int] = field(default_factory=dict)
    average_retrieval_relevance: float = 0.0
    successful_reuse_rate: float = 0.0
    misleading_reuse_rate: float = 0.0
    contradiction_rate: float = 0.0
    poisoning_rejection_count: int = 0
    knowledge_promotion_count: int = 0
    knowledge_demotion_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_knowledge_items": self.total_knowledge_items,
            "candidate_items": self.candidate_items,
            "validated_items": self.validated_items,
            "corroborated_items": self.corroborated_items,
            "stale_items": self.stale_items,
            "contradicted_items": self.contradicted_items,
            "deprecated_items": self.deprecated_items,
            "knowledge_by_type": self.knowledge_by_type,
            "knowledge_by_confidence": self.knowledge_by_confidence,
            "average_retrieval_relevance": round(self.average_retrieval_relevance, 4),
            "successful_reuse_rate": round(self.successful_reuse_rate, 4),
            "misleading_reuse_rate": round(self.misleading_reuse_rate, 4),
            "contradiction_rate": round(self.contradiction_rate, 4),
            "poisoning_rejection_count": self.poisoning_rejection_count,
            "knowledge_promotion_count": self.knowledge_promotion_count,
            "knowledge_demotion_count": self.knowledge_demotion_count,
        }


@dataclass
class KnowledgeStoreVersion:
    """Global knowledge store version and schema digest."""
    store_version: str = "1.0.0"
    schema_version: str = "1.0.0"
    migration_version: int = 1
    total_records: int = 0
    store_digest: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "store_version": self.store_version,
            "schema_version": self.schema_version,
            "migration_version": self.migration_version,
            "total_records": self.total_records,
            "store_digest": self.store_digest,
            "created_at": self.created_at,
        }
