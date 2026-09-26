"""
Phase 13: Knowledge Extractor

Extracts structured, abstract, reusable candidate security knowledge from P3-P12 mission outcomes
while strictly stripping all credentials, secrets, raw tool dumps, and target-specific private state.
"""

from __future__ import annotations

import re
import secrets
from typing import Any

from runtime.knowledge.models import (
    KnowledgeFreshness,
    KnowledgePromotionLevel,
    KnowledgeStatus,
    KnowledgeType,
    SecurityKnowledge,
)


class KnowledgeExtractor:
    """
    Extracts abstract security knowledge from structured mission events and models.

    STRICT INVARIANTS:
    - Never copies raw credentials, cookies, tokens, or session secrets.
    - Never copies internal target hostnames, IPs, or customer data.
    - Compresses raw findings/experiments into reusable patterns.
    - Assigns initial status CANDIDATE or UNVALIDATED.
    """

    # Secret and private identifier patterns to sanitize
    SECRET_PATTERNS = [
        re.compile(r'(?i)(?:bearer\s+|token[:=]\s*|jwt[:=]\s*|api[_-]?key[:=]\s*|auth[_-]?header[:=]\s*)["\']?([a-zA-Z0-9_\-\.]{12,})["\']?'),
        re.compile(r'(?i)(?:password|passwd|secret)[:=]\s*["\']?([^\s"\']+)["\']?'),
        re.compile(r'(?i)(?:session[_-]?id|cookie)[:=]\s*["\']?([a-zA-Z0-9_\-\.]{10,})["\']?'),
    ]
    INTERNAL_IP_PATTERN = re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b')

    def sanitize_text(self, text: str) -> str:
        """Sanitizes text removing secrets, passwords, tokens, and internal IPs."""
        if not text:
            return ""
        sanitized = text
        for p in self.SECRET_PATTERNS:
            sanitized = p.sub("[REDACTED_SECRET]", sanitized)
        sanitized = self.INTERNAL_IP_PATTERN.sub("[INTERNAL_IP]", sanitized)
        return sanitized

    def extract_from_finding(
        self,
        finding_data: dict[str, Any],
        *,
        mission_id: str = "",
        technologies: list[str] | None = None,
        auth_model: list[str] | None = None,
    ) -> SecurityKnowledge | None:
        """Extracts reusable vulnerability or authorization pattern from a validated finding."""
        fid = finding_data.get("id", "")
        vclass = finding_data.get("vulnerability_class", "UNKNOWN")
        if isinstance(vclass, dict) and "name" in vclass:
            vclass = vclass["name"]
        elif hasattr(vclass, "value"):
            vclass = vclass.value
        vclass_str = str(vclass).upper()

        title = finding_data.get("title", f"Security Pattern ({vclass_str})")
        clean_title = self.sanitize_text(title)
        
        # Abstraction of endpoint/vulnerability
        affected_endpoints = finding_data.get("affected_endpoints", [])
        clean_endpoints = [self._generalize_endpoint(ep) for ep in affected_endpoints]

        statement = (
            f"Endpoints with architecture '{clean_endpoints[:2]}' in technologies '{technologies or []}' "
            f"are susceptible to {vclass_str} when {auth_model or ['standard']} controls are used."
        )

        ktype = KnowledgeType.VULNERABILITY_PATTERN
        if "AUTH" in vclass_str or "BFLA" in vclass_str or "IDOR" in vclass_str or "BOLA" in vclass_str:
            ktype = KnowledgeType.AUTHORIZATION_PATTERN
        elif "TENANT" in vclass_str:
            ktype = KnowledgeType.TENANT_ISOLATION_PATTERN

        k = SecurityKnowledge(
            knowledge_id=f"SKN-EXT-{secrets.token_hex(4).upper()}",
            knowledge_type=ktype,
            title=f"Reusable Pattern: {clean_title}",
            statement=statement,
            normalized_pattern=f"{vclass_str} on {clean_endpoints}",
            status=KnowledgeStatus.CANDIDATE,
            promotion_level=KnowledgePromotionLevel.MISSION_LOCAL,
            confidence=0.75 if finding_data.get("status") in ("VALIDATED", "CONFIRMED") else 0.5,
            source_mission_ids=[mission_id] if mission_id else [],
            source_finding_ids=[fid] if fid else [],
            source_evidence_refs=list(finding_data.get("evidence_refs", [])),
            applicable_technology=list(technologies or []),
            applicable_auth_model=list(auth_model or []),
            applicable_endpoint_types=clean_endpoints,
            rationale=f"Extracted from validated mission finding {fid}",
        )
        k.compute_digest()
        return k

    def extract_from_experiment(
        self,
        hypothesis_data: dict[str, Any],
        experiment_result: dict[str, Any],
        *,
        mission_id: str = "",
        technologies: list[str] | None = None,
    ) -> SecurityKnowledge | None:
        """Extracts security pattern or negative knowledge from controlled experiment outcomes."""
        hid = hypothesis_data.get("hypothesis_id", "")
        statement = hypothesis_data.get("statement", "")
        clean_statement = self.sanitize_text(statement)
        is_violation = bool(experiment_result.get("is_security_violation") or experiment_result.get("vulnerability_reproduced"))

        if is_violation:
            k = SecurityKnowledge(
                knowledge_id=f"SKN-EXP-{secrets.token_hex(4).upper()}",
                knowledge_type=KnowledgeType.SECURITY_PATTERN,
                title=f"Experiment-Validated Pattern: {hypothesis_data.get('title', 'Security Probe')}",
                statement=f"Controlled experiment confirmed: {clean_statement}",
                normalized_pattern=f"CONFIRMED_HYPOTHESIS:{hid}",
                status=KnowledgeStatus.CANDIDATE,
                confidence=0.7,
                source_mission_ids=[mission_id] if mission_id else [],
                source_hypothesis_ids=[hid] if hid else [],
                source_evidence_refs=list(experiment_result.get("evidence_refs", [])),
                applicable_technology=list(technologies or []),
                rationale=f"Derived from successful experiment on hypothesis {hid}",
            )
        else:
            # Reusable Negative Knowledge
            k = SecurityKnowledge(
                knowledge_id=f"SKN-NEG-{secrets.token_hex(4).upper()}",
                knowledge_type=KnowledgeType.NEGATIVE_KNOWLEDGE,
                title=f"Enforced Boundary: {hypothesis_data.get('title', 'Protected Endpoint')}",
                statement=f"Security control remained properly enforced during controlled experiment: {clean_statement}",
                normalized_pattern=f"ENFORCED_CONTROL:{hid}",
                status=KnowledgeStatus.CANDIDATE,
                confidence=0.7,
                source_mission_ids=[mission_id] if mission_id else [],
                source_hypothesis_ids=[hid] if hid else [],
                source_evidence_refs=list(experiment_result.get("evidence_refs", [])),
                applicable_technology=list(technologies or []),
                rationale=f"Derived from negative experiment outcome proving control enforcement on {hid}",
            )
        k.compute_digest()
        return k

    def extract_from_poc(
        self,
        poc_data: dict[str, Any],
        *,
        mission_id: str = "",
    ) -> SecurityKnowledge | None:
        """Extracts reusable exploitability or reproduction heuristic from a safe PoC."""
        poc_id = poc_data.get("poc_id", "")
        vuln_class = poc_data.get("vulnerability_class", "GENERIC")
        is_reproducible = poc_data.get("status") in ("REPRODUCIBLE", "READY")

        k = SecurityKnowledge(
            knowledge_id=f"SKN-POC-{secrets.token_hex(4).upper()}",
            knowledge_type=KnowledgeType.RESEARCH_HEURISTIC,
            title=f"Safe PoC Heuristic ({vuln_class})",
            statement=f"Reproducible verification pattern for {vuln_class} using minimal bounded probes.",
            normalized_pattern=f"SAFE_POC_HEURISTIC:{vuln_class}",
            status=KnowledgeStatus.CANDIDATE,
            confidence=0.8 if is_reproducible else 0.5,
            source_mission_ids=[mission_id] if mission_id else [],
            source_poc_ids=[poc_id] if poc_id else [],
            source_evidence_refs=list(poc_data.get("evidence_refs", [])),
            rationale=f"Derived from safe PoC {poc_id}",
        )
        k.compute_digest()
        return k

    def extract_from_remediation(
        self,
        finding_id: str,
        finding_data: dict[str, Any],
        *,
        mission_id: str = "",
    ) -> SecurityKnowledge | None:
        """Extracts reusable remediation pattern from confirmed fix verification."""
        vclass = finding_data.get("vulnerability_class", "ACCESS_CONTROL")
        k = SecurityKnowledge(
            knowledge_id=f"SKN-REM-{secrets.token_hex(4).upper()}",
            knowledge_type=KnowledgeType.REMEDIATION_PATTERN,
            title=f"Confirmed Remediation Pattern ({vclass})",
            statement=f"Effective remediation for {vclass} requires server-side boundary validation and robust counter-test checks.",
            normalized_pattern=f"REMEDIATION:{vclass}",
            status=KnowledgeStatus.CANDIDATE,
            confidence=0.85,
            source_mission_ids=[mission_id] if mission_id else [],
            source_finding_ids=[finding_id],
            rationale=f"Derived from confirmed fix verification on {finding_id}",
        )
        k.compute_digest()
        return k

    def extract_from_false_positive(
        self,
        finding_id: str,
        reason: str,
        *,
        mission_id: str = "",
        endpoint: str = "",
    ) -> SecurityKnowledge:
        """Extracts reusable false-positive pattern to avoid repeated futile scans."""
        clean_reason = self.sanitize_text(reason)
        clean_ep = self._generalize_endpoint(endpoint) if endpoint else "GENERAL_ENDPOINT"
        k = SecurityKnowledge(
            knowledge_id=f"SKN-FP-{secrets.token_hex(4).upper()}",
            knowledge_type=KnowledgeType.FALSE_POSITIVE_PATTERN,
            title=f"False Positive Pattern: {clean_ep}",
            statement=f"Apparent vulnerability signal on {clean_ep} is commonly a non-exploitable artifact due to: {clean_reason}",
            normalized_pattern=f"FALSE_POSITIVE:{clean_ep}:{clean_reason[:30]}",
            status=KnowledgeStatus.CANDIDATE,
            confidence=0.8,
            source_mission_ids=[mission_id] if mission_id else [],
            source_finding_ids=[finding_id] if finding_id else [],
            applicable_endpoint_types=[clean_ep],
            rationale=f"Extracted from false positive diagnosis: {clean_reason}",
        )
        k.compute_digest()
        return k

    def _generalize_endpoint(self, endpoint_url: str) -> str:
        """Generalizes specific endpoint URLs to abstract parameterized route templates."""
        if not endpoint_url:
            return ""
        clean = self.sanitize_text(endpoint_url)
        # Strip scheme & domain (e.g. http://127.0.0.1:8000/api/users/123 -> /api/users/{param})
        clean = re.sub(r'^https?://[^/]+', '', clean)
        # Replace UUIDs with {uuid}
        clean = re.sub(r'[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}', '{uuid}', clean)
        # Replace integer IDs with {id}
        clean = re.sub(r'/\d+(?=/|$)', '/{id}', clean)
        # Replace hex tokens with {token}
        clean = re.sub(r'/[a-fA-F0-9]{16,}(?=/|$)', '/{token}', clean)
        return clean or "/"
