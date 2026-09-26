"""
Phase 12: Semantic Normalization & Security Diff Engine

Compares two immutable SecuritySnapshot states, filters non-security noise
(HTML whitespace, header ordering, timestamps, random tokens), and emits
structured, categorized SecurityChange objects within a SecurityDiff.
"""

from __future__ import annotations

import re
import secrets
from typing import Any

from runtime.regression.classifier import ChangeClassifier
from runtime.regression.models import (
    ChangeCategory,
    ChangeRelevance,
    SecurityChange,
    SecurityDiff,
    SecuritySnapshot,
)


class SemanticNormalizer:
    """
    Normalizes textual and structured data to eliminate non-security noise.
    """

    @staticmethod
    def normalize_text(text: str) -> str:
        """Strips HTML tags, collapses whitespace, removes timestamps and dynamic IDs."""
        if not text:
            return ""
        # Remove HTML tags
        t = re.sub(r"<[^>]+>", " ", text)
        # Remove timestamps (ISO format, standard date formats)
        t = re.sub(r"\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?", "", t)
        # Remove UUIDs and hex hashes
        t = re.sub(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", "", t, flags=re.IGNORECASE)
        t = re.sub(r"[a-f0-9]{32,64}", "", t, flags=re.IGNORECASE)
        # Collapse whitespace
        t = re.sub(r"\s+", " ", t).strip()
        return t

    @staticmethod
    def are_texts_semantically_equivalent(text1: str, text2: str) -> bool:
        return SemanticNormalizer.normalize_text(text1) == SemanticNormalizer.normalize_text(text2)

    @staticmethod
    def normalize_headers(headers: dict[str, Any]) -> dict[str, str]:
        """Normalizes header keys to lowercase and filters non-security dynamic headers."""
        ignore_headers = {"date", "set-cookie", "x-request-id", "x-runtime", "cf-ray", "age"}
        return {
            k.lower(): str(v).strip()
            for k, v in headers.items()
            if k.lower() not in ignore_headers
        }


class SecurityDiffEngine:
    """
    Computes semantic, categorized differences between two SecuritySnapshots.
    """

    def __init__(self, classifier: ChangeClassifier | None = None) -> None:
        self.classifier = classifier or ChangeClassifier()

    def diff(self, base_snapshot: SecuritySnapshot, current_snapshot: SecuritySnapshot) -> SecurityDiff:
        """
        Calculates the complete security-relevant diff from base to current.
        """
        changes: list[SecurityChange] = []

        # 1. Asset Differences
        base_assets = set(base_snapshot.assets)
        curr_assets = set(current_snapshot.assets)
        for a in curr_assets - base_assets:
            changes.append(self._create_change(ChangeCategory.ASSET_ADDED, [a], previous_state=None, current_state=a, rationale=f"New asset discovered: {a}"))
        for a in base_assets - curr_assets:
            changes.append(self._create_change(ChangeCategory.ASSET_REMOVED, [a], previous_state=a, current_state=None, rationale=f"Asset removed: {a}"))

        # 2. Endpoint Differences
        base_ep_map = {f"{e.get('method', 'GET').upper()}:{e.get('path', '')}": e for e in base_snapshot.endpoints}
        curr_ep_map = {f"{e.get('method', 'GET').upper()}:{e.get('path', '')}": e for e in current_snapshot.endpoints}

        for ep_key in set(curr_ep_map.keys()) - set(base_ep_map.keys()):
            ep = curr_ep_map[ep_key]
            changes.append(self._create_change(ChangeCategory.ENDPOINT_ADDED, [ep.get("path", "")], previous_state=None, current_state=ep, rationale=f"New endpoint added: {ep_key}"))

        for ep_key in set(base_ep_map.keys()) - set(curr_ep_map.keys()):
            ep = base_ep_map[ep_key]
            changes.append(self._create_change(ChangeCategory.ENDPOINT_REMOVED, [ep.get("path", "")], previous_state=ep, current_state=None, rationale=f"Endpoint removed: {ep_key}"))

        for ep_key in set(base_ep_map.keys()) & set(curr_ep_map.keys()):
            b_ep = base_ep_map[ep_key]
            c_ep = curr_ep_map[ep_key]
            if self._has_endpoint_behavior_changed(b_ep, c_ep):
                changes.append(self._create_change(ChangeCategory.ENDPOINT_CHANGED, [c_ep.get("path", "")], previous_state=b_ep, current_state=c_ep, rationale=f"Endpoint behavior changed: {ep_key}"))

        # 3. Parameter Differences
        for ep_path, curr_params in current_snapshot.parameters.items():
            base_params = base_snapshot.parameters.get(ep_path, [])
            for p in set(curr_params) - set(base_params):
                changes.append(self._create_change(ChangeCategory.PARAMETER_ADDED, [ep_path], previous_state=None, current_state=p, rationale=f"Parameter '{p}' added to {ep_path}"))
            for p in set(base_params) - set(curr_params):
                changes.append(self._create_change(ChangeCategory.PARAMETER_REMOVED, [ep_path], previous_state=p, current_state=None, rationale=f"Parameter '{p}' removed from {ep_path}"))

        # 4. API Differences
        base_api_ids = {a.get("id", ""): a for a in base_snapshot.apis}
        curr_api_ids = {a.get("id", ""): a for a in current_snapshot.apis}
        for aid in set(curr_api_ids.keys()) - set(base_api_ids.keys()):
            changes.append(self._create_change(ChangeCategory.API_ADDED, [aid], previous_state=None, current_state=curr_api_ids[aid], rationale=f"New API registered: {aid}"))
        for aid in set(base_api_ids.keys()) - set(curr_api_ids.keys()):
            changes.append(self._create_change(ChangeCategory.API_REMOVED, [aid], previous_state=base_api_ids[aid], current_state=None, rationale=f"API removed: {aid}"))
        for aid in set(base_api_ids.keys()) & set(curr_api_ids.keys()):
            if base_api_ids[aid] != curr_api_ids[aid]:
                changes.append(self._create_change(ChangeCategory.API_CHANGED, [aid], previous_state=base_api_ids[aid], current_state=curr_api_ids[aid], rationale=f"API configuration changed: {aid}"))

        # 5. Technology Differences
        base_tech_map = {t.get("name", ""): t.get("version", "") for t in base_snapshot.technologies}
        curr_tech_map = {t.get("name", ""): t.get("version", "") for t in current_snapshot.technologies}
        for tname in set(curr_tech_map.keys()) - set(base_tech_map.keys()):
            changes.append(self._create_change(ChangeCategory.TECHNOLOGY_ADDED, [tname], previous_state=None, current_state=curr_tech_map[tname], rationale=f"Technology added: {tname} v{curr_tech_map[tname]}"))
        for tname in set(base_tech_map.keys()) - set(curr_tech_map.keys()):
            changes.append(self._create_change(ChangeCategory.TECHNOLOGY_REMOVED, [tname], previous_state=base_tech_map[tname], current_state=None, rationale=f"Technology removed: {tname}"))
        for tname in set(base_tech_map.keys()) & set(curr_tech_map.keys()):
            if base_tech_map[tname] != curr_tech_map[tname]:
                changes.append(self._create_change(ChangeCategory.TECHNOLOGY_CHANGED, [tname], previous_state=base_tech_map[tname], current_state=curr_tech_map[tname], rationale=f"Technology version changed for {tname}: {base_tech_map[tname]} -> {curr_tech_map[tname]}"))

        # 6. Authentication & Authorization Boundaries
        if base_snapshot.authentication_boundaries != current_snapshot.authentication_boundaries:
            changes.append(self._create_change(ChangeCategory.AUTH_CHANGED, ["auth_boundary"], previous_state=base_snapshot.authentication_boundaries, current_state=current_snapshot.authentication_boundaries, rationale="Authentication boundary definition modified"))

        if base_snapshot.trust_boundaries != current_snapshot.trust_boundaries:
            changes.append(self._create_change(ChangeCategory.TRUST_BOUNDARY_CHANGED, ["trust_boundary"], previous_state=base_snapshot.trust_boundaries, current_state=current_snapshot.trust_boundaries, rationale="Trust boundaries modified"))

        # 7. Roles & Tenants
        for r in set(current_snapshot.roles) - set(base_snapshot.roles):
            changes.append(self._create_change(ChangeCategory.ROLE_ADDED, [r], previous_state=None, current_state=r, rationale=f"New role added: {r}"))
        for r in set(base_snapshot.roles) - set(current_snapshot.roles):
            changes.append(self._create_change(ChangeCategory.ROLE_REMOVED, [r], previous_state=r, current_state=None, rationale=f"Role removed: {r}"))
        if base_snapshot.tenants != current_snapshot.tenants:
            changes.append(self._create_change(ChangeCategory.TENANT_MODEL_CHANGED, current_snapshot.tenants, previous_state=base_snapshot.tenants, current_state=current_snapshot.tenants, rationale="Tenant isolation model modified"))

        # 8. Workflows
        base_wf_ids = {w.get("id", ""): w for w in base_snapshot.workflows}
        curr_wf_ids = {w.get("id", ""): w for w in current_snapshot.workflows}
        for wfid in set(curr_wf_ids.keys()) - set(base_wf_ids.keys()):
            changes.append(self._create_change(ChangeCategory.WORKFLOW_ADDED, [wfid], previous_state=None, current_state=curr_wf_ids[wfid], rationale=f"Workflow added: {wfid}"))
        for wfid in set(base_wf_ids.keys()) - set(curr_wf_ids.keys()):
            changes.append(self._create_change(ChangeCategory.WORKFLOW_REMOVED, [wfid], previous_state=base_wf_ids[wfid], current_state=None, rationale=f"Workflow removed: {wfid}"))
        for wfid in set(base_wf_ids.keys()) & set(curr_wf_ids.keys()):
            if base_wf_ids[wfid] != curr_wf_ids[wfid]:
                changes.append(self._create_change(ChangeCategory.WORKFLOW_CHANGED, [wfid], previous_state=base_wf_ids[wfid], current_state=curr_wf_ids[wfid], rationale=f"Workflow sequence/transitions changed: {wfid}"))

        # 9. Findings Lifecycle Changes
        base_finding_map = {f.get("id", ""): f for f in base_snapshot.findings}
        curr_finding_map = {f.get("id", ""): f for f in current_snapshot.findings}
        for fid in set(base_finding_map.keys()) & set(curr_finding_map.keys()):
            b_f = base_finding_map[fid]
            c_f = curr_finding_map[fid]
            if b_f.get("status") != c_f.get("status"):
                if c_f.get("status") in ("FIXED", "REMEDIATED"):
                    changes.append(self._create_change(ChangeCategory.FINDING_FIXED, [fid], previous_state=b_f, current_state=c_f, rationale=f"Finding status updated to remediation: {fid}"))
                elif c_f.get("status") in ("REGRESSED", "VALIDATED") and b_f.get("status") in ("FIXED", "REMEDIATED"):
                    changes.append(self._create_change(ChangeCategory.FINDING_REGRESSED, [fid], previous_state=b_f, current_state=c_f, rationale=f"Previously fixed finding regressed: {fid}"))
                else:
                    changes.append(self._create_change(ChangeCategory.FINDING_CHANGED, [fid], previous_state=b_f, current_state=c_f, rationale=f"Finding status changed: {fid} ({b_f.get('status')} -> {c_f.get('status')})"))

        # 10. Coverage Delta
        if base_snapshot.coverage != current_snapshot.coverage:
            changes.append(self._create_change(ChangeCategory.COVERAGE_CHANGED, ["coverage"], previous_state=base_snapshot.coverage, current_state=current_snapshot.coverage, rationale="Security test coverage delta observed"))

        # Classify all changes
        for c in changes:
            self.classifier.classify(c)

        # Build Summary
        summary_counts: dict[str, int] = {}
        max_rel = ChangeRelevance.NO_SECURITY_CHANGE
        for c in changes:
            cat_name = c.category.value if isinstance(c.category, ChangeCategory) else str(c.category)
            summary_counts[cat_name] = summary_counts.get(cat_name, 0) + 1
            if c.relevance == ChangeRelevance.CRITICAL_SECURITY_RELEVANCE:
                max_rel = ChangeRelevance.CRITICAL_SECURITY_RELEVANCE
            elif c.relevance == ChangeRelevance.HIGH_SECURITY_RELEVANCE and max_rel != ChangeRelevance.CRITICAL_SECURITY_RELEVANCE:
                max_rel = ChangeRelevance.HIGH_SECURITY_RELEVANCE
            elif c.relevance == ChangeRelevance.MEDIUM_SECURITY_RELEVANCE and max_rel in (ChangeRelevance.NO_SECURITY_CHANGE, ChangeRelevance.LOW_SECURITY_RELEVANCE):
                max_rel = ChangeRelevance.MEDIUM_SECURITY_RELEVANCE
            elif c.relevance == ChangeRelevance.LOW_SECURITY_RELEVANCE and max_rel == ChangeRelevance.NO_SECURITY_CHANGE:
                max_rel = ChangeRelevance.LOW_SECURITY_RELEVANCE

        has_security = any(c.relevance not in (ChangeRelevance.NO_SECURITY_CHANGE, ChangeRelevance.UNKNOWN_RELEVANCE) for c in changes)

        return SecurityDiff(
            diff_id=f"DIFF-{secrets.token_hex(4).upper()}",
            base_snapshot_id=base_snapshot.snapshot_id,
            current_snapshot_id=current_snapshot.snapshot_id,
            changes=changes,
            summary_counts=summary_counts,
            has_security_changes=has_security,
            max_relevance=max_rel,
        )

    def _create_change(
        self,
        category: ChangeCategory,
        affected_assets: list[str],
        *,
        previous_state: Any = None,
        current_state: Any = None,
        rationale: str = "",
    ) -> SecurityChange:
        return SecurityChange(
            change_id=f"CHG-{secrets.token_hex(4).upper()}",
            category=category,
            affected_assets=affected_assets,
            affected_graph_nodes=affected_assets,
            previous_state=previous_state,
            current_state=current_state,
            rationale=rationale,
        )

    def _has_endpoint_behavior_changed(self, b_ep: dict[str, Any], c_ep: dict[str, Any]) -> bool:
        """Determines if endpoint changed semantically rather than textually/noise."""
        # Status code change
        if b_ep.get("status_code") != c_ep.get("status_code"):
            return True
        # Auth requirement change
        if b_ep.get("auth_required") != c_ep.get("auth_required"):
            return True
        # Roles permitted changed
        if set(b_ep.get("allowed_roles", [])) != set(c_ep.get("allowed_roles", [])):
            return True
        # Parameters changed
        if set(b_ep.get("parameters", [])) != set(c_ep.get("parameters", [])):
            return True
        # Semantic response body check
        b_body = SemanticNormalizer.normalize_text(str(b_ep.get("response_body", "")))
        c_body = SemanticNormalizer.normalize_text(str(c_ep.get("response_body", "")))
        if b_body and c_body and b_body != c_body:
            return True
        return False
