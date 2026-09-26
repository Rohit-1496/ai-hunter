"""
Phase 12: Security Snapshot Engine & Deterministic Fingerprinting

Generates immutable, deterministically fingerprinted SecuritySnapshot objects
from target observations, attack surface graphs, and research state.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any

from runtime.regression.models import SecuritySnapshot, SnapshotType


class SecurityFingerprinter:
    """
    Computes deterministic fingerprints across all security dimensions.
    Sorts keys/lists and removes volatile metadata so equivalent states hash identically.
    """

    @staticmethod
    def _hash_dict(data: dict[str, Any] | list[Any]) -> str:
        serialized = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @classmethod
    def fingerprint_target(cls, assets: list[str], domains: list[str], endpoints: list[dict[str, Any]]) -> str:
        normalized_endpoints = sorted([
            f"{e.get('method', 'GET').upper()}:{e.get('path', '')}" for e in endpoints
        ])
        return cls._hash_dict({
            "assets": sorted(assets),
            "domains": sorted(domains),
            "endpoints": normalized_endpoints,
        })

    @classmethod
    def fingerprint_environment(cls, technologies: list[dict[str, Any]]) -> str:
        tech_list = sorted([
            f"{t.get('name', '')}:{t.get('version', '')}" for t in technologies
        ])
        return cls._hash_dict({"technologies": tech_list})

    @classmethod
    def fingerprint_auth_model(
        cls,
        auth_boundaries: list[dict[str, Any]],
        tokens_sessions: list[dict[str, Any]],
    ) -> str:
        return cls._hash_dict({
            "auth_boundaries": sorted([str(b) for b in auth_boundaries]),
            "tokens_sessions": sorted([str(t) for t in tokens_sessions]),
        })

    @classmethod
    def fingerprint_authorization_model(
        cls,
        roles: list[str],
        tenants: list[str],
        workflows: list[dict[str, Any]],
        trust_boundaries: list[dict[str, Any]],
    ) -> str:
        return cls._hash_dict({
            "roles": sorted(roles),
            "tenants": sorted(tenants),
            "workflows": sorted([w.get("id", str(w)) for w in workflows]),
            "trust_boundaries": sorted([str(b) for b in trust_boundaries]),
        })

    @classmethod
    def fingerprint_attack_surface(
        cls,
        endpoints: list[dict[str, Any]],
        parameters: dict[str, list[str]],
        apis: list[dict[str, Any]],
    ) -> str:
        return cls._hash_dict({
            "endpoints": sorted([f"{e.get('method', 'GET')}:{e.get('path', '')}" for e in endpoints]),
            "parameters": {k: sorted(v) for k, v in sorted(parameters.items())},
            "apis": sorted([a.get("id", str(a)) for a in apis]),
        })

    @classmethod
    def fingerprint_security_graph(cls, graph_nodes: list[str], graph_edges: list[dict[str, Any]]) -> str:
        edge_list = sorted([
            f"{e.get('source', '')}->{e.get('target', '')}:{e.get('type', '')}" for e in graph_edges
        ])
        return cls._hash_dict({
            "nodes": sorted(graph_nodes),
            "edges": edge_list,
        })


class SnapshotEngine:
    """
    Constructs, verifies, and validates immutable SecuritySnapshot objects.
    """

    def __init__(self, fingerprinter: SecurityFingerprinter | None = None) -> None:
        self.fingerprinter = fingerprinter or SecurityFingerprinter()

    def create_snapshot(
        self,
        mission_id: str,
        *,
        snapshot_type: SnapshotType = SnapshotType.PERIODIC,
        parent_snapshot: SecuritySnapshot | None = None,
        assets: list[str] | None = None,
        domains: list[str] | None = None,
        subdomains: list[str] | None = None,
        endpoints: list[dict[str, Any]] | None = None,
        parameters: dict[str, list[str]] | None = None,
        apis: list[dict[str, Any]] | None = None,
        technologies: list[dict[str, Any]] | None = None,
        authentication_boundaries: list[dict[str, Any]] | None = None,
        roles: list[str] | None = None,
        tenants: list[str] | None = None,
        workflows: list[dict[str, Any]] | None = None,
        trust_boundaries: list[dict[str, Any]] | None = None,
        tokens_sessions: list[dict[str, Any]] | None = None,
        hypotheses: list[str] | None = None,
        findings: list[dict[str, Any]] | None = None,
        attack_paths: list[dict[str, Any]] | None = None,
        exploitability_results: list[dict[str, Any]] | None = None,
        pocs: list[dict[str, Any]] | None = None,
        coverage: dict[str, Any] | None = None,
        graph_version: int = 1,
        graph_nodes: list[str] | None = None,
        graph_edges: list[dict[str, Any]] | None = None,
        scope_fingerprint: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> SecuritySnapshot:
        """
        Creates, computes fingerprints for, digests, and freezes a new SecuritySnapshot.
        """
        assets = assets or []
        domains = domains or []
        subdomains = subdomains or []
        endpoints = endpoints or []
        parameters = parameters or {}
        apis = apis or []
        technologies = technologies or []
        authentication_boundaries = authentication_boundaries or []
        roles = roles or []
        tenants = tenants or []
        workflows = workflows or []
        trust_boundaries = trust_boundaries or []
        tokens_sessions = tokens_sessions or []
        hypotheses = hypotheses or []
        findings = findings or []
        attack_paths = attack_paths or []
        exploitability_results = exploitability_results or []
        pocs = pocs or []
        coverage = coverage or {}
        graph_nodes = graph_nodes or []
        graph_edges = graph_edges or []

        # Deterministic fingerprints
        target_fp = self.fingerprinter.fingerprint_target(assets, domains, endpoints)
        env_fp = self.fingerprinter.fingerprint_environment(technologies)
        graph_digest = self.fingerprinter.fingerprint_security_graph(graph_nodes, graph_edges)

        snapshot = SecuritySnapshot(
            snapshot_id=f"SNAP-{secrets.token_hex(4).upper()}",
            mission_id=mission_id,
            snapshot_type=snapshot_type,
            target_fingerprint=target_fp,
            environment_fingerprint=env_fp,
            parent_snapshot_id=parent_snapshot.snapshot_id if parent_snapshot else None,
            scope_fingerprint=scope_fingerprint,
            assets=list(set(assets)),
            domains=list(set(domains)),
            subdomains=list(set(subdomains)),
            endpoints=endpoints,
            parameters=parameters,
            apis=apis,
            technologies=technologies,
            authentication_boundaries=authentication_boundaries,
            roles=list(set(roles)),
            tenants=list(set(tenants)),
            workflows=workflows,
            trust_boundaries=trust_boundaries,
            tokens_sessions=tokens_sessions,
            hypotheses=hypotheses,
            findings=findings,
            attack_paths=attack_paths,
            exploitability_results=exploitability_results,
            pocs=pocs,
            coverage=coverage,
            graph_version=graph_version,
            graph_digest=graph_digest,
            metadata=metadata or {},
        )

        snapshot.compute_digest()
        snapshot.freeze()
        return snapshot
