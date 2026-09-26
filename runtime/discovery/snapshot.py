"""
Phase 6: Adaptive Reconnaissance & Attack-Surface Mapping
Attack-Surface Snapshots, Diffing & Stale Knowledge Detection
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from runtime.discovery.model import DiscoveredEntity, DiscoveredRelationship


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AttackSurfaceSnapshot:
    snapshot_id: str
    mission_id: str
    timestamp: str = field(default_factory=_now_iso)
    entities_count: int = 0
    relationships_count: int = 0
    endpoints: list[str] = field(default_factory=list)
    apis: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    auth_boundaries: list[str] = field(default_factory=list)
    tenants: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    content_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "mission_id": self.mission_id,
            "timestamp": self.timestamp,
            "entities_count": self.entities_count,
            "relationships_count": self.relationships_count,
            "endpoints": self.endpoints,
            "apis": self.apis,
            "technologies": self.technologies,
            "auth_boundaries": self.auth_boundaries,
            "tenants": self.tenants,
            "roles": self.roles,
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttackSurfaceSnapshot:
        return cls(
            snapshot_id=data["snapshot_id"],
            mission_id=data["mission_id"],
            timestamp=data.get("timestamp", _now_iso()),
            entities_count=data.get("entities_count", 0),
            relationships_count=data.get("relationships_count", 0),
            endpoints=data.get("endpoints", []),
            apis=data.get("apis", []),
            technologies=data.get("technologies", []),
            auth_boundaries=data.get("auth_boundaries", []),
            tenants=data.get("tenants", []),
            roles=data.get("roles", []),
            content_hash=data.get("content_hash", ""),
        )


class AttackSurfaceSnapshotManager:
    """
    Manages snapshots of the attack surface and computes compact diffs.
    """

    def __init__(self, mission_id: str) -> None:
        self.mission_id = mission_id
        self._snapshots: list[AttackSurfaceSnapshot] = []

    def create_snapshot(
        self,
        entities: list[DiscoveredEntity],
        relationships: list[DiscoveredRelationship]
    ) -> AttackSurfaceSnapshot:
        endpoints = sorted([e.identity_string for e in entities if e.entity_type == "ENDPOINT"])
        apis = sorted([e.identity_string for e in entities if e.entity_type == "API"])
        technologies = sorted([e.identity_string for e in entities if e.entity_type == "TECHNOLOGY"])
        auth_boundaries = sorted([e.identity_string for e in entities if "AUTH" in e.identity_string or e.entity_type == "ASSUMPTION"])
        tenants = sorted([e.identity_string for e in entities if e.entity_type == "TENANT"])
        roles = sorted([e.identity_string for e in entities if e.entity_type == "ROLE"])

        payload = f"{endpoints}|{apis}|{technologies}|{auth_boundaries}|{tenants}|{roles}"
        content_hash = hashlib.sha256(payload.encode()).hexdigest()[:12]

        snapshot_id = f"SNAP-{len(self._snapshots) + 1}-{content_hash}"
        snapshot = AttackSurfaceSnapshot(
            snapshot_id=snapshot_id,
            mission_id=self.mission_id,
            entities_count=len(entities),
            relationships_count=len(relationships),
            endpoints=endpoints,
            apis=apis,
            technologies=technologies,
            auth_boundaries=auth_boundaries,
            tenants=tenants,
            roles=roles,
            content_hash=content_hash
        )

        self._snapshots.append(snapshot)
        return snapshot

    def diff_snapshots(
        self,
        older: AttackSurfaceSnapshot,
        newer: AttackSurfaceSnapshot
    ) -> dict[str, Any]:
        """
        Computes differences between two snapshots: added, removed, unchanged counts.
        """
        added_endpoints = list(set(newer.endpoints) - set(older.endpoints))
        removed_endpoints = list(set(older.endpoints) - set(newer.endpoints))

        added_apis = list(set(newer.apis) - set(older.apis))
        removed_apis = list(set(older.apis) - set(newer.apis))

        added_techs = list(set(newer.technologies) - set(older.technologies))
        removed_techs = list(set(older.technologies) - set(newer.technologies))

        added_auth = list(set(newer.auth_boundaries) - set(older.auth_boundaries))

        return {
            "older_snapshot_id": older.snapshot_id,
            "newer_snapshot_id": newer.snapshot_id,
            "added_endpoints": added_endpoints,
            "removed_endpoints": removed_endpoints,
            "added_apis": added_apis,
            "removed_apis": removed_apis,
            "added_technologies": added_techs,
            "removed_technologies": removed_techs,
            "added_auth_boundaries": added_auth,
            "is_identical": older.content_hash == newer.content_hash
        }

    @staticmethod
    def is_stale(entity: DiscoveredEntity, max_age_seconds: int = 3600) -> bool:
        """
        Detects if an entity has not been validated within max_age_seconds.
        """
        try:
            val_time = datetime.fromisoformat(entity.last_validated_at)
            age = (datetime.now(timezone.utc) - val_time).total_seconds()
            return age > max_age_seconds
        except Exception:
            return False
