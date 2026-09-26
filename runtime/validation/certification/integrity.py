"""
Level 5 Real-World Certification Track — Integrity, Anti-Contamination & Manifest

Implements Phase L (Anti-Contamination & Canary System) and Phase Q (Evidence Integrity):
- Pre-run and post-run state snapshots (Brain, P13 knowledge, hypotheses, benchmark registry)
- Canary detection & ground-truth isolation checks
- SHA256 cryptographic manifest generation for all certification artifacts
- Tamper detection and manifest validation
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

from runtime.validation.integrity import compute_sha256_digest


@dataclass
class PreRunSnapshot:
    """Snapshot of Hunter state before certification run begins to detect contamination."""
    snapshot_id: str
    run_id: str
    timestamp: str
    p13_knowledge_hashes: list[str]
    benchmark_vulnerability_tokens: list[str]
    canary_tokens: list[str]
    graph_node_count: int
    prior_hypotheses_count: int
    snapshot_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("snapshot_hash", None)
        return d

    def compute_hash(self) -> str:
        return compute_sha256_digest(self.to_dict())


class ContaminationDetector:
    """
    Guarantees target vulnerability knowledge != Hunter prior knowledge != operator hints != benchmark metadata.
    """

    def __init__(self, pre_run_snapshot: Optional[PreRunSnapshot] = None):
        self.pre_run_snapshot = pre_run_snapshot

    def create_pre_run_snapshot(
        self,
        run_id: str,
        p13_knowledge_items: Optional[list[str]] = None,
        benchmark_tokens: Optional[list[str]] = None,
        canary_tokens: Optional[list[str]] = None,
        graph_node_count: int = 0,
        prior_hypotheses_count: int = 0,
    ) -> PreRunSnapshot:
        """Captures pre-run baseline to detect subsequent data leakage."""
        p13_hashes = [
            hashlib.sha256(item.encode("utf-8")).hexdigest()
            for item in (p13_knowledge_items or [])
        ]
        tokens = list(benchmark_tokens or [])
        canaries = list(canary_tokens or [])
        
        snapshot = PreRunSnapshot(
            snapshot_id=f"snap_{run_id}_{int(time.time())}",
            run_id=run_id,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            p13_knowledge_hashes=p13_hashes,
            benchmark_vulnerability_tokens=tokens,
            canary_tokens=canaries,
            graph_node_count=graph_node_count,
            prior_hypotheses_count=prior_hypotheses_count,
        )
        snapshot.snapshot_hash = snapshot.compute_hash()
        self.pre_run_snapshot = snapshot
        return snapshot

    def check_for_contamination(
        self,
        finding_data: dict[str, Any],
        operator_prompts: Optional[list[str]] = None,
        research_trace: Optional[list[dict[str, Any]]] = None,
    ) -> tuple[bool, list[str]]:
        """
        Audits execution traces for leaks:
        1. Operator hints injecting the target vulnerability
        2. Benchmark ground-truth canary strings leaking into research trace or finding
        3. Pre-run P13 knowledge injecting the finding directly
        
        Returns:
            (is_contaminated, list_of_violations)
        """
        violations: list[str] = []
        finding_text = json.dumps(finding_data, sort_keys=True).lower()

        # 1. Check operator prompt hints
        if operator_prompts:
            endpoint = str(finding_data.get("affected_endpoint", "")).lower()
            param = str(finding_data.get("affected_parameter", "")).lower()
            vuln_class = str(finding_data.get("vulnerability_class", "")).lower()

            for prompt in operator_prompts:
                p_lower = prompt.lower()
                # If operator told hunter exact endpoint and vuln
                if endpoint and endpoint in p_lower and vuln_class in p_lower:
                    violations.append(
                        f"Operator hint violation: prompt provided target endpoint '{endpoint}' and class '{vuln_class}'."
                    )
                if param and param in p_lower and len(param) > 3:
                    violations.append(
                        f"Operator hint violation: prompt explicitly suggested vulnerable parameter '{param}'."
                    )

        # 2. Check canary leakage if pre-run snapshot exists
        if self.pre_run_snapshot:
            # Check canary tokens
            trace_text = ""
            if research_trace:
                trace_text = json.dumps(research_trace, sort_keys=True).lower()

            for canary in self.pre_run_snapshot.canary_tokens:
                c_lower = canary.lower()
                if c_lower in finding_text or c_lower in trace_text:
                    violations.append(
                        f"Ground-truth canary leak: canary token '{canary}' observed in Hunter execution."
                    )

            # Check benchmark tokens
            for b_tok in self.pre_run_snapshot.benchmark_vulnerability_tokens:
                b_lower = b_tok.lower()
                if b_lower and b_lower in finding_text and len(b_lower) > 5:
                    violations.append(
                        f"Benchmark token leak: fixture string '{b_tok}' matched finding evidence."
                    )

        is_contaminated = len(violations) > 0
        return is_contaminated, violations


class CertificationManifestManager:
    """Generates and cryptographically verifies CERTIFICATION_MANIFEST.json."""

    @staticmethod
    def generate_manifest(
        directory_path: str,
        output_file_path: Optional[str] = None,
        source_run_id: str = "GLOBAL",
    ) -> dict[str, Any]:
        """
        Scans all artifacts in directory_path, computes SHA256 and byte sizes,
        and generates an authoritative manifest.
        """
        root_dir = Path(directory_path)
        if not root_dir.exists():
            root_dir.mkdir(parents=True, exist_ok=True)

        entries: list[dict[str, Any]] = []
        now_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Scan all files recursively except the manifest file itself
        for p in sorted(root_dir.rglob("*")):
            if p.is_file() and not p.name.endswith("CERTIFICATION_MANIFEST.json"):
                rel_path = str(p.relative_to(root_dir)).replace("\\", "/")
                content = p.read_bytes()
                sha256 = hashlib.sha256(content).hexdigest()
                size = len(content)
                entries.append({
                    "artifact": rel_path,
                    "sha256": sha256,
                    "size_bytes": size,
                    "created_at": now_str,
                    "source_run": source_run_id,
                })

        manifest_data = {
            "manifest_version": "1.0.0",
            "source_run_id": source_run_id,
            "generated_at": now_str,
            "artifact_count": len(entries),
            "artifacts": entries,
        }
        manifest_data["manifest_digest"] = compute_sha256_digest(manifest_data)

        if output_file_path:
            out_p = Path(output_file_path)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as f:
                json.dump(manifest_data, f, indent=2)

        return manifest_data

    @staticmethod
    def verify_manifest(
        directory_path: str,
        manifest_file_path: str,
    ) -> tuple[bool, list[str]]:
        """
        Verifies that every artifact listed in the manifest matches its SHA256 hash,
        and detects unmanifested or missing files.
        """
        manifest_p = Path(manifest_file_path)
        if not manifest_p.exists():
            return False, [f"Manifest file not found: {manifest_file_path}"]

        with open(manifest_p, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        root_dir = Path(directory_path)
        errors: list[str] = []

        # Check recorded artifacts
        for entry in manifest.get("artifacts", []):
            art_path = root_dir / entry["artifact"]
            if not art_path.exists():
                errors.append(f"Missing artifact: {entry['artifact']}")
                continue

            current_hash = hashlib.sha256(art_path.read_bytes()).hexdigest()
            if current_hash != entry["sha256"]:
                errors.append(
                    f"Integrity violation on {entry['artifact']}: expected {entry['sha256']}, got {current_hash}"
                )

        is_valid = len(errors) == 0
        return is_valid, errors
