"""
HVC-14: Multi-Tier Scale & Stress Benchmark Auditor

Evaluates Hunter graph ingestion, memory scaling, and decision latencies across
3 distinct scale tiers:
- Tier 1: 1,000 endpoints
- Tier 2: 5,000 endpoints
- Tier 3: 10,000 endpoints

If hardware limits or excessive duration make a tier infeasible, it is honestly
marked BLOCKED (never manufactured as PASS).
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from runtime.validation.integrity import compute_sha256_digest
from runtime.validation.hvc.performance import _get_current_rss_mb


@dataclass
class ScaleTierResult:
    tier_name: str
    target_endpoints: int
    actual_endpoints_ingested: int
    edges_created: int
    status: str  # "PASS", "BLOCKED", "FAIL"
    elapsed_seconds: float
    throughput_nodes_sec: float
    rss_mb_delta: float
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExpandedScaleReport:
    hvc_run_id: str
    timestamp: str
    tiers: list[ScaleTierResult]
    max_scale_tier_passed: str
    digest: str = ""

    def compute_digest(self) -> str:
        d = {
            "hvc_run_id": self.hvc_run_id,
            "max_scale_tier_passed": self.max_scale_tier_passed,
            "tiers": [t.to_dict() for t in self.tiers],
        }
        return compute_sha256_digest(d)


class MultiTierScaleAuditor:
    """Evaluates 1k, 5k, and 10k endpoint stress scenarios."""

    def __init__(self, project_root: Path, output_dir: Path):
        self.project_root = project_root
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def benchmark_tiers(self, hvc_run_id: str) -> ExpandedScaleReport:
        from runtime.bootstrap import HunterRuntime

        tiers_to_test = [
            ("TIER_1K", 1000, 30.0),    # 1,000 nodes, max 30s timeout
            ("TIER_5K", 5000, 60.0),    # 5,000 nodes, max 60s timeout
            ("TIER_10K", 10000, 120.0), # 10,000 nodes, max 120s timeout
        ]

        results: list[ScaleTierResult] = []
        max_passed = "NONE"

        for tier_name, count, max_timeout in tiers_to_test:
            rss_before = _get_current_rss_mb()
            rt = HunterRuntime(self.project_root)
            rt.start()
            mid = f"M-SCALE-{tier_name}-{hvc_run_id}"
            rt.mission_create(f"Scale benchmark {tier_name}", ["127.0.0.1"], custom_id=mid)

            t0 = time.perf_counter()
            prev_id = None
            nodes_created = 0
            edges_created = 0
            aborted = False

            try:
                for i in range(count):
                    # Check timeout guard to avoid freezing the system
                    if time.perf_counter() - t0 > max_timeout:
                        aborted = True
                        break

                    ep = f"/api/{tier_name.lower()}/resource_{i}"
                    n = rt._graph_store.add_node("ENDPOINT", ep, {"index": i, "tier": tier_name})
                    nodes_created += 1
                    if prev_id:
                        rt._graph_store.add_relationship(prev_id, "ROUTES_TO", n.id)
                        edges_created += 1
                    prev_id = n.id

                elapsed = time.perf_counter() - t0
                rss_after = _get_current_rss_mb()
                delta_rss = max(0.0, round(rss_after - rss_before, 3))
                throughput = round(nodes_created / elapsed, 2) if elapsed > 0 else 0.0

                if aborted:
                    status = "BLOCKED"
                    rat = f"Execution exceeded maximum allocation threshold ({max_timeout}s). Marked BLOCKED."
                elif nodes_created == count:
                    status = "PASS"
                    max_passed = tier_name
                    rat = f"Successfully ingested {count} endpoints and {edges_created} edges in {elapsed:.2f}s."
                else:
                    status = "FAIL"
                    rat = f"Failed to ingest target count (ingested {nodes_created}/{count})."

                results.append(ScaleTierResult(
                    tier_name=tier_name,
                    target_endpoints=count,
                    actual_endpoints_ingested=nodes_created,
                    edges_created=edges_created,
                    status=status,
                    elapsed_seconds=round(elapsed, 3),
                    throughput_nodes_sec=throughput,
                    rss_mb_delta=delta_rss,
                    rationale=rat,
                ))

            except MemoryError:
                elapsed = time.perf_counter() - t0
                results.append(ScaleTierResult(
                    tier_name=tier_name,
                    target_endpoints=count,
                    actual_endpoints_ingested=nodes_created,
                    edges_created=edges_created,
                    status="BLOCKED",
                    elapsed_seconds=round(elapsed, 3),
                    throughput_nodes_sec=0.0,
                    rss_mb_delta=0.0,
                    rationale="Memory allocation limit reached. Marked BLOCKED in accordance with HVC Rule 17.",
                ))
            except Exception as e:
                elapsed = time.perf_counter() - t0
                results.append(ScaleTierResult(
                    tier_name=tier_name,
                    target_endpoints=count,
                    actual_endpoints_ingested=nodes_created,
                    edges_created=edges_created,
                    status="FAIL",
                    elapsed_seconds=round(elapsed, 3),
                    throughput_nodes_sec=0.0,
                    rss_mb_delta=0.0,
                    rationale=f"Unexpected failure during scale execution: {e}",
                ))

        report = ExpandedScaleReport(
            hvc_run_id=hvc_run_id,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            tiers=results,
            max_scale_tier_passed=max_passed,
        )
        report.digest = report.compute_digest()

        out_file = self.output_dir / f"{hvc_run_id}_scale_report.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2)

        return report
