"""
HVC-6: High-Resolution Performance Profiler & Memory Auditor

Replaces rounded zero-second latencies with sub-millisecond nanosecond-precision
measurements. Computes min, max, mean, median, p50, p90, p95, p99 latencies,
RSS memory tracking (baseline, peak, delta), and processing throughputs.
"""

from __future__ import annotations

import os
import platform
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from runtime.validation.integrity import compute_sha256_digest


def _get_current_rss_mb() -> float:
    """Retrieves current process RSS memory in megabytes."""
    try:
        import psutil
        proc = psutil.Process(os.getpid())
        return round(proc.memory_info().rss / (1024 * 1024), 3)
    except Exception:
        return 0.0


@dataclass
class LatencyDistribution:
    sample_count: int
    min_us: float
    max_us: float
    mean_us: float
    median_us: float
    p50_us: float
    p90_us: float
    p95_us: float
    p99_us: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_count": self.sample_count,
            "min_microseconds": round(self.min_us, 3),
            "max_microseconds": round(self.max_us, 3),
            "mean_microseconds": round(self.mean_us, 3),
            "median_microseconds": round(self.median_us, 3),
            "p50_microseconds": round(self.p50_us, 3),
            "p90_microseconds": round(self.p90_us, 3),
            "p95_microseconds": round(self.p95_us, 3),
            "p99_microseconds": round(self.p99_us, 3),
            "mean_milliseconds": round(self.mean_us / 1000.0, 4),
        }


def compute_latency_distribution(latencies_ns: list[int]) -> LatencyDistribution:
    """Computes high-resolution percentiles from nanosecond measurements."""
    if not latencies_ns:
        return LatencyDistribution(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

    # Convert to microseconds
    us_values = sorted([ns / 1000.0 for ns in latencies_ns])
    n = len(us_values)

    def _percentile(p: float) -> float:
        if n == 1:
            return us_values[0]
        k = (n - 1) * p
        f = int(k)
        c = min(f + 1, n - 1)
        d0 = us_values[f] * (c - k)
        d1 = us_values[c] * (k - f)
        return d0 + d1

    return LatencyDistribution(
        sample_count=n,
        min_us=us_values[0],
        max_us=us_values[-1],
        mean_us=statistics.mean(us_values),
        median_us=statistics.median(us_values),
        p50_us=_percentile(0.50),
        p90_us=_percentile(0.90),
        p95_us=_percentile(0.95),
        p99_us=_percentile(0.99),
    )


@dataclass
class PerformanceBenchmarkManifest:
    hvc_run_id: str
    environment_info: dict[str, Any]
    baseline_rss_mb: float
    peak_rss_mb: float
    delta_rss_mb: float
    decision_latency: LatencyDistribution
    graph_ingestion_throughput_nodes_per_sec: float
    payload_normalization_throughput_mb_per_sec: float
    digest: str = ""

    def compute_digest(self) -> str:
        d = {
            "hvc_run_id": self.hvc_run_id,
            "baseline_rss_mb": self.baseline_rss_mb,
            "peak_rss_mb": self.peak_rss_mb,
            "delta_rss_mb": self.delta_rss_mb,
            "decision_latency": self.decision_latency.to_dict(),
            "graph_throughput": self.graph_ingestion_throughput_nodes_per_sec,
            "payload_throughput": self.payload_normalization_throughput_mb_per_sec,
        }
        return compute_sha256_digest(d)


class HighResolutionProfiler:
    """Profiles Hunter decision latencies, graph ingestion, and memory with sub-millisecond precision."""

    def __init__(self, project_root: Path):
        self.project_root = project_root

    def profile_decision_and_scale(self, hvc_run_id: str, sample_runs: int = 100) -> PerformanceBenchmarkManifest:
        import secrets
        from runtime.bootstrap import HunterRuntime
        from runtime.vulnerability.model import VulnerabilityHypothesis, VulnerabilityClass, HypothesisState
        from runtime.brain.decision import CandidateAction

        env_info = {
            "platform": platform.platform(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "os": platform.system(),
        }

        rss_baseline = _get_current_rss_mb()
        rt = HunterRuntime(self.project_root)
        rt.start()
        mid = f"M-PERF-{hvc_run_id}-{secrets.token_hex(2).upper()}"
        rt.mission_create("Performance profiling", ["127.0.0.1"], custom_id=mid)

        # 1. Profile Graph Ingest
        t_graph_0 = time.perf_counter_ns()
        node_count = 1000
        prev_id = None
        for i in range(node_count):
            ep = f"/api/perf/endpoint_{i}"
            n = rt._graph_store.add_node("ENDPOINT", ep, {"idx": i})
            if prev_id:
                rt._graph_store.add_relationship(prev_id, "ROUTES_TO", n.id)
            prev_id = n.id
        t_graph_elapsed_sec = (time.perf_counter_ns() - t_graph_0) / 1e9
        graph_throughput = node_count / t_graph_elapsed_sec if t_graph_elapsed_sec > 0 else 0.0

        # 2. Profile Decision Latency (Repeated High-Res Measurements)
        latencies_ns: list[int] = []
        for i in range(sample_runs):
            h = VulnerabilityHypothesis(
                id=f"HYP-PERF-{i}",
                mission_id=mid,
                title=f"Potential IDOR on /perf_{i}",
                vulnerability_class=VulnerabilityClass.IDOR_BOLA,
                assumption="Missing auth check",
                claim="Data exfiltration possible",
                confidence=0.5,
                state=HypothesisState.ACTIVE,
            )
            rt.brain.state.hypotheses[h.id] = h

            act = CandidateAction(
                id=f"ACT-PERF-{i}",
                action_type="EXPERIMENT",
                objective=f"Test hypothesis {h.id}",
                target=f"http://127.0.0.1/perf_{i}",
                capability_id="HTTP_REQUEST",
                input_parameters={"url": f"http://127.0.0.1/perf_{i}"},
                expected_information_gain=0.8,
                expected_security_value=1.0,
                scope_alignment="IN_SCOPE",
            )
            rt.brain.state.candidate_actions[act.id] = act

            # Benchmark individual selection decision in nanoseconds
            t_dec_0 = time.perf_counter_ns()
            chosen, rationale = rt.brain.decide_next_action([act])
            t_dec_ns = time.perf_counter_ns() - t_dec_0
            latencies_ns.append(t_dec_ns)

        latency_dist = compute_latency_distribution(latencies_ns)

        # 3. Profile Payload Ingestion Throughput
        large_payload = ("var route = '/api/v1/resource';\n" * 15000)  # ~500 KB
        payload_bytes = len(large_payload)
        t_pay_0 = time.perf_counter_ns()
        rt._evidence_normalizer.ingest_execution_result(mid, {
            "execution_id": f"EXEC-PERF-PL",
            "tool": "curl",
            "raw_output": large_payload,
        })
        t_pay_elapsed_sec = (time.perf_counter_ns() - t_pay_0) / 1e9
        payload_mb = payload_bytes / (1024 * 1024)
        payload_throughput_mb_s = payload_mb / t_pay_elapsed_sec if t_pay_elapsed_sec > 0 else 0.0

        rss_peak = _get_current_rss_mb()
        rss_delta = max(0.0, round(rss_peak - rss_baseline, 3))

        manifest = PerformanceBenchmarkManifest(
            hvc_run_id=hvc_run_id,
            environment_info=env_info,
            baseline_rss_mb=rss_baseline,
            peak_rss_mb=rss_peak,
            delta_rss_mb=rss_delta,
            decision_latency=latency_dist,
            graph_ingestion_throughput_nodes_per_sec=round(graph_throughput, 2),
            payload_normalization_throughput_mb_per_sec=round(payload_throughput_mb_s, 2),
        )
        manifest.digest = manifest.compute_digest()
        return manifest
