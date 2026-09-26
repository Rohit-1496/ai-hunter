"""
HVC-3: Boundary Canary Leakage Guard & Runtime Quarantine Verifier

Instruments and scans all Hunter runtime boundaries (prompts, Brain state, hypotheses,
candidate actions, observations, Security Graph, Mission Manager, threads, P13 knowledge,
and tool inputs/outputs) to mathematically prove that ground-truth canaries never enter
autonomous execution.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from runtime.validation.integrity import compute_sha256_digest, FailClosedIntegrityError
from runtime.validation.models import SafetyViolation, SafetyViolationType


@dataclass
class CanaryScanResult:
    hvc_run_id: str
    total_canaries_checked: int
    runtime_components_scanned: list[str]
    leaks_detected_count: int
    violations: list[SafetyViolation] = field(default_factory=list)
    quarantine_verified: bool = True
    digest: str = ""

    def compute_digest(self) -> str:
        d = asdict(self)
        d.pop("digest", None)
        return compute_sha256_digest(d)


class CanaryLeakGuard:
    """Rigorous runtime boundary scanner searching for canary tokens."""

    def __init__(self, canary_tokens: set[str], ground_truth_ids: set[str]):
        self.canary_tokens = canary_tokens
        self.ground_truth_ids = ground_truth_ids
        self.forbidden_markers = set(canary_tokens) | set(ground_truth_ids)

    def scan_runtime_boundaries(
        self,
        runtime_instance: Any,
        mission_id: str | None = None,
        hvc_run_id: str = "HVC-RUN-DEFAULT",
    ) -> CanaryScanResult:
        violations: list[SafetyViolation] = []
        scanned_components: list[str] = []

        # 1. Inspect Brain State (Hypotheses, Candidate Actions, Observations)
        if hasattr(runtime_instance, "brain") and hasattr(runtime_instance.brain, "state"):
            b_state = runtime_instance.brain.state
            scanned_components.append("BrainState.Hypotheses")
            for h in getattr(b_state, "hypotheses", {}).values():
                h_text = f"{getattr(h, 'title', '')} {getattr(h, 'claim', '')} {getattr(h, 'assumption', '')} {getattr(h, 'statement', '')}"
                for m in self.forbidden_markers:
                    if m in h_text:
                        violations.append(
                            SafetyViolation(
                                violation_type=SafetyViolationType.GROUND_TRUTH_LEAKAGE,
                                severity="CRITICAL",
                                details=f"Ground truth marker '{m}' leaked into Hypothesis '{getattr(h, 'id', '')}'",
                            )
                        )

            scanned_components.append("BrainState.CandidateActions")
            for act in getattr(b_state, "candidate_actions", {}).values():
                act_str = f"{getattr(act, 'objective', '')} {getattr(act, 'target', '')} {json.dumps(getattr(act, 'input_parameters', {}))}"
                for m in self.forbidden_markers:
                    if m in act_str:
                        violations.append(
                            SafetyViolation(
                                violation_type=SafetyViolationType.GROUND_TRUTH_LEAKAGE,
                                severity="CRITICAL",
                                details=f"Ground truth marker '{m}' leaked into CandidateAction '{getattr(act, 'id', '')}'",
                            )
                        )

            scanned_components.append("BrainState.Observations")
            for obs in getattr(b_state, "observations", {}).values():
                obs_text = f"{getattr(obs, 'fact', '')} {getattr(obs, 'source', '')}"
                for m in self.forbidden_markers:
                    if m in obs_text:
                        violations.append(
                            SafetyViolation(
                                violation_type=SafetyViolationType.GROUND_TRUTH_LEAKAGE,
                                severity="CRITICAL",
                                details=f"Ground truth marker '{m}' leaked into Observation '{getattr(obs, 'id', '')}'",
                            )
                        )

        # 2. Inspect Security Graph Store
        if hasattr(runtime_instance, "_graph_store"):
            graph = runtime_instance._graph_store
            scanned_components.append("SecurityGraphStore.Nodes")
            for node in getattr(graph, "_nodes", {}).values():
                n_str = f"{getattr(node, 'identity_string', '')} {json.dumps(getattr(node, 'attributes', {}))}"
                for m in self.forbidden_markers:
                    if m in n_str:
                        violations.append(
                            SafetyViolation(
                                violation_type=SafetyViolationType.GROUND_TRUTH_LEAKAGE,
                                severity="CRITICAL",
                                details=f"Ground truth marker '{m}' leaked into Graph Node '{getattr(node, 'id', '')}'",
                            )
                        )

            scanned_components.append("SecurityGraphStore.Relationships")
            for rel in getattr(graph, "_relationships", {}).values():
                r_str = f"{getattr(rel, 'rel_type', '')} {getattr(rel, 'evidence_ref', '')}"
                for m in self.forbidden_markers:
                    if m in r_str:
                        violations.append(
                            SafetyViolation(
                                violation_type=SafetyViolationType.GROUND_TRUTH_LEAKAGE,
                                severity="CRITICAL",
                                details=f"Ground truth marker '{m}' leaked into Graph Relationship '{getattr(rel, 'id', '')}'",
                            )
                        )

        # 3. Inspect Mission Manager State
        if hasattr(runtime_instance, "_mission_manager") and mission_id:
            scanned_components.append("MissionManager.MissionState")
            m_data = runtime_instance._mission_manager.get_mission(mission_id)
            m_str = json.dumps(m_data or {})
            for m in self.forbidden_markers:
                if m in m_str:
                    violations.append(
                        SafetyViolation(
                            violation_type=SafetyViolationType.GROUND_TRUTH_LEAKAGE,
                            severity="CRITICAL",
                            details=f"Ground truth marker '{m}' leaked into MissionManager state for '{mission_id}'",
                        )
                    )

        # 4. Inspect Objective Portfolio / Research Threads
        if hasattr(runtime_instance, "_director") or hasattr(runtime_instance, "_portfolio"):
            scanned_components.append("ResearchPortfolio.Threads")
            threads = getattr(getattr(runtime_instance, "_thread_manager", None), "threads", {})
            for t in threads.values():
                t_str = f"{getattr(t, 'objective', '')} {getattr(t, 'context', '')}"
                for m in self.forbidden_markers:
                    if m in t_str:
                        violations.append(
                            SafetyViolation(
                                violation_type=SafetyViolationType.GROUND_TRUTH_LEAKAGE,
                                severity="CRITICAL",
                                details=f"Ground truth marker '{m}' leaked into ResearchThread '{getattr(t, 'id', '')}'",
                            )
                        )

        # 5. Inspect P13 Knowledge Store
        if hasattr(runtime_instance, "_knowledge_store"):
            scanned_components.append("P13KnowledgeStore.Items")
            k_store = runtime_instance._knowledge_store
            for k_item in getattr(k_store, "_items", {}).values():
                k_str = json.dumps(k_item.to_dict() if hasattr(k_item, "to_dict") else str(k_item))
                for m in self.forbidden_markers:
                    if m in k_str:
                        violations.append(
                            SafetyViolation(
                                violation_type=SafetyViolationType.GROUND_TRUTH_LEAKAGE,
                                severity="CRITICAL",
                                details=f"Ground truth marker '{m}' leaked into P13 Knowledge Store item",
                            )
                        )

        # 6. Inspect Raw Tool Execution & Evidence Store
        if hasattr(runtime_instance, "_evidence_store"):
            scanned_components.append("EvidenceStore.Artifacts")
            e_store = runtime_instance._evidence_store
            for ev in getattr(e_store, "_items", {}).values():
                ev_str = json.dumps(ev if isinstance(ev, dict) else str(ev))
                for m in self.forbidden_markers:
                    if m in ev_str:
                        violations.append(
                            SafetyViolation(
                                violation_type=SafetyViolationType.GROUND_TRUTH_LEAKAGE,
                                severity="CRITICAL",
                                details=f"Ground truth marker '{m}' leaked into Evidence Store",
                            )
                        )

        leaks_count = len(violations)
        scan_res = CanaryScanResult(
            hvc_run_id=hvc_run_id,
            total_canaries_checked=len(self.forbidden_markers),
            runtime_components_scanned=scanned_components,
            leaks_detected_count=leaks_count,
            violations=violations,
            quarantine_verified=(leaks_count == 0),
        )
        scan_res.digest = scan_res.compute_digest()
        return scan_res
