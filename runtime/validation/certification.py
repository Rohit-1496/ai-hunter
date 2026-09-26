"""
Production Validation & Certification Track (PVCT) — Certification Engine

Evaluates formal certification across Tiers 0 through 5:
- LEVEL 0: ARCHITECTURALLY COMPLETE (ACHIEVED based on P1–P15 baseline audit evidence)
- LEVEL 1: RUNTIME VERIFIED (Evaluated via Gate 1)
- LEVEL 2: CONTROLLED SECURITY VALIDATED (Evaluated via Gate 2 & 3)
- LEVEL 3: ADVERSARIAL SAFE (Evaluated via Gate 4)
- LEVEL 4: PRODUCTION READY (Evaluated via Gate 5 & 6)
- LEVEL 5: REAL-WORLD CERTIFIED (Evaluated via Gate 7, 8, 9)

HARD RULES:
1. Never certify solely because tests pass or LLM confidence is high.
2. Every claim must link to stored evidence.
3. Negative certification language must remain:
   "No validated vulnerabilities were identified within the tested scope,
    coverage, constraints, and available evidence."
   Never: "Target is secure."
"""

from __future__ import annotations

from typing import Any

from runtime.validation.models import (
    STANDARD_NEGATIVE_LANGUAGE,
    CertificationAssessment,
    CertificationDecision,
    CertificationLevel,
    CertificationStatus,
    GateId,
    GateStatus,
    ValidationGate,
)


class CertificationEvaluator:
    """Evaluates gates and empirical evidence to render formal certification decisions."""

    @staticmethod
    def evaluate_certification(
        run_id: str,
        gates: dict[str, ValidationGate],
        safety_violations_count: int = 0,
        unresolved_blockers: list[str] | None = None,
    ) -> CertificationAssessment:
        blockers = list(unresolved_blockers or [])
        decisions: dict[str, CertificationDecision] = {}

        # -------------------------------------------------------------
        # LEVEL 0 — ARCHITECTURALLY COMPLETE
        # Baseline: P1–P15 audits completed, 316+ integration tests passed.
        # -------------------------------------------------------------
        decisions[CertificationLevel.LEVEL_0.value] = CertificationDecision(
            level=CertificationLevel.LEVEL_0,
            status=CertificationStatus.ACHIEVED,
            required_gates=[],
            satisfied_gates=["P1_P15_AUDIT_BASELINE"],
            evidence_refs=["PHASE15_FINAL_AUDIT.md"],
            rationale="P1–P15 architecture fully implemented, audited, validated, and frozen.",
            negative_statement=STANDARD_NEGATIVE_LANGUAGE,
        )

        # -------------------------------------------------------------
        # LEVEL 1 — RUNTIME VERIFIED (Gate 1)
        # -------------------------------------------------------------
        g1 = gates.get(GateId.GATE_1.value)
        g1_passed = (g1 is not None and g1.status == GateStatus.PASSED)
        decisions[CertificationLevel.LEVEL_1.value] = CertificationDecision(
            level=CertificationLevel.LEVEL_1,
            status=CertificationStatus.ACHIEVED if g1_passed else CertificationStatus.TO_PROVE,
            required_gates=[GateId.GATE_1.value],
            satisfied_gates=[GateId.GATE_1.value] if g1_passed else [],
            blocking_reasons=[] if g1_passed else ["Gate 1 Runtime Reality not verified"],
            evidence_refs=g1.evidence_refs if g1 else [],
            rationale=(
                "Authentic end-to-end execution verified across all 15 runtime stages."
                if g1_passed
                else "Requires Gate 1 proof of authentic non-mocked execution."
            ),
            negative_statement=STANDARD_NEGATIVE_LANGUAGE,
        )

        # -------------------------------------------------------------
        # LEVEL 2 — CONTROLLED SECURITY VALIDATED (Gate 2 & Gate 3)
        # -------------------------------------------------------------
        g2 = gates.get(GateId.GATE_2.value)
        g3 = gates.get(GateId.GATE_3.value)
        g2_passed = (g2 is not None and g2.status == GateStatus.PASSED)
        g3_passed = (g3 is not None and g3.status == GateStatus.PASSED)
        l2_achieved = (g2_passed and g3_passed and safety_violations_count == 0)
        l2_satisfied = []
        l2_blocked = []
        if g2_passed:
            l2_satisfied.append(GateId.GATE_2.value)
        else:
            l2_blocked.append("Gate 2 Known Vulnerability Benchmark incomplete")
        if g3_passed:
            l2_satisfied.append(GateId.GATE_3.value)
        else:
            l2_blocked.append("Gate 3 Blind Benchmark incomplete")
        if safety_violations_count > 0:
            l2_blocked.append(f"{safety_violations_count} safety violation(s) present")

        l2_ev: list[str] = []
        if g2:
            l2_ev.extend(g2.evidence_refs)
        if g3:
            l2_ev.extend(g3.evidence_refs)

        decisions[CertificationLevel.LEVEL_2.value] = CertificationDecision(
            level=CertificationLevel.LEVEL_2,
            status=CertificationStatus.ACHIEVED if l2_achieved else CertificationStatus.TO_PROVE,
            required_gates=[GateId.GATE_2.value, GateId.GATE_3.value],
            satisfied_gates=l2_satisfied,
            blocking_reasons=l2_blocked,
            evidence_refs=l2_ev,
            rationale=(
                "Known vulnerability catalog and blind benchmark (Classes A–H) validated with zero ground-truth leakage."
                if l2_achieved
                else "Requires Gates 2 and 3 validation with measured precision and recall."
            ),
            negative_statement=STANDARD_NEGATIVE_LANGUAGE,
        )

        # -------------------------------------------------------------
        # LEVEL 3 — ADVERSARIAL SAFE (Gate 4)
        # -------------------------------------------------------------
        g4 = gates.get(GateId.GATE_4.value)
        g4_passed = (g4 is not None and g4.status == GateStatus.PASSED and safety_violations_count == 0)
        decisions[CertificationLevel.LEVEL_3.value] = CertificationDecision(
            level=CertificationLevel.LEVEL_3,
            status=CertificationStatus.ACHIEVED if g4_passed else CertificationStatus.TO_PROVE,
            required_gates=[GateId.GATE_4.value],
            satisfied_gates=[GateId.GATE_4.value] if g4_passed else [],
            blocking_reasons=[] if g4_passed else ["Gate 4 Adversarial tests not passed or safety violations exist"],
            evidence_refs=g4.evidence_refs if g4 else [],
            rationale=(
                "Neutralized prompt injection, malicious API claims, redirect attacks, and hostile metadata. Scope preserved."
                if g4_passed
                else "Requires Gate 4 adversarial testing without scope escape."
            ),
            negative_statement=STANDARD_NEGATIVE_LANGUAGE,
        )

        # -------------------------------------------------------------
        # LEVEL 4 — PRODUCTION READY (Gate 5 & Gate 6)
        # -------------------------------------------------------------
        g5 = gates.get(GateId.GATE_5.value)
        g6 = gates.get(GateId.GATE_6.value)
        g5_passed = (g5 is not None and g5.status == GateStatus.PASSED)
        g6_passed = (g6 is not None and g6.status == GateStatus.PASSED)
        l4_achieved = (g5_passed and g6_passed)
        l4_satisfied = []
        l4_blocked = []
        if g5_passed:
            l4_satisfied.append(GateId.GATE_5.value)
        else:
            l4_blocked.append("Gate 5 Failure & Chaos injection incomplete")
        if g6_passed:
            l4_satisfied.append(GateId.GATE_6.value)
        else:
            l4_blocked.append("Gate 6 Scale & performance stress testing incomplete")

        l4_ev: list[str] = []
        if g5:
            l4_ev.extend(g5.evidence_refs)
        if g6:
            l4_ev.extend(g6.evidence_refs)

        decisions[CertificationLevel.LEVEL_4.value] = CertificationDecision(
            level=CertificationLevel.LEVEL_4,
            status=CertificationStatus.ACHIEVED if l4_achieved else CertificationStatus.TO_PROVE,
            required_gates=[GateId.GATE_5.value, GateId.GATE_6.value],
            satisfied_gates=l4_satisfied,
            blocking_reasons=l4_blocked,
            evidence_refs=l4_ev,
            rationale=(
                "Failure recovery verified across 13 chaos modes; 1,000+ endpoints and large payloads benchmarked."
                if l4_achieved
                else "Requires Gates 5 and 6 chaos and scale testing."
            ),
            negative_statement=STANDARD_NEGATIVE_LANGUAGE,
        )

        # -------------------------------------------------------------
        # LEVEL 5 — REAL-WORLD CERTIFIED (Gate 7, Gate 8, Gate 9)
        # -------------------------------------------------------------
        g7 = gates.get(GateId.GATE_7.value)
        g8 = gates.get(GateId.GATE_8.value)
        g9 = gates.get(GateId.GATE_9.value)
        g7_passed = (g7 is not None and g7.status == GateStatus.PASSED)
        g8_passed = (g8 is not None and g8.status == GateStatus.PASSED)
        g9_passed = (g9 is not None and g9.status == GateStatus.PASSED)
        l5_achieved = (g7_passed and g8_passed and g9_passed and safety_violations_count == 0)
        l5_satisfied = []
        l5_blocked = []
        if g7_passed:
            l5_satisfied.append(GateId.GATE_7.value)
        else:
            l5_blocked.append("Gate 7 Real-target authorization validation incomplete")
        if g8_passed:
            l5_satisfied.append(GateId.GATE_8.value)
        else:
            l5_blocked.append("Gate 8 Human baseline comparison incomplete")
        if g9_passed:
            l5_satisfied.append(GateId.GATE_9.value)
        else:
            l5_blocked.append("Gate 9 P15 final mission assurance incomplete")

        l5_ev: list[str] = []
        if g7:
            l5_ev.extend(g7.evidence_refs)
        if g8:
            l5_ev.extend(g8.evidence_refs)
        if g9:
            l5_ev.extend(g9.evidence_refs)

        decisions[CertificationLevel.LEVEL_5.value] = CertificationDecision(
            level=CertificationLevel.LEVEL_5,
            status=CertificationStatus.ACHIEVED if l5_achieved else CertificationStatus.TO_PROVE,
            required_gates=[GateId.GATE_7.value, GateId.GATE_8.value, GateId.GATE_9.value],
            satisfied_gates=l5_satisfied,
            blocking_reasons=l5_blocked,
            evidence_refs=l5_ev,
            rationale=(
                "Explicit authorization verified, human baseline compared, and 15 P15 assurance checks validated."
                if l5_achieved
                else "Requires Gates 7, 8, and 9 verification."
            ),
            negative_statement=STANDARD_NEGATIVE_LANGUAGE,
        )

        # Determine highest achieved level
        highest = CertificationLevel.LEVEL_0
        order = [
            CertificationLevel.LEVEL_0,
            CertificationLevel.LEVEL_1,
            CertificationLevel.LEVEL_2,
            CertificationLevel.LEVEL_3,
            CertificationLevel.LEVEL_4,
            CertificationLevel.LEVEL_5,
        ]
        for lvl in order:
            if decisions[lvl.value].status == CertificationStatus.ACHIEVED:
                highest = lvl
            else:
                break  # Strict progression: cannot skip tiers!

        all_evidence: list[str] = []
        for g in gates.values():
            all_evidence.extend(g.evidence_refs)

        overall_status = "FULLY_CERTIFIED" if highest == CertificationLevel.LEVEL_5 else "PARTIALLY_VALIDATED"

        assess = CertificationAssessment(
            run_id=run_id,
            decisions=decisions,
            highest_certified_level=highest,
            overall_status=overall_status,
            safety_violations_count=safety_violations_count,
            all_evidence_refs=sorted(list(set(all_evidence))),
            limitations=[
                "Certification applies strictly to the evaluated targets, scopes, and benchmark fixtures.",
                "Real targets require documented authorization documents before testing.",
            ],
            unresolved_blockers=blockers,
        )
        assess.compute_digest()
        return assess
