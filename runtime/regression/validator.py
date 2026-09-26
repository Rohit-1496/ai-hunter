"""
Phase 12: Targeted Regression Validator

Designs and coordinates minimal targeted experiments to validate regression hypotheses
passing strictly through Phase 5 controlled execution and Phase 11 safe PoCs.

Phase A final hardening:
- Every HTTP target is re-validated with ScopeResolver + SSRFValidator
  (DNS consulted) immediately before plan construction.
- DNS answers are pinned via curl --resolve when DNS was consulted.
- Curl argv includes --max-redirs 0 and --noproxy *.
- Policy evaluation errors and pin failures fail closed (no execution).
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any, Sequence

from runtime.executor.interface import ExecutionResult, TacticalExecutorInterface
from runtime.executor.planner import ExecutionPlan
from runtime.orchestration.budget import MissionBudget
from runtime.regression.baseline import RegressionBaselinePreserver
from runtime.regression.models import (
    RegressionExperiment,
    RegressionHypothesis,
    RegressionResult,
    RegressionStatus,
)
from runtime.regression.regression import RegressionDetector


class TargetedRegressionValidator:
    """
    Executes minimal targeted validation experiments for regression hypotheses.
    """

    def __init__(
        self,
        executor: TacticalExecutorInterface,
        detector: RegressionDetector | None = None,
        baseline_preserver: RegressionBaselinePreserver | None = None,
    ) -> None:
        self.executor = executor
        self.detector = detector or RegressionDetector()
        self.baseline_preserver = baseline_preserver or RegressionBaselinePreserver()

    def design_experiment(
        self,
        hypothesis: RegressionHypothesis,
        *,
        target_endpoint: str = "",
        method: str = "GET",
        headers: dict[str, str] | None = None,
        controlled_variable: str = "authorization_boundary",
    ) -> RegressionExperiment:
        """
        Designs the minimal single-variable experiment capable of validating the regression hypothesis.
        """
        headers = headers or {}
        step = {
            "step_number": 1,
            "action": "EXECUTE_REGRESSION_PROBE",
            "target": target_endpoint or (hypothesis.affected_graph_nodes[0] if hypothesis.affected_graph_nodes else "http://127.0.0.1/"),
            "method": method,
            "headers": headers,
        }
        return RegressionExperiment(
            experiment_id=f"REXP-{secrets.token_hex(4).upper()}",
            hypothesis_id=hypothesis.hypothesis_id,
            controlled_variable=controlled_variable,
            test_plan=[step],
            evidence_requirements=["response_status", "response_body", "auth_behavior"],
            budget_reserved=1.0,
            status="PLANNED",
        )

    def execute_validation(
        self,
        hypothesis: RegressionHypothesis,
        experiment: RegressionExperiment,
        *,
        mission_id: str = "",
        budget: MissionBudget | None = None,
        original_finding: dict[str, Any] | None = None,
        scope_valid: bool = True,
        counter_test_endpoint: str | None = None,
        mission_scope: Sequence[str] | None = None,
        excluded_scope: Sequence[str] | None = None,
        resolve_ssrf: bool = True,
    ) -> RegressionResult:
        """
        Executes the targeted experiment strictly through Phase 5, evaluates counter-test, and detects regression result.
        """
        # 1. Budget check & reservation
        reservation_id = None
        if budget:
            reservation_id = budget.reserve("execution", experiment.budget_reserved)
            if reservation_id is None:
                return self.detector.evaluate_regression(
                    hypothesis,
                    budget_sufficient=False,
                    scope_valid=scope_valid,
                )

        # 2. Scope check (caller-provided verdict; bootstrap recomputes live)
        if not scope_valid:
            if budget and reservation_id:
                budget.release(reservation_id)
            return self.detector.evaluate_regression(
                hypothesis,
                scope_valid=False,
            )

        # 3. Execute probe step via Phase 5 TacticalExecutorInterface
        plan_step = experiment.test_plan[0] if experiment.test_plan else {}
        target = plan_step.get("target", "http://127.0.0.1/")
        method = str(plan_step.get("method", "GET")).upper()
        headers = plan_step.get("headers", {}) or {}

        if not target.startswith(("http://", "https://")):
            if budget and reservation_id:
                budget.release(reservation_id)
            return self.detector.evaluate_regression(
                hypothesis, scope_valid=False, budget_sufficient=True,
            )

        # 3a. Centralized scope + SSRF (DNS) immediately before plan build.
        pin_ip: str | None = None
        if mission_scope is not None:
            from runtime.executor.adapters.curl import CurlAdapter, _validate_method, _validate_header_name, _validate_header_value
            from runtime.scope.resolver import ScopeResolver
            from runtime.scope.ssrf import SSRFValidator

            scope_verdict = ScopeResolver.decide(
                target, mission_scope,
                excluded_scope=excluded_scope or [], mission_id=mission_id or hypothesis.mission_id,
            )
            if not scope_verdict.allowed:
                if budget and reservation_id:
                    budget.release(reservation_id)
                return self.detector.evaluate_regression(
                    hypothesis, scope_valid=False, budget_sufficient=True,
                )
            try:
                ssrf = SSRFValidator().validate_url(
                    target,
                    mission_scope=mission_scope,
                    excluded_scope=excluded_scope or [],
                    resolve_dns=resolve_ssrf,
                    mission_id=mission_id or hypothesis.mission_id,
                )
            except Exception:
                if budget and reservation_id:
                    budget.release(reservation_id)
                return self.detector.evaluate_regression(
                    hypothesis, scope_valid=False, budget_sufficient=True,
                )
            if not ssrf.allowed:
                if budget and reservation_id:
                    budget.release(reservation_id)
                return self.detector.evaluate_regression(
                    hypothesis, scope_valid=False, budget_sufficient=True,
                )
            pin_ip = SSRFValidator().select_pin_ip(ssrf)
            if ssrf.resolved_ips and not pin_ip:
                if budget and reservation_id:
                    budget.release(reservation_id)
                return self.detector.evaluate_regression(
                    hypothesis, scope_valid=False, budget_sufficient=True,
                )

            adapter = CurlAdapter()
            try:
                tool = type("T", (), {
                    "id": "curl", "binary": "curl",
                    "timeout_defaults": 30,
                    "supported_capabilities": ["HTTP_REQUEST"],
                })()
                exec_plan = adapter.build_plan(
                    mission_id or hypothesis.mission_id,
                    f"action-reg-{experiment.experiment_id}",
                    "HTTP_REQUEST",
                    tool,
                    {"url": target, "method": method, "headers": dict(headers)},
                    mission_scope=mission_scope,
                    excluded_scope=excluded_scope or [],
                    resolve_dns=False,
                    resolve_ip=pin_ip,
                )
            except ValueError:
                if budget and reservation_id:
                    budget.release(reservation_id)
                return self.detector.evaluate_regression(
                    hypothesis, scope_valid=False, budget_sufficient=True,
                )
        else:
            # Legacy path (no scope supplied): still harden argv, never shell.
            from runtime.executor.adapters.curl import _validate_method, _validate_header_name, _validate_header_value

            args = ["--silent", "--max-time", "30", "--max-redirs", "0",
                    "--noproxy", "*", "-X", _validate_method(method)]
            for hname, hval in headers.items():
                args.extend(["-H", f"{_validate_header_name(hname)}: {_validate_header_value(hval)}"])
            args.append(target)
            exec_plan = ExecutionPlan(
                execution_id=f"EXEC-{secrets.token_hex(4)}",
                mission_id=mission_id or hypothesis.mission_id,
                action_id=f"action-reg-{experiment.experiment_id}",
                capability_id="HTTP_REQUEST",
                tool_id="curl",
                target=target,
                binary_path="curl",
                validated_arguments=args,
                timeout=30,
            )

        # 4. Enforce scope_valid contract before touching the executor.
        if not scope_valid:
            if budget and reservation_id:
                budget.release(reservation_id)
            return self.detector.evaluate_regression(
                hypothesis, scope_valid=False, budget_sufficient=True,
            )

        exec_result: ExecutionResult = self.executor.execute(exec_plan)

        # 5. Consume Budget
        if budget and reservation_id:
            budget.consume(reservation_id, experiment.budget_reserved)

        # 6. Evaluate result
        evidence_id = f"EV-REG-{secrets.token_hex(4).upper()}"
        stdout_text = ""
        if exec_result.stdout_reference:
            try:
                p = Path(exec_result.stdout_reference)
                if p.exists():
                    stdout_text = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass
        if not stdout_text and exec_result.raw_output:
            stdout_text = exec_result.raw_output

        observed = stdout_text or f"Status: {exec_result.status}, Exit code: {exec_result.exit_code}"

        # Determine if security violation observed
        is_violation = (
            exec_result.status == "COMPLETED"
            and exec_result.exit_code == 0
            and (
                "vulnerable" in stdout_text.lower()
                or "user_promoted_admin" in stdout_text.lower()
                or "200 ok" in stdout_text.lower()
                or "leak" in stdout_text.lower()
            )
            and "forbidden" not in stdout_text.lower()
            and "insufficient privileges" not in stdout_text.lower()
            and "unauthorized" not in stdout_text.lower()
            and "403" not in stdout_text.lower()
            and "401" not in stdout_text.lower()
        )
        # Phase A — Safety Lockdown: counter-test status is derived from the
        # actually executed probe above, never hardcoded. The control is
        # valid only if the probe completed and produced observable output;
        # a silent/empty run must NOT confirm a fix (fail closed).
        counter_test_passed = (
            exec_result.status == "COMPLETED" and bool(stdout_text.strip())
        )

        experiment_data = {
            "observed_behavior": observed,
            "evidence_refs": [evidence_id],
            "vulnerability_reproduced": is_violation,
            "status_changed": True,
            "impact": original_finding.get("impact", {"severity": "HIGH"}) if original_finding else {"severity": "HIGH"},
            "pinned_ip": pin_ip or "",
        }
        experiment.status = "COMPLETED"
        experiment.results = [experiment_data]

        return self.detector.evaluate_regression(
            hypothesis,
            experiment_result=experiment_data,
            counter_test_passed=counter_test_passed,
            is_security_violation=is_violation,
            original_finding=original_finding,
            scope_valid=scope_valid,
            budget_sufficient=True,
        )
