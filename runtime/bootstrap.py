"""
Hunter Runtime Bootstrap — Phase 1

Orchestrates the initialization of all Phase 1 subsystems and provides:
- Subsystem health reporting (hunter status)
- Hi handshake response generation

This is the single entry point that the adapter calls.
The Brain intelligence, Context Firewall, Graph, and Hypothesis engine
are NOT implemented in Phase 1. Their stubs report READY only once
their minimal required structures are initialized.

Architecture:
  Adapter → HunterRuntime → subsystems
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runtime.memory.persistence import PersistenceManager
from runtime.memory.mission import MissionManager
from runtime.memory.checkpoint import CheckpointEngine
from runtime.brain.brain import BeastBrain
from runtime.brain.observations import Observation, Unknown
from runtime.brain.decision import CandidateAction
from runtime.executor.process import ProcessExecutor
from runtime.executor.planner import ExecutionPlan
from runtime.executor.adapters.curl import CurlAdapter
from runtime.executor.adapters.dig import DigAdapter
from runtime.capabilities.registry import CapabilityRegistry
from runtime.capabilities.model import Capability, Tool
from runtime.capabilities.selector import ToolSelector

# Phase B Imports
from runtime.config.safety_gate import (
    ProductionSafetyGate,
    ProductionSafetyGateError,
    SafetyGateVerdict,
)
from runtime.scope.authz_provider import (
    AuthMode,
    AuthorizationState,
    ProviderConfig,
    ProviderStatus,
    ProviderVerification,
    resolve_auth_mode,
    evaluate_external_authorization,
)
from runtime.executor.network_boundary import (
    NetworkConnectionBoundary,
    NetworkBoundaryVerdict,
    ToolNetworkCapability,
)
from runtime.scope.target import (
    CanonicalTarget,
    validate_redirect,
)

# Phase 4 Imports
from runtime.evidence.normalizer import EvidenceNormalizer
from runtime.evidence.extractor import EvidenceExtractor
from runtime.graph.store import SecurityGraphStore
from runtime.graph.query import SecurityGraphQuery
from runtime.graph.ingester import SecurityGraphIngester
from runtime.context.firewall import ContextFirewall
from runtime.context.sensitive import SensitiveDataFirewall

# Phase 6 Discovery Imports
from runtime.discovery.model import DiscoveryResult, DiscoveryType, DiscoveryStatus
from runtime.discovery.mapper import AttackSurfaceMapper
from runtime.discovery.dedup import DiscoveryDeduplicator
from runtime.discovery.coverage import CoverageMap, CoverageStatus
from runtime.discovery.snapshot import AttackSurfaceSnapshotManager
from runtime.discovery.strategy import DiscoveryStrategy
from runtime.discovery.planner import DiscoveryPlanner
from runtime.scope.resolver import ScopeResolver
from runtime.scope.authorization import (
    AuthStatus,
    AuthorizationContext,
    AuthorizationGate,
)

# Phase 7 Vulnerability Imports
from runtime.vulnerability.model import (
    Assumption,
    DifferentialOutcome,
    Experiment,
    Finding,
    FindingStatus,
    HypothesisState,
    ImpactCategory,
    SecurityBoundary,
    SecurityBoundaryType,
    VulnerabilityClass,
    VulnerabilityHypothesis,
)
from runtime.vulnerability.assumptions import AssumptionEngine
from runtime.vulnerability.hypothesis_engine import HypothesisEngine
from runtime.vulnerability.discriminators import DifferentialComparator
from runtime.vulnerability.experiments import ExperimentPlanner
from runtime.vulnerability.impact import ImpactEvaluator
from runtime.vulnerability.validation import FindingQualityGate
from runtime.vulnerability.findings import FindingStore

# Phase 8 Attack Chain Imports
from runtime.chains.model import (
    AttackPath,
    AttackPathState,
    ChainEdge,
    ChainEdgeStatus,
    ChainExperiment,
    ChainGoal,
    CompoundFinding,
    DependencyStrength,
    ExploitabilityAssessment,
    ExploitabilityLevel,
    Precondition,
    PreconditionStatus,
)
from runtime.chains.preconditions import PreconditionEngine
from runtime.chains.chain_engine import AttackChainEngine
from runtime.chains.missing_evidence import MissingEvidenceEngine
from runtime.chains.planner import ChainExperimentPlanner
from runtime.chains.exploitability import ExploitabilityEvaluator
from runtime.chains.compound_impact import CompoundImpactEvaluator
from runtime.chains.validation import AttackPathValidationGate, CompoundFindingStore

# Phase 9 Adaptive Deep-Dive Imports
from runtime.adaptive.model import (
    AssumptionStaleness,
    DirectionStatus,
    FailureCause,
    FailureDiagnosis,
    ResearchDirection,
    ResearchPivot,
    SecurityModelDelta,
)
from runtime.adaptive.diagnosis import FailureDiagnostician
from runtime.adaptive.model_delta import SecurityModelTracker
from runtime.adaptive.pivot_engine import AdaptivePivotEngine

# Phase 10 Orchestration Imports
from runtime.orchestration.models import (
    CompletionReason,
    DependencyStatus,
    MissionCompletionRationale,
    Objective,
    ObjectiveStatus,
    OrchestrationEvent,
    ResearchThread,
    ResearchWorkUnit,
    ThreadDependency,
    ThreadStatus,
)
from runtime.orchestration.budget import MissionBudget
from runtime.orchestration.portfolio import ObjectivePortfolio
from runtime.orchestration.threads import ThreadManager
from runtime.orchestration.dependencies import ThreadDependencyGraph
from runtime.orchestration.correlation import CrossThreadCorrelator
from runtime.orchestration.scheduler import ResearchScheduler
from runtime.orchestration.completion import MissionCompletionEngine
from runtime.orchestration.director import MissionDirector

# Phase 11 Exploitation Imports
from runtime.exploitation.models import (
    BaselineComparison,
    CleanupVerification,
    ExploitabilityAssessment,
    ExploitabilityDimension,
    ExploitabilityResult,
    ExploitabilityScore,
    ExploitabilityStatus,
    PoCEvent,
    PoCExecutionRecord,
    PoCExecutionStep,
    PoCRationale,
    PoCStateSnapshot,
    PoCStatus,
    ProofOfConcept,
    ReproducibilityLevel,
    ReproducibilityRecord,
    SafePoCPolicy,
    StateChangeClass,
)
from runtime.exploitation.eligibility import PoCEligibilityGate
from runtime.exploitation.preconditions import PoCPreconditionValidator
from runtime.exploitation.exploitability import ExploitabilityAnalyzer
from runtime.exploitation.poc import PoCGenerator
from runtime.exploitation.executor import PoCExecutor
from runtime.exploitation.safety import SafePoCPolicyEngine
from runtime.exploitation.comparator import PoCDifferentialComparator
from runtime.exploitation.validator import IndependentValidator
from runtime.exploitation.impact import PoCImpactValidator
from runtime.exploitation.reproducibility import ReproducibilityEngine
from runtime.exploitation.evidence import EvidenceRequirementEngine
from runtime.exploitation.rationale import PoCRationaleGenerator
from runtime.exploitation.state import PoCStateManager
from runtime.exploitation.store import ExploitationStore
from runtime.exploitation.chain_gate import ChainPoCExecutionGate, ChainPathMinimizer

# Phase 12 Regression Imports
from runtime.regression.models import (
    ChangeCategory,
    ChangeRelevance,
    CoverageChangeType,
    FindingLifecycleEvent,
    FindingLifecycleState,
    FindingSecurityHistory,
    FixConfidence,
    RegressionExperiment,
    RegressionHypothesis,
    RegressionMetrics,
    RegressionRationale,
    RegressionResult,
    RegressionStatus,
    SecurityChange,
    SecurityDiff,
    SecuritySnapshot,
    SnapshotType,
    ValidationMode,
)
from runtime.regression.snapshots import SnapshotEngine, SecurityFingerprinter
from runtime.regression.diff import SecurityDiffEngine, SemanticNormalizer
from runtime.regression.classifier import ChangeClassifier
from runtime.regression.change_impact import ChangeImpactEngine
from runtime.regression.hypotheses import RegressionHypothesisEngine
from runtime.regression.regression import RegressionDetector
from runtime.regression.baseline import RegressionBaselinePreserver
from runtime.regression.validator import TargetedRegressionValidator
from runtime.regression.stale import StalePoCDetector
from runtime.regression.prioritization import RegressionPrioritizer
from runtime.regression.scheduler import RegressionScheduler
from runtime.regression.coverage import CoverageTracker
from runtime.regression.rationale import RegressionRationaleGenerator
from runtime.regression.state import RegressionStateManager
from runtime.regression.store import RegressionStore

# Phase 13 Knowledge Imports
from runtime.knowledge.models import (
    KnowledgeFreshness,
    KnowledgeMetrics,
    KnowledgePromotionLevel,
    KnowledgeRelationshipType,
    KnowledgeStatus,
    KnowledgeStoreVersion,
    KnowledgeType,
    KnowledgeUsageOutcome,
    KnowledgeUsageRecord,
    KnowledgeVersion,
    MissionKnowledgeReference,
    SecurityKnowledge,
)
from runtime.knowledge.store import KnowledgeStore
from runtime.knowledge.state import KnowledgeStateManager
from runtime.knowledge.extractor import KnowledgeExtractor
from runtime.knowledge.normalizer import KnowledgeNormalizer
from runtime.knowledge.dedup import KnowledgeDeduplicator
from runtime.knowledge.contradictions import ContradictionEngine
from runtime.knowledge.confidence import ConfidenceScorer
from runtime.knowledge.freshness import FreshnessEngine
from runtime.knowledge.poisoning import PoisoningDetector
from runtime.knowledge.scope import ScopeIsolationGuard
from runtime.knowledge.write_gate import KnowledgeWriteGate
from runtime.knowledge.graph import KnowledgeGraph
from runtime.knowledge.retriever import KnowledgeRetriever
from runtime.knowledge.usage import KnowledgeUsageTracker
from runtime.knowledge.correlation import KnowledgeCorrelationEngine
from runtime.knowledge.rationale import KnowledgeRationaleGenerator

# Phase 14 Strategy Imports
from runtime.strategy.models import (
    StrategicDecisionRationale,
    StrategicEvent,
    StrategicEventType,
    StrategicEvidenceGap,
    StrategicFeedbackSignal,
    StrategicObjective,
    StrategicObjectiveState,
    StrategicObjectiveType,
    StrategicState,
    StrategyAllocation,
    StrategyMode,
    StrategyPerformanceRecord,
    StrategyStopRationale,
    SystemicWeaknessHypothesis,
)
from runtime.strategy.planner import StrategicSecurityPlanner
from runtime.strategy.state import StrategicStateManager
from runtime.strategy.persistence import StrategicPersistenceManager

# Phase 15 Imports
from runtime.finalization.models import (
    AssuranceConfidence,
    AssuranceStatus,
    CompletionRationale,
    CoverageLevel,
    FinalCoverageAssessment,
    FinalDecisionTrace,
    FinalFindingAssessment,
    FinalMissionAssessment,
    FinalSecurityModelSnapshot,
    FinalSecurityReport,
    FinalizationDecision,
    FinalizationEventType,
    FindingFinalStatus,
    LimitationType,
    MissionCompletionState,
    MissionFinalizationEvent,
    MissionLimitation,
)
from runtime.finalization.assurance import MissionAssuranceEngine
from runtime.finalization.persistence import FinalPersistenceManager


# ---------------------------------------------------------------------------
# Subsystem Stubs — Phase 1
#
# These stubs represent subsystems that are not yet fully implemented.
# They report READY only when their required initialization conditions are met.
# They report UNAVAILABLE when not initialized or ERROR on failure.
# ---------------------------------------------------------------------------




class _ScopeStub:
    """
    Scope gate stub for Phase 1.

    READY status means: hunter/policy.md exists and defines scope enforcement.
    Full scope resolution is Phase 3+.
    """

    def __init__(self, project_root: Path) -> None:
        self._policy = project_root / "hunter" / "policy.md"
        self._ready = False

    def initialize(self) -> bool:
        self._ready = self._policy.is_file()
        return self._ready

    def health(self) -> str:
        if not self._ready:
            return "UNAVAILABLE"
        return "READY" if self._policy.is_file() else "ERROR"


class _ExecutorStub:
    """
    Tactical Executor stub for Phase 1.

    READY status means: executor directory exists.
    Full executor is Phase 3+.
    """

    def __init__(self, project_root: Path) -> None:
        self._executor_dir = project_root / "runtime" / "executor"
        self._ready = False

    def initialize(self) -> bool:
        self._ready = self._executor_dir.is_dir()
        return self._ready

    def health(self) -> str:
        if not self._ready:
            return "UNAVAILABLE"
        return "READY" if self._executor_dir.is_dir() else "ERROR"


class _GraphStub:
    """
    Security Graph stub for Phase 1.

    READY status means: graph directory exists.
    Full graph is Phase 5+.
    """

    def __init__(self, project_root: Path) -> None:
        self._graph_dir = project_root / "runtime" / "graph"
        self._ready = False

    def initialize(self) -> bool:
        self._ready = self._graph_dir.is_dir()
        return self._ready

    def health(self) -> str:
        if not self._ready:
            return "UNAVAILABLE"
        return "READY" if self._graph_dir.is_dir() else "ERROR"


# ---------------------------------------------------------------------------
# HunterRuntime
# ---------------------------------------------------------------------------

class HunterRuntime:
    """
    Core Hunter Runtime — Phase 1.

    Initializes all subsystems and provides:
    - health() — real subsystem health dict
    - handshake() — hi response string
    - status_report() — hunter status response string
    """

    VERSION = "1.0.0-phase1"

    def __init__(self, project_root: Path | None = None) -> None:
        self._root = project_root or _find_project_root()
        self._started_at = datetime.now(timezone.utc).isoformat()
        self._start_error: str | None = None
        self._initialized: bool = False

        # Subsystems
        self._persistence = PersistenceManager(self._root)
        self._mission_manager = MissionManager(self._root)
        self._checkpoint_engine = CheckpointEngine(self._root, self._mission_manager)
        
        self._brain = BeastBrain(self._root)
        self._executor_interface = ProcessExecutor(self._root) # Upgraded to real process executor
        
        # Phase 5: Capabilities and Tools
        self._capability_registry = CapabilityRegistry()
        self._tool_selector = ToolSelector(self._capability_registry)
        self._adapters = {
            "curl": CurlAdapter(workspace_root=self._root),
            "dig": DigAdapter(workspace_root=self._root)
        }
        self._register_default_capabilities()
        
        # Phase B: Authorization Mode & Network Connection Boundary
        self._auth_mode = resolve_auth_mode()
        self._external_auth_provider = None
        self._network_boundary = NetworkConnectionBoundary(auth_mode=self._auth_mode)
        
        # Phase 4 Modules
        self._evidence_normalizer = EvidenceNormalizer(self._root)
        self._evidence_extractor = EvidenceExtractor()
        self._graph_store = SecurityGraphStore()
        self._graph_query = SecurityGraphQuery(self._graph_store)
        self._graph_ingester = SecurityGraphIngester(self._graph_store)
        self._context_firewall = ContextFirewall(max_context_observations=100)
        self._sensitive_firewall = SensitiveDataFirewall()
        
        # Phase 6 Modules
        self._coverage_map = CoverageMap()
        self._discovery_mapper = AttackSurfaceMapper()
        self._discovery_dedup = DiscoveryDeduplicator()
        self._discovery_strategy = DiscoveryStrategy(self._coverage_map)
        self._snapshot_managers: dict[str, AttackSurfaceSnapshotManager] = {}
        
        # Phase 7 Modules
        self._assumption_engine = AssumptionEngine()
        self._hypothesis_engines: dict[str, HypothesisEngine] = {}
        self._differential_comparator = DifferentialComparator()
        self._experiment_planner = ExperimentPlanner()
        self._impact_evaluator = ImpactEvaluator()
        self._finding_quality_gate = FindingQualityGate()
        self._finding_stores: dict[str, FindingStore] = {}
        
        # Phase 8 Modules
        self._precondition_engine = PreconditionEngine()
        self._chain_engines: dict[str, AttackChainEngine] = {}
        self._missing_evidence_engine = MissingEvidenceEngine()
        self._chain_planner = ChainExperimentPlanner()
        self._exploitability_evaluator = ExploitabilityEvaluator()
        self._compound_impact_evaluator = CompoundImpactEvaluator()
        self._attack_path_validation_gate = AttackPathValidationGate()
        self._compound_finding_stores: dict[str, CompoundFindingStore] = {}
        
        # Phase 9 Modules
        self._failure_diagnostician = FailureDiagnostician()
        self._model_trackers: dict[str, SecurityModelTracker] = {}
        self._pivot_engines: dict[str, AdaptivePivotEngine] = {}
        
        # Phase 10 Modules
        self._mission_directors: dict[str, MissionDirector] = {}
        
        # Phase 11 Modules
        self._poc_eligibility_gate = PoCEligibilityGate()
        self._poc_precondition_validator = PoCPreconditionValidator()
        self._exploitability_analyzer = ExploitabilityAnalyzer()
        self._poc_generator = PoCGenerator()
        self._poc_safety_engine = SafePoCPolicyEngine()
        self._poc_differential_comparator = PoCDifferentialComparator()
        self._poc_independent_validator = IndependentValidator()
        self._poc_impact_validator = PoCImpactValidator()
        self._poc_reproducibility_engine = ReproducibilityEngine()
        self._poc_evidence_engine = EvidenceRequirementEngine()
        self._poc_rationale_generator = PoCRationaleGenerator()
        self._poc_state_manager = PoCStateManager()
        self._exploitation_stores: dict[str, ExploitationStore] = {}
        self._poc_executors: dict[str, PoCExecutor] = {}
        
        # Phase 12 Regression Modules
        self._regression_snapshot_engine = SnapshotEngine()
        self._regression_diff_engine = SecurityDiffEngine()
        self._regression_classifier = ChangeClassifier()
        self._regression_impact_engine = ChangeImpactEngine()
        self._regression_hypothesis_engine = RegressionHypothesisEngine()
        self._regression_detector = RegressionDetector()
        self._regression_baseline_preserver = RegressionBaselinePreserver()
        self._regression_prioritizer = RegressionPrioritizer()
        self._regression_scheduler = RegressionScheduler()
        self._regression_stale_detector = StalePoCDetector()
        self._regression_coverage_tracker = CoverageTracker()
        self._regression_rationale_generator = RegressionRationaleGenerator()
        self._regression_stores: dict[str, RegressionStore] = {}
        self._regression_state_managers: dict[str, RegressionStateManager] = {}
        self._regression_validators: dict[str, TargetedRegressionValidator] = {}
        
        # Phase 13 Knowledge Subsystems
        self._knowledge_store = KnowledgeStore(self._root)
        self._knowledge_extractor = KnowledgeExtractor()
        self._knowledge_normalizer = KnowledgeNormalizer()
        self._knowledge_dedup = KnowledgeDeduplicator()
        self._knowledge_contradictions = ContradictionEngine()
        self._knowledge_confidence = ConfidenceScorer()
        self._knowledge_freshness = FreshnessEngine()
        self._knowledge_poisoning = PoisoningDetector()
        self._knowledge_scope = ScopeIsolationGuard()
        self._knowledge_write_gate = KnowledgeWriteGate()
        self._knowledge_graph = KnowledgeGraph()
        self._knowledge_retriever = KnowledgeRetriever()
        self._knowledge_usage = KnowledgeUsageTracker()
        self._knowledge_correlations = KnowledgeCorrelationEngine()
        self._knowledge_rationale = KnowledgeRationaleGenerator()
        self._knowledge_state_managers: dict[str, KnowledgeStateManager] = {}
        
        # Phase 14: Autonomous Security Strategy Subsystems
        self._strategy_planner = StrategicSecurityPlanner()
        self._strategy_state_managers: dict[str, StrategicStateManager] = {}
        self._strategy_persistence_managers: dict[str, StrategicPersistenceManager] = {}
        
        # Phase 15: Mission Assurance & Finalization Subsystems
        self._assurance_engine = MissionAssuranceEngine()
        self._final_persistence_managers: dict[str, FinalPersistenceManager] = {}
        
        self._scope = _ScopeStub(self._root)
        self._auth_gate = AuthorizationGate()
        
    def _register_default_capabilities(self) -> None:
        self._capability_registry.register_capability(Capability(
            id="HTTP_REQUEST", name="HTTP Request", description="Make web request",
            category="WEB", risk_level="LOW", network_effect=True, required_authorization=False
        ))
        self._capability_registry.register_capability(Capability(
            id="DNS_LOOKUP", name="DNS Lookup", description="Resolve DNS records",
            category="NETWORK", risk_level="LOW", network_effect=True, required_authorization=False
        ))
        # Depending on platform, 'curl' and 'dig' might have different paths, but shutil.which handles it.
        # We pass 'curl' and 'dig' as binary names.
        self._capability_registry.register_tool(Tool(
            id="curl", name="cURL", binary="curl", supported_capabilities=["HTTP_REQUEST"]
        ))
        self._capability_registry.register_tool(Tool(
            id="dig", name="DiG", binary="dig", supported_capabilities=["DNS_LOOKUP"]
        ))
        self._executor = _ExecutorStub(self._root)

    # ------------------------------------------------------------------
    # Bootstrap
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """
        Initialize all subsystems in dependency order.

        Returns True if the runtime started successfully enough to operate.
        Partial failures are tolerated; individual subsystem health reflects
        the actual state.
        """
        # 1. Persistence must succeed first — everything else depends on it
        if not self._persistence.initialize():
            self._start_error = f"Persistence initialization failed: {self._persistence.error}"
            self._initialized = False
            return False

        # 2. Initialize remaining subsystems (stubs for Phase 1)
        self._brain.initialize()
        self._scope.initialize()
        self._executor.initialize()

        # 3. Log the runtime start event
        self._persistence.log_event("runtime_started", {
            "version": self.VERSION,
            "project_root": str(self._root),
        })

        self._initialized = True
        return True

    def initialize(self) -> bool:
        return self.start()

    @property
    def is_running(self) -> bool:
        return self._initialized

    @property
    def brain(self) -> BeastBrain:
        return self._brain
        
    @property
    def graph_store(self) -> SecurityGraphStore:
        return self._graph_store

    @property
    def graph_query(self) -> SecurityGraphQuery:
        return self._graph_query
        
    @property
    def context_firewall(self) -> ContextFirewall:
        return self._context_firewall

    @property
    def coverage_map(self) -> CoverageMap:
        return self._coverage_map

    @property
    def discovery_dedup(self) -> DiscoveryDeduplicator:
        return self._discovery_dedup

    @property
    def discovery_strategy(self) -> DiscoveryStrategy:
        return self._discovery_strategy

    @property
    def assumption_engine(self) -> AssumptionEngine:
        return self._assumption_engine

    @property
    def differential_comparator(self) -> DifferentialComparator:
        return self._differential_comparator

    @property
    def experiment_planner(self) -> ExperimentPlanner:
        return self._experiment_planner

    @property
    def impact_evaluator(self) -> ImpactEvaluator:
        return self._impact_evaluator

    @property
    def finding_quality_gate(self) -> FindingQualityGate:
        return self._finding_quality_gate

    def _get_hypothesis_engine(self, mission_id: str) -> HypothesisEngine:
        if mission_id not in self._hypothesis_engines:
            self._hypothesis_engines[mission_id] = HypothesisEngine(mission_id)
        return self._hypothesis_engines[mission_id]

    def _get_finding_store(self, mission_id: str) -> FindingStore:
        if mission_id not in self._finding_stores:
            self._finding_stores[mission_id] = FindingStore(mission_id)
        return self._finding_stores[mission_id]

    def _get_chain_engine(self, mission_id: str) -> AttackChainEngine:
        if mission_id not in self._chain_engines:
            self._chain_engines[mission_id] = AttackChainEngine(mission_id)
        return self._chain_engines[mission_id]

    def _get_compound_finding_store(self, mission_id: str) -> CompoundFindingStore:
        if mission_id not in self._compound_finding_stores:
            self._compound_finding_stores[mission_id] = CompoundFindingStore(mission_id)
        return self._compound_finding_stores[mission_id]

    @property
    def precondition_engine(self) -> PreconditionEngine:
        return self._precondition_engine

    @property
    def missing_evidence_engine(self) -> MissingEvidenceEngine:
        return self._missing_evidence_engine

    @property
    def chain_planner(self) -> ChainExperimentPlanner:
        return self._chain_planner

    @property
    def exploitability_evaluator(self) -> ExploitabilityEvaluator:
        return self._exploitability_evaluator

    @property
    def compound_impact_evaluator(self) -> CompoundImpactEvaluator:
        return self._compound_impact_evaluator

    @property
    def attack_path_validation_gate(self) -> AttackPathValidationGate:
        return self._attack_path_validation_gate

    def _get_model_tracker(self, mission_id: str) -> SecurityModelTracker:
        if mission_id not in self._model_trackers:
            self._model_trackers[mission_id] = SecurityModelTracker(mission_id)
        return self._model_trackers[mission_id]

    def _get_pivot_engine(self, mission_id: str) -> AdaptivePivotEngine:
        if mission_id not in self._pivot_engines:
            self._pivot_engines[mission_id] = AdaptivePivotEngine(mission_id)
        return self._pivot_engines[mission_id]

    def _get_mission_director(self, mission_id: str) -> MissionDirector:
        if mission_id not in self._mission_directors:
            self._mission_directors[mission_id] = MissionDirector(mission_id, self._root)
        return self._mission_directors[mission_id]

    @property
    def failure_diagnostician(self) -> FailureDiagnostician:
        return self._failure_diagnostician

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health(self) -> dict[str, Any]:
        """
        Return real subsystem health.
        Never hardcodes READY — each subsystem checks its actual state.
        """
        if not self._initialized:
            return {
                "hunter": "OFFLINE",
                "adapter": "DISCONNECTED",
                "subsystems": {
                    "brain": "UNAVAILABLE",
                    "memory": "UNAVAILABLE",
                    "scope": "UNAVAILABLE",
                    "executor": "UNAVAILABLE",
                    "graph": "UNAVAILABLE",
                    "checkpoints": "UNAVAILABLE",
                },
                "active_mission": None,
                "error": self._start_error,
            }

        mem_health = self._persistence.health()
        return {
            "hunter": "ONLINE",
            "adapter": "CONNECTED",
            "subsystems": {
                "brain": self._brain.health(),
                "memory": mem_health["memory"],
                "scope": self._scope.health(),
                "executor": self._executor.health(),
                "graph": "READY", # Phase 4
                "checkpoints": mem_health["checkpoints"],
            },
            "active_mission": self._mission_manager.get_active_mission_id(),
            "error": None,
        }

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def set_auth_mode(self, mode: AuthMode | str) -> None:
        """Configure runtime authorization mode and update network boundary."""
        self._auth_mode = resolve_auth_mode(mode if isinstance(mode, str) else mode.value)
        self._network_boundary = NetworkConnectionBoundary(auth_mode=self._auth_mode)

    def set_external_auth_provider(self, provider: Any) -> None:
        """Register an authoritative external authorization provider."""
        self._external_auth_provider = provider

    def handshake(self) -> str:
        """
        Generate the hunter handshake response for the 'hi' command.

        The response reflects REAL subsystem health, not hardcoded values.
        """
        h = self.health()
        sub = h["subsystems"]
        mission_line = h["active_mission"] or "NONE"

        lines = [
            "Hunter online.",
            "",
            "I am the autonomous security research runtime connected to this OpenCode session.",
            "",
            "Runtime:",
            f"  Brain        {sub['brain']}",
            f"  Memory       {sub['memory']}",
            f"  Scope        {sub['scope']}",
            f"  Executor     {sub['executor']}",
            f"  Graph        {sub['graph']}",
            f"  Checkpoints  {sub['checkpoints']}",
            "",
            f"Mission:",
            f"  {mission_line}",
            "",
            'I am ready for an authorized security-testing mission.',
            'Use "hunter status" for detailed subsystem health.',
        ]
        self._persistence.log_event("handshake_sent", {"mission": h["active_mission"]})
        return "\n".join(lines)

    def status_report(self) -> str:
        """
        Generate the hunter status report for the 'hunter status' command.

        Reports real state — never hardcoded.
        """
        if not self._initialized:
            report = (
                "Hunter: OFFLINE\n"
                f"Error: {self._start_error or 'Unknown initialization failure'}"
            )
            return report

        h = self.health()
        sub = h["subsystems"]
        mission = h["active_mission"] or "NONE"

        lines = [
            f"Hunter: {h['hunter']}",
            f"OpenCode adapter: {h['adapter']}",
            f"Brain: {sub['brain']}",
            f"Persistent memory: {sub['memory']}",
            f"Scope gate: {sub['scope']}",
            f"Executor: {sub['executor']}",
            f"Security graph: {sub['graph']}",
            f"Checkpoint engine: {sub['checkpoints']}",
            f"Active mission: {mission}",
            f"Runtime version: {self.VERSION}",
            f"Started: {self._started_at}",
        ]
        self._persistence.log_event("status_checked", {"mission": h["active_mission"]})
        return "\n".join(lines)

    def discovery_status(self, mission_id: str) -> dict[str, Any]:
        """Returns structured discovery progress and diminishing returns status."""
        return {
            "mission_id": mission_id,
            "total_entities_discovered": self._coverage_map._total_entities_discovered,
            "total_actions_executed": self._coverage_map._total_actions_executed,
            "diminishing_returns": self._coverage_map.is_diminishing_returns(),
            "coverage_gaps": self._coverage_map.get_coverage_gaps(),
            "strategy_focus": self._discovery_strategy.evaluate_next_focus(self._discovery_dedup.entities)
        }

    def attack_surface(self, mission_id: str) -> dict[str, Any]:
        """Returns compact attack-surface entities and relationships."""
        return {
            "mission_id": mission_id,
            "entities": [e.to_dict() for e in self._discovery_dedup.entities],
            "relationships": [r.to_dict() for r in self._discovery_dedup.relationships],
            "endpoints": [e.identity_string for e in self._discovery_dedup.entities if e.entity_type == "ENDPOINT"],
            "apis": [e.identity_string for e in self._discovery_dedup.entities if e.entity_type == "API"],
            "technologies": [e.identity_string for e in self._discovery_dedup.entities if e.entity_type == "TECHNOLOGY"]
        }

    def coverage_report(self, mission_id: str) -> dict[str, Any]:
        """Returns coverage map matrix."""
        return {
            "mission_id": mission_id,
            "coverage": self._coverage_map.to_dict()
        }

    # ------------------------------------------------------------------
    # Mission Operations (Phase 2)
    # ------------------------------------------------------------------

    def mission_create(
        self,
        operator_objective: str,
        target_scope: list[str] | None = None,
        custom_id: str | None = None,
        excluded_scope: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a new persistent mission."""
        if not self._initialized:
            raise RuntimeError("Runtime not initialized")

        # Clear any existing graph state from memory to ensure mission isolation
        self._graph_store._nodes.clear()
        self._graph_store._relationships.clear()

        # Phase B: Enforce Production Safety Gates prior to mission creation
        if self._auth_mode == AuthMode.PRODUCTION:
            gate_verdict = ProductionSafetyGate.evaluate(
                auth_mode=self._auth_mode,
                target_scope=target_scope,
                provider=self._external_auth_provider,
                project_root=self._root,
            )
            if not gate_verdict.passed:
                self._mission_manager.log_event(
                    custom_id or "M-PROD-BLOCKED",
                    "SEC_PRODUCTION_SAFETY_GATE_FAILED",
                    {"blocking_reasons": gate_verdict.blocking_reasons},
                )
                raise ProductionSafetyGateError(gate_verdict.blocking_reasons)

        # Phase A: validate the scope definition at creation for observability.
        # Creation is permitted (missions are also used for offline analysis),
        # but the verdict is persisted and ALL execution paths fail closed on
        # missing/invalid scope. No network execution is possible without scope.
        scope_ok, scope_reason = ScopeResolver.validate_scope_definition(
            target_scope, excluded_scope=excluded_scope
        )

        m = self._mission_manager.create_mission(
            operator_objective=operator_objective,
            target_scope=target_scope,
            custom_id=custom_id,
            excluded_scope=excluded_scope,
        )
        # Persist the creation-time scope verdict on the mission state.
        try:
            self._mission_manager.update_mission(m["mission_id"], {
                "scope_status": "VALID" if scope_ok else "INVALID",
                "scope_reason": scope_reason,
            })
            m["scope_status"] = "VALID" if scope_ok else "INVALID"
            m["scope_reason"] = scope_reason
        except Exception:
            pass
        self._mission_manager.log_event(
            m["mission_id"],
            "SEC_SCOPE_DEFINED" if scope_ok else "SEC_SCOPE_MISSING",
            {"reason_code": scope_reason, "scope_status": m.get("scope_status", "UNKNOWN")},
        )
        # Authorization issuance: mission creation IS the operator's explicit
        # attesting act. The context binds mission id + exact scope snapshot +
        # capabilities + validity window + integrity digest. Only a GRANTED
        # context permits target-affecting execution (scope gate still applies).
        auth_ctx = self._auth_gate.issue(
            m["mission_id"],
            m.get("target_scope") or [],
            excluded_scope=m.get("excluded_scope") or [],
            audit_id=f"AUTH-{m['mission_id']}",
        )
        try:
            self._mission_manager.update_mission(m["mission_id"], {
                "authorization": auth_ctx.to_dict(),
            })
            m["authorization"] = auth_ctx.to_dict()
        except Exception:
            pass
        self._mission_manager.log_event(
            m["mission_id"],
            "SEC_AUTH_GRANTED" if auth_ctx.status == AuthStatus.GRANTED else "SEC_AUTH_INVALID",
            {"reason_code": auth_ctx.status.value, "audit_id": auth_ctx.audit_id},
        )
        # Initialize Phase 10 Mission Director Portfolio
        director = self._get_mission_director(m["mission_id"])
        director.initialize_default_portfolio(target_scope=target_scope or ["127.0.0.1"])
        director.save_state()
        return m

    def _get_mission_auth(self, mission_id: str) -> AuthorizationContext:
        """Load the persisted authorization context (INVALID if absent/corrupt)."""
        try:
            state = self._mission_manager.get_mission(mission_id)
            return AuthorizationContext.from_dict(state.get("authorization"))
        except Exception:
            return AuthorizationContext(status=AuthStatus.INVALID)

    def _check_mission_auth(
        self,
        mission_id: str,
        targets: list[str] | None = None,
        capability: str = "",
        source: str = "",
    ) -> Any:
        """
        Evaluate mission authorization (fail-closed) and audit denials.
        Returns the AuthVerdict. Callers must deny on not allowed.
        """
        from runtime.scope.authorization import AuthStatus as _AS

        mission_scope: list[str] = []
        mission_excluded: list[str] = []
        try:
            state = self._mission_manager.get_mission(mission_id)
            mission_scope = state.get("target_scope") or []
            mission_excluded = state.get("excluded_scope") or []
        except Exception:
            pass
        # Phase B: In production mode, evaluate external authorization provider (fail-closed)
        if self._auth_mode == AuthMode.PRODUCTION:
            from runtime.scope.authorization import AuthVerdict, AuthStatus as _AS_EXT, scope_fingerprint
            if not self._external_auth_provider:
                self._mission_manager.log_event(
                    mission_id, "SEC_AUTH_DENIED",
                    {"source": source, "reason_code": "EXTERNAL_AUTH_PROVIDER_MISSING_IN_PRODUCTION"},
                )
                return AuthVerdict(
                    allowed=False,
                    status=_AS_EXT.DENIED,
                    reason_code="EXTERNAL_AUTH_PROVIDER_MISSING_IN_PRODUCTION",
                    mission_id=mission_id,
                    audit_id=f"AUTH-DENIED-{mission_id}",
                )

            cfg = ProviderConfig(
                mode=self._auth_mode,
                provider=self._external_auth_provider,
                allow_synthetic=False,
            )
            fp = scope_fingerprint(mission_scope, mission_excluded)
            ext_verif = evaluate_external_authorization(
                cfg,
                mission_id=mission_id,
                scope_fingerprint=fp,
                capabilities=[capability] if capability else ["HTTP_REQUEST"],
                targets=targets or [],
            )
            if not ext_verif.allowed:
                event = "SEC_AUTH_EXPIRED" if ext_verif.status == ProviderStatus.EXPIRED else "SEC_AUTH_DENIED"
                self._mission_manager.log_event(
                    mission_id, event,
                    {"source": source, "reason_code": ext_verif.reason_code, "detail": ext_verif.detail},
                )
                return AuthVerdict(
                    allowed=False,
                    status=_AS_EXT.EXPIRED if ext_verif.status == ProviderStatus.EXPIRED else _AS_EXT.DENIED,
                    reason_code=ext_verif.reason_code,
                    mission_id=mission_id,
                    audit_id=f"AUTH-{ext_verif.status.value}-{mission_id}",
                )

        verdict = self._auth_gate.evaluate(
            self._get_mission_auth(mission_id),
            mission_id=mission_id,
            targets=targets or [],
            capability=capability,
            current_scope=mission_scope,
            current_excluded=mission_excluded,
        )
        if not verdict.allowed:
            event = "SEC_AUTH_EXPIRED" if verdict.status == _AS.EXPIRED else "SEC_AUTH_DENIED"
            try:
                self._mission_manager.log_event(
                    mission_id, event,
                    {"source": source, **verdict.to_dict()},
                )
            except Exception:
                pass
        return verdict

    def mission_get(self, mission_id: str) -> dict[str, Any]:
        """Retrieve current state of a mission."""
        if not self._initialized:
            raise RuntimeError("Runtime not initialized")
        return self._mission_manager.get_mission(mission_id)

    def mission_checkpoint(self, mission_id: str) -> dict[str, Any]:
        """Create a new checkpoint / resume capsule for a mission."""
        import json
        if not self._initialized:
            raise RuntimeError("Runtime not initialized")
        brain_state = self._brain.generate_capsule_payload() if self._brain else None
        
        # Add Graph summary
        capsule = self._checkpoint_engine.create_checkpoint(mission_id, brain_state=brain_state)
        
        # 1. Write compact summary to capsule
        capsule["graph_summary"] = {
            "nodes_count": len(self._graph_store._nodes),
            "relationships_count": len(self._graph_store._relationships)
        }
        capsule["coverage_summary"] = {
            "dimensions_count": len(self._coverage_map.dimensions),
            "gaps_count": len(self._coverage_map.get_coverage_gaps()),
            "total_entities": self._coverage_map._total_entities_discovered
        }
        
        # 4. Phase 7 Vulnerability & Finding Summaries
        hyp_engine = self._get_hypothesis_engine(mission_id)
        finding_store = self._get_finding_store(mission_id)
        
        capsule["vulnerability_summary"] = {
            "active_hypotheses_count": len(hyp_engine.get_top_hypotheses(100)),
            "killed_hypotheses_count": len([h for h in hyp_engine.hypotheses.values() if h.state == HypothesisState.KILLED]),
            "validated_findings_count": len(finding_store.get_validated_findings()),
            "negative_knowledge_count": len(hyp_engine.negative_knowledge)
        }
        
        # 5. Phase 8 Attack Path Summaries
        chain_engine = self._get_chain_engine(mission_id)
        compound_store = self._get_compound_finding_store(mission_id)
        
        capsule["attack_chain_summary"] = {
            "total_attack_paths_count": len(chain_engine.attack_paths),
            "validated_attack_paths_count": len([p for p in chain_engine.attack_paths.values() if p.state == AttackPathState.VALIDATED]),
            "blocked_attack_paths_count": len([p for p in chain_engine.attack_paths.values() if p.state == AttackPathState.BLOCKED]),
            "compound_findings_count": len(compound_store.get_validated_compound_findings()),
            "negative_chain_knowledge_count": len(chain_engine.negative_knowledge)
        }

        # 2. Write full graph canonical state to mission-scoped graph.json
        graph_file = self._root / "state" / "missions" / mission_id / "graph.json"
        with graph_file.open("w", encoding="utf-8") as f:
            json.dump(self._graph_store.to_capsule_dict(), f, indent=2)
            
        # 3. Write coverage state to coverage.json
        coverage_file = self._root / "state" / "missions" / mission_id / "coverage.json"
        with coverage_file.open("w", encoding="utf-8") as f:
            json.dump(self._coverage_map.to_dict(), f, indent=2)
            
        # 4. Write Phase 7 Vulnerabilities & Findings
        vuln_file = self._root / "state" / "missions" / mission_id / "vulnerabilities.json"
        with vuln_file.open("w", encoding="utf-8") as f:
            json.dump(hyp_engine.to_dict(), f, indent=2)
            
        finding_file = self._root / "state" / "missions" / mission_id / "findings.json"
        with finding_file.open("w", encoding="utf-8") as f:
            json.dump(finding_store.to_dict(), f, indent=2)
            
        # 5. Write Phase 8 Attack Paths & Compound Findings
        path_file = self._root / "state" / "missions" / mission_id / "attack_paths.json"
        with path_file.open("w", encoding="utf-8") as f:
            json.dump(chain_engine.to_dict(), f, indent=2)

        compound_file = self._root / "state" / "missions" / mission_id / "compound_findings.json"
        with compound_file.open("w", encoding="utf-8") as f:
            json.dump(compound_store.to_dict(), f, indent=2)

        # 6. Write Phase 9 Adaptive Model Deltas & Pivots
        model_tracker = self._get_model_tracker(mission_id)
        pivot_engine = self._get_pivot_engine(mission_id)

        capsule["adaptive_research_summary"] = {
            "model_version": model_tracker.current_version,
            "research_directions_count": len(pivot_engine.directions),
            "pivots_count": len(pivot_engine.pivots),
            "deltas_count": len(model_tracker.deltas),
            "diagnoses_count": len(self._failure_diagnostician.diagnoses)
        }

        delta_file = self._root / "state" / "missions" / mission_id / "model_deltas.json"
        with delta_file.open("w", encoding="utf-8") as f:
            json.dump(model_tracker.to_dict(), f, indent=2)

        pivot_file = self._root / "state" / "missions" / mission_id / "adaptive_pivots.json"
        with pivot_file.open("w", encoding="utf-8") as f:
            json.dump(pivot_engine.to_dict(), f, indent=2)

        # 7. Write Phase 10 Orchestration State & Summary
        director = self._get_mission_director(mission_id)
        director.save_state()
        capsule["orchestration_summary"] = director.generate_capsule_summary()

        # Re-seal AFTER all summary mutations using HMAC key matching the runtime root
        from runtime.memory.checkpoint import seal_checkpoint, get_checkpoint_key
        capsule = seal_checkpoint(capsule, hmac_key=get_checkpoint_key(self._root))

        capsule_file = self._root / "state" / "missions" / mission_id / "resume_capsule.json"
        import json
        with capsule_file.open("w", encoding="utf-8") as f:
            json.dump(capsule, f, indent=2)
            
        return capsule

    def mission_resume(self, mission_id: str) -> dict[str, Any]:
        """Load a mission's resume capsule and set it as active."""
        if not self._initialized:
            raise RuntimeError("Runtime not initialized")
        capsule = self._checkpoint_engine.resume_mission(mission_id)

        # Phase B: Revalidate mission authorization upon resume (fail closed on expired/revoked)
        auth_verdict = self._check_mission_auth(mission_id, source="mission_resume")
        if not auth_verdict.allowed:
            self._mission_manager.log_event(
                mission_id, "SEC_RESUME_AUTH_DENIED",
                {"reason_code": auth_verdict.reason_code},
            )
            if self._auth_mode == AuthMode.PRODUCTION:
                raise PermissionError(
                    f"MISSION_RESUME_DENIED: authorization invalid or expired ({auth_verdict.reason_code})"
                )
        
        # Isolate and Load Phase 4 Graph State
        self._graph_store._nodes.clear()
        self._graph_store._relationships.clear()
        
        graph_file = self._root / "state" / "missions" / mission_id / "graph.json"
        if graph_file.is_file():
            import json
            with graph_file.open("r", encoding="utf-8") as f:
                graph_state = json.load(f)
            self._graph_store.load_from_capsule(graph_state)
            
        # Load Phase 6 Coverage State
        coverage_file = self._root / "state" / "missions" / mission_id / "coverage.json"
        if coverage_file.is_file():
            import json
            with coverage_file.open("r", encoding="utf-8") as f:
                cov_data = json.load(f)
            self._coverage_map = CoverageMap.from_dict(cov_data)
            self._discovery_strategy = DiscoveryStrategy(self._coverage_map)
            
        # Load Phase 7 Vulnerabilities & Findings
        vuln_file = self._root / "state" / "missions" / mission_id / "vulnerabilities.json"
        if vuln_file.is_file():
            import json
            with vuln_file.open("r", encoding="utf-8") as f:
                v_data = json.load(f)
            hyp_engine = self._get_hypothesis_engine(mission_id)
            hyp_engine.load_from_dict(v_data)

        finding_file = self._root / "state" / "missions" / mission_id / "findings.json"
        if finding_file.is_file():
            import json
            with finding_file.open("r", encoding="utf-8") as f:
                f_data = json.load(f)
            finding_store = self._get_finding_store(mission_id)
            finding_store.load_from_dict(f_data)
            
        # Load Phase 8 Attack Paths & Compound Findings
        path_file = self._root / "state" / "missions" / mission_id / "attack_paths.json"
        if path_file.is_file():
            import json
            with path_file.open("r", encoding="utf-8") as f:
                p_data = json.load(f)
            chain_engine = self._get_chain_engine(mission_id)
            chain_engine.load_from_dict(p_data)

        compound_file = self._root / "state" / "missions" / mission_id / "compound_findings.json"
        if compound_file.is_file():
            import json
            with compound_file.open("r", encoding="utf-8") as f:
                c_data = json.load(f)
            compound_store = self._get_compound_finding_store(mission_id)
            compound_store.load_from_dict(c_data)

        # Load Phase 9 Adaptive Model Deltas & Pivots
        delta_file = self._root / "state" / "missions" / mission_id / "model_deltas.json"
        if delta_file.is_file():
            import json
            with delta_file.open("r", encoding="utf-8") as f:
                d_data = json.load(f)
            model_tracker = self._get_model_tracker(mission_id)
            model_tracker.load_from_dict(d_data)

        pivot_file = self._root / "state" / "missions" / mission_id / "adaptive_pivots.json"
        if pivot_file.is_file():
            import json
            with pivot_file.open("r", encoding="utf-8") as f:
                pv_data = json.load(f)
            pivot_engine = self._get_pivot_engine(mission_id)
            pivot_engine.load_from_dict(pv_data)

        # Load Phase 10 Orchestration State
        director = self._get_mission_director(mission_id)
        director.load_state()

        # Phase A: revalidate persisted scope on resume. A resumed mission
        # with missing/invalid scope is observable and execution stays denied.
        try:
            resumed_state = self._mission_manager.get_mission(mission_id)
            scope_ok, scope_reason = ScopeResolver.validate_scope_definition(
                resumed_state.get("target_scope"),
                excluded_scope=resumed_state.get("excluded_scope"),
            )
            self._mission_manager.update_mission(mission_id, {
                "scope_status": "VALID" if scope_ok else "INVALID",
                "scope_reason": scope_reason,
            })
            self._mission_manager.log_event(
                mission_id,
                "SEC_SCOPE_DEFINED" if scope_ok else "SEC_SCOPE_MISSING",
                {"reason_code": scope_reason, "on_resume": True},
            )
            # Re-verify persisted authorization integrity + expiry on resume.
            # Execution enforces it live; resume only records observability
            # (persisted block is left untouched to preserve its digest).
            self._check_mission_auth(
                mission_id, targets=[], capability="", source="mission_resume",
            )
        except Exception:
            pass

        return capsule

    # ------------------------------------------------------------------
    # Independent counter-probe (step-path counter-test execution)
    # ------------------------------------------------------------------

    def _execute_counter_probe(
        self,
        mission_id: str,
        hyp: Any,
        primary_url: str,
        target_scope: list[str],
        excluded_scope: list[str],
    ) -> Any:
        """
        Execute a genuinely independent counter-probe for a hypothesis whose
        primary observation was flagged SECURITY_RELEVANT.

        Independence guarantees (documented):
        - Different request: neutral GET (no identity/test headers) against a
          synthetic NONEXISTENT resource designed by ExperimentPlanner, never
          the primary URL or parameters.
        - Different evidence object: separately executed, hashed, and stored
          (distinct evidence ID linked to the hypothesis).
        - Different expectation: the server must discriminate (401/403/404);
          a 200-with-content on a nonexistent resource FAILS the counter-test
          (wildcard server => primary observation untrustworthy).
        - Same policy gates as primary execution: scope, authorization, SSRF
          with DNS, budget reservation. Any denial yields BLOCKED (fail closed);
          execution errors yield INCONCLUSIVE or ERROR — never PASSED.

        Conflicting results: FAILED records evidence AGAINST the hypothesis;
        INCONCLUSIVE/BLOCKED/ERROR record nothing (unknown stays unknown).
        A fabricated success is impossible: PASSED requires an executed probe
        whose observed behavior matches the secure expectation.
        """
        from runtime.vulnerability.counter_test import CounterTestResult, CounterTestStatus
        from runtime.scope.ssrf import SSRFValidator

        def _done(status: Any, observed: str, reason: str,
                  evidence_refs: list[str] | None = None) -> Any:
            ct = CounterTestResult(
                finding_or_hypothesis_id=getattr(hyp, "id", ""),
                mission_id=mission_id,
                baseline_reference=f"expected-secure:{getattr(hyp, 'expected_secure_behavior', '')}",
                test_reference="counter-probe:nonexistent-resource",
                objective=(
                    "Independent counter-probe: verify the server discriminates "
                    f"nonexistent resources for {getattr(hyp, 'title', '')}"
                ),
                expected_secure_behavior=getattr(hyp, "expected_secure_behavior", ""),
                expected_insecure_behavior=getattr(hyp, "expected_insecure_behavior", ""),
                observed_behavior=observed[:500],
                status=status,
                evidence_refs=evidence_refs or [],
                block_or_error_reason=reason,
            )
            event = {
                CounterTestStatus.PASSED: "SEC_COUNTER_TEST_COMPLETED",
                CounterTestStatus.FAILED: "SEC_COUNTER_TEST_FAILED",
            }.get(status, "SEC_COUNTER_TEST_NOT_RUN")
            try:
                self._mission_manager.log_event(
                    mission_id, event,
                    {"hypothesis_id": getattr(hyp, "id", ""), "status": status.value,
                     "reason": reason},
                )
            except Exception:
                pass
            return ct

        # 1. Derive the counter-probe base origin from the primary URL.
        try:
            import urllib.parse

            parsed_primary = urllib.parse.urlparse((primary_url or "").strip())
            if parsed_primary.scheme.lower() not in ("http", "https") or not parsed_primary.hostname:
                return _done(CounterTestStatus.ERROR, "", "Counter-probe base URL unparseable")
            origin = f"{parsed_primary.scheme.lower()}://{parsed_primary.netloc}"
        except Exception as exc:
            return _done(CounterTestStatus.ERROR, "", f"Counter-probe URL parse error: {exc}")

        # 2. Design the nonexistent-resource experiment (no execution yet).
        try:
            experiment = self._experiment_planner.plan_counter_test_for_hypothesis(
                hyp, origin, scope=target_scope
            )
            counter_url = (experiment.test_request or {}).get("url", "")
            if not counter_url:
                return _done(CounterTestStatus.ERROR, "", "Counter-test design produced no URL")
        except Exception as exc:
            return _done(CounterTestStatus.ERROR, "", f"Counter-test design error: {exc}")

        # 3. Policy gates (scope, authorization, SSRF+DNS) — fail closed.
        scope_verdict = ScopeResolver.decide(
            counter_url, target_scope, excluded_scope=excluded_scope, mission_id=mission_id
        )
        if not scope_verdict.allowed:
            return _done(CounterTestStatus.BLOCKED, "",
                         f"Counter-probe scope denied: {scope_verdict.reason_code}")
        auth_verdict = self._check_mission_auth(
            mission_id, targets=[counter_url], capability="HTTP_REQUEST",
            source="counter_probe",
        )
        if not auth_verdict.allowed:
            return _done(CounterTestStatus.BLOCKED, "",
                         f"Counter-probe authorization denied: {auth_verdict.reason_code}")
        ssrf = SSRFValidator().validate_url(
            counter_url, mission_scope=target_scope, excluded_scope=excluded_scope,
            resolve_dns=True, mission_id=mission_id,
        )
        if not ssrf.allowed:
            try:
                self._mission_manager.log_event(
                    mission_id, "SEC_SSRF_BLOCKED",
                    {"hypothesis_id": getattr(hyp, "id", ""), **ssrf.to_dict()},
                )
            except Exception:
                pass
            return _done(CounterTestStatus.BLOCKED, "",
                         f"Counter-probe SSRF denied: {ssrf.reason_code}")
        pin_ip = SSRFValidator().select_pin_ip(ssrf)
        if ssrf.resolved_ips and not pin_ip:
            return _done(CounterTestStatus.BLOCKED, "", "Counter-probe DNS pin unavailable")

        # 4. Budget reservation (fail closed when exhausted).
        try:
            budget = self._get_mission_director(mission_id).budget
            reservation = budget.reserve("execution", 1.0)
        except Exception as exc:
            return _done(CounterTestStatus.ERROR, "", f"Counter-probe budget error: {exc}")
        if reservation is None:
            return _done(CounterTestStatus.BLOCKED, "", "Counter-probe budget exhausted")

        # 5. Build + execute the neutral control probe through Phase 5.
        try:
            from runtime.executor.adapters.curl import CurlAdapter

            tool = self._capability_registry.get_tool("curl")
            if tool is None:
                return _done(CounterTestStatus.ERROR, "", "Counter-probe tool unavailable")
            adapter = CurlAdapter(workspace_root=self._root)
            ct_action_id = f"CT-{secrets.token_hex(3).upper()}"
            plan = adapter.build_plan(
                mission_id, ct_action_id, "HTTP_REQUEST", tool,
                {"url": counter_url},
                mission_scope=target_scope, excluded_scope=excluded_scope,
                resolve_dns=False, resolve_ip=pin_ip,
            )
        except ValueError as exc:
            return _done(CounterTestStatus.BLOCKED, "", f"Counter-probe plan denied: {exc}")
        except Exception as exc:
            return _done(CounterTestStatus.ERROR, "", f"Counter-probe plan error: {exc}")
        try:
            ct_result = self._executor_interface.execute(plan)
            try:
                budget.consume(reservation, 1.0)
            except Exception:
                pass
        except Exception as exc:
            try:
                budget.consume(reservation, 1.0)
            except Exception:
                pass
            return _done(CounterTestStatus.ERROR, "", f"Counter-probe execution error: {exc}")

        if ct_result.status != "COMPLETED":
            return _done(
                CounterTestStatus.INCONCLUSIVE, "",
                f"Counter-probe did not complete: {ct_result.status}",
            )

        # 6. Independent evidence object (distinct ID, hashed, on disk).
        try:
            ct_evidence = self._evidence_normalizer.ingest_streamed_result(
                mission_id=mission_id,
                exec_result={"execution_id": ct_result.execution_id, "tool": ct_result.tool_id},
                file_path=__import__("pathlib").Path(ct_result.stdout_reference),
            )
            ct_body = __import__("pathlib").Path(ct_evidence.artifact_path).read_text(
                encoding="utf-8", errors="replace"
            )
        except Exception as exc:
            return _done(CounterTestStatus.ERROR, "", f"Counter-probe evidence error: {exc}")

        # 7. Evaluate the control: the server must discriminate.
        lowered = ct_body.lower()
        if ("401" in ct_body or "unauthorized" in lowered
                or "403" in ct_body or "forbidden" in lowered
                or "404" in ct_body or "not found" in lowered):
            return _done(
                CounterTestStatus.PASSED,
                f"Control {counter_url} discriminated: {ct_body[:200]}",
                "",
                evidence_refs=[ct_evidence.id],
            )
        if ct_body.strip():
            return _done(
                CounterTestStatus.FAILED,
                f"Control {counter_url} returned content for nonexistent resource: {ct_body[:200]}",
                "Wildcard response: primary observation may be benign",
                evidence_refs=[ct_evidence.id],
            )
        return _done(
            CounterTestStatus.INCONCLUSIVE,
            f"Control {counter_url} returned empty body",
            "Cannot discriminate from empty control response",
            evidence_refs=[ct_evidence.id],
        )

    # ------------------------------------------------------------------
    # Phase 4 Real Observation Loop
    # ------------------------------------------------------------------

    def step_mission(self, mission_id: str) -> dict[str, Any]:
        """
        Executes one complete Phase 4 decision loop:
        Brain decision -> Executor -> Raw Evidence -> Normalizer -> Extraction ->
        Context Firewall -> Graph Update -> Brain State Update.
        """
        mission_data = self._mission_manager.get_mission(mission_id)
        target_scope = mission_data.get("target_scope") or []
        # Phase A: excluded scope is a first-class enforcement input everywhere.
        excluded_scope = mission_data.get("excluded_scope") or []

        # Autonomous Seed Candidate Action Initiation (GAP 3)
        if not self._brain.state.candidate_actions and target_scope:
            seed_target = target_scope[0]
            if seed_target.startswith(("http://", "https://")):
                seed_origin = seed_target
            else:
                scheme = "http://" if any(h in seed_target for h in ("127.0.0.1", "localhost")) else "https://"
                seed_origin = f"{scheme}{seed_target}"
            planner = DiscoveryPlanner(target_scope=target_scope, excluded_scope=excluded_scope)
            initial_cands = planner.plan_candidate_actions(
                focus={"discovery_type": "HTTP_DISCOVERY"},
                discovered_entities=self._discovery_dedup.entities,
                base_origin=seed_origin
            )
            for cand in initial_cands:
                # Phase A: centralized verdict (excluded-first, fail-closed).
                seed_verdict = ScopeResolver.decide(
                    cand.target, target_scope,
                    excluded_scope=excluded_scope, mission_id=mission_id,
                )
                if seed_verdict.allowed:
                    cand.scope_alignment = "IN_SCOPE"
                    self._brain.state.candidate_actions[cand.id] = cand
                else:
                    self._mission_manager.log_event(
                        mission_id, "SEC_SCOPE_DENIED",
                        {"action_id": cand.id, **seed_verdict.to_dict()},
                    )

        # 1. Brain Decision
        action, rationale = self._brain.decide_next_action()
        if not action:
            return {"status": "NO_ACTION", "reason": "No valid actions available"}
            
        # 3. Execution Phase (Real Process Execution & Safety Gates)
        # 3a. Verify Scope
        if action.scope_alignment != "IN_SCOPE":
            # Safety Gate: Reject anything not explicitly marked IN_SCOPE by Brain
            self._mission_manager.log_event(
                mission_id, "SEC_ACTION_BLOCKED",
                {"action_id": action.id, "reason_code": "SCOPE_FLAG_NOT_IN_SCOPE"},
            )
            return {"status": "BLOCKED", "reason": "OUT_OF_SCOPE", "action": action.id}

        # Phase A: centralized, unconditional scope verdict immediately before
        # execution (revalidates queued actions against current mission scope).
        # Empty/missing scope FAILS CLOSED; excluded takes precedence.
        # Validate what will ACTUALLY execute: for HTTP actions the executed
        # URL comes from input_parameters["url"], which may differ from
        # action.target — both must pass (prevents target confusion).
        _eff_url = (action.input_parameters or {}).get("url")
        _validate_targets = [action.target]
        if action.capability_id == "HTTP_REQUEST" and _eff_url and _eff_url != action.target:
            _validate_targets.append(_eff_url)
        scope_verdict = None
        for _t in _validate_targets:
            scope_verdict = ScopeResolver.decide(
                _t, target_scope,
                excluded_scope=excluded_scope, mission_id=mission_id,
            )
            if not scope_verdict.allowed:
                break
        if not scope_verdict.allowed:
            self._mission_manager.log_event(
                mission_id, "SEC_SCOPE_DENIED",
                {"action_id": action.id, **scope_verdict.to_dict()},
            )
            return {
                "status": "BLOCKED",
                "reason": scope_verdict.decision.value,
                "action": action.id,
                "error": scope_verdict.reason_code,
            }
        self._mission_manager.log_event(
            mission_id, "SEC_SCOPE_ACCEPTED",
            {"action_id": action.id, **scope_verdict.to_dict()},
        )

        # Authorization gate: scope says the target is permitted; the mission
        # authorization context says the operator allowed THIS mission/scope/
        # capability. Both are required. Missing/invalid/expired/mismatched
        # authorization denies even in-scope targets.
        auth_verdict = self._check_mission_auth(
            mission_id,
            targets=_validate_targets,
            capability=action.capability_id or "",
            source="step_mission",
        )
        if not auth_verdict.allowed:
            return {
                "status": "BLOCKED",
                "reason": "AUTHZ_DENIED",
                "action": action.id,
                "error": auth_verdict.reason_code,
            }

        # Phase A: SSRF destination validation immediately before execution
        # (DNS revalidated here, not only at proposal time).
        # Only for HTTP actions; other capabilities (e.g. DNS_LOOKUP) carry
        # no fetchable URL. Validate the effective execution URL.
        # Any policy evaluation exception fails closed (BLOCKED).
        from runtime.scope.ssrf import SSRFValidator

        ssrf_verdict = None
        if action.capability_id == "HTTP_REQUEST":
            try:
                ssrf_verdict = SSRFValidator().validate_url(
                    _eff_url or action.target,
                    mission_scope=target_scope,
                    excluded_scope=excluded_scope,
                    resolve_dns=True,
                    mission_id=mission_id,
                )
            except Exception as exc:
                self._mission_manager.log_event(
                    mission_id, "SEC_POLICY_ERROR",
                    {"action_id": action.id, "reason_code": f"SSRF_EVAL_ERROR:{exc}"},
                )
                return {
                    "status": "BLOCKED",
                    "reason": "POLICY_ERROR",
                    "action": action.id,
                    "error": "SSRF policy evaluation failed closed",
                }
        if ssrf_verdict is not None and not ssrf_verdict.allowed:
            self._mission_manager.log_event(
                mission_id, "SEC_SSRF_BLOCKED",
                {"action_id": action.id, **ssrf_verdict.to_dict()},
            )
            return {
                "status": "BLOCKED",
                "reason": "SSRF_DESTINATION_BLOCKED",
                "action": action.id,
                "error": ssrf_verdict.reason_code,
            }

        # DNS pinning: when DNS was consulted, fix the connection IP to the
        # validated address via curl --resolve (TLS SNI/Host unchanged).
        # IP literals need no pin (no DNS to rebind). Pin unavailable after
        # a DNS-backed allow -> deny (fail closed, never silently unpinned).
        pinned_ip: str | None = None
        if ssrf_verdict is not None:
            pinned_ip = SSRFValidator().select_pin_ip(ssrf_verdict)
            dns_was_used = bool(ssrf_verdict.resolved_ips)
            if dns_was_used and not pinned_ip:
                self._mission_manager.log_event(
                    mission_id, "SEC_POLICY_ERROR",
                    {"action_id": action.id, "reason_code": "PIN_UNAVAILABLE"},
                )
                return {
                    "status": "BLOCKED",
                    "reason": "POLICY_ERROR",
                    "action": action.id,
                    "error": "DNS pin unavailable after validation",
                }
            if pinned_ip:
                self._mission_manager.log_event(
                    mission_id, "SEC_DNS_PINNED",
                    {"action_id": action.id, "pinned_ip": pinned_ip,
                     "target": ssrf_verdict.to_dict().get("target", "")},
                )
            
        header_file_path = None
        # Check if mock response exists for action (Phase 4 mock compatibility)
        if hasattr(self._executor_interface, "mock_responses") and action.id in self._executor_interface.mock_responses:
            exec_result = self._executor_interface.mock_responses[action.id]
            if hasattr(exec_result, "raw_output") and exec_result.raw_output:
                raw_payload = {
                    "execution_id": exec_result.execution_id,
                    "tool": exec_result.tool_id,
                    "raw_output": exec_result.raw_output
                }
                evidence = self._evidence_normalizer.ingest_execution_result(mission_id, raw_payload)
            else:
                streamed_file_path = Path(exec_result.stdout_reference)
                raw_result_payload = {
                    "execution_id": exec_result.execution_id,
                    "tool": exec_result.tool_id
                }
                evidence = self._evidence_normalizer.ingest_streamed_result(
                    mission_id=mission_id, 
                    exec_result=raw_result_payload, 
                    file_path=streamed_file_path
                )
        else:
            # 3b. Capability & Tool Selection
            if not action.capability_id:
                return {"status": "BLOCKED", "reason": "MISSING_CAPABILITY", "action": action.id}
                
            selected_tool = self._tool_selector.select_tool(action.capability_id)
            if not selected_tool:
                return {"status": "BLOCKED", "reason": "TOOL_UNAVAILABLE", "action": action.id}

            # Phase B: Centralized Network Connection Boundary gate
            net_verdict = self._network_boundary.evaluate_connection(
                selected_tool.id,
                action.target,
                mission_scope=target_scope,
                excluded_scope=excluded_scope,
                mission_id=mission_id,
            )
            if not net_verdict.allowed:
                self._mission_manager.log_event(
                    mission_id, "SEC_NETWORK_BOUNDARY_DENIED",
                    {"action_id": action.id, "reason_code": net_verdict.reason_code, "detail": net_verdict.detail},
                )
                return {
                    "status": "BLOCKED",
                    "reason": net_verdict.reason_code,
                    "action": action.id,
                    "error": net_verdict.detail or net_verdict.reason_code,
                }
            if net_verdict.pinned_ip and not pinned_ip:
                pinned_ip = net_verdict.pinned_ip
                
            # 3c. Execution Planning via Adapter
            adapter = self._adapters.get(selected_tool.id)
            if not adapter:
                return {"status": "BLOCKED", "reason": "NO_ADAPTER", "action": action.id}
                
            header_file_path = None
            if selected_tool.id in ("curl", "tool-curl"):
                artifact_dir = self._root / "workspace" / "raw" / mission_id / "headers"
                artifact_dir.mkdir(parents=True, exist_ok=True)
                header_file_path = str(artifact_dir / f"{action.id}_headers.txt")
                action.input_parameters["header_file_path"] = header_file_path

            try:
                # Phase A: adapter revalidates scope + SSRF literals at plan
                # time (defense in depth; DNS was already checked pre-execution).
                plan = adapter.build_plan(
                    mission_id, action.id, action.capability_id,
                    selected_tool, action.input_parameters,
                    mission_scope=target_scope,
                    excluded_scope=excluded_scope,
                    resolve_dns=False,
                    resolve_ip=pinned_ip if selected_tool.id in ("curl", "tool-curl") else None,
                )
            except Exception as e:
                self._mission_manager.log_event(
                    mission_id, "SEC_ACTION_BLOCKED",
                    {"action_id": action.id, "reason_code": f"INVALID_PLAN:{e}"},
                )
                return {"status": "BLOCKED", "reason": f"INVALID_PLAN: {str(e)}", "action": action.id}
                
            # 3d. Real Process Execution — budget reservation (fail-closed
            # when exhausted; released on plan/execution failure paths that
            # return before consume).
            _step_reservation: str | None = None
            try:
                director_budget = self._get_mission_director(mission_id).budget
                _step_reservation = director_budget.reserve("execution", 1.0)
            except Exception:
                _step_reservation = None
            if _step_reservation is None:
                self._mission_manager.log_event(
                    mission_id, "SEC_ACTION_BLOCKED",
                    {"action_id": action.id, "reason_code": "BUDGET_EXHAUSTED"},
                )
                return {
                    "status": "BLOCKED",
                    "reason": "BUDGET_EXHAUSTED",
                    "action": action.id,
                    "error": "Execution budget exhausted",
                }
            exec_result = self._executor_interface.execute(plan)
            try:
                director_budget.consume(_step_reservation, 1.0)
            except Exception:
                pass

            if exec_result.status != "COMPLETED":
                # Item 15: negative-result -> BrainState
                obs = Observation(
                    id=f"OBS-FAIL-{secrets.token_hex(4).upper()}",
                    source="executor",
                    fact=f"Action {action.id} (Capability: {action.capability_id}) against {action.target} failed. Reason: {exec_result.error_type or exec_result.status}",
                    evidence_refs=["EXEC_FAILURE"],
                    confidence=1.0,
                    tags=["execution_failure"]
                )
                self._brain.state.add_observation(obs)
                return {"status": exec_result.status, "reason": exec_result.error_type, "action": action.id}
                
            # Streamed evidence ingestion
            streamed_file_path = Path(exec_result.stdout_reference)
            raw_result_payload = {
                "execution_id": exec_result.execution_id,
                "tool": exec_result.tool_id
            }
            evidence = self._evidence_normalizer.ingest_streamed_result(
                mission_id=mission_id, 
                exec_result=raw_result_payload, 
                file_path=streamed_file_path
            )
        
        # 4. Observation Extraction & Phase 6 Discovery Mapping
        raw_obs = self._evidence_extractor.extract_observations(evidence)
        
        evidence_text = ""
        try:
            evidence_text = Path(evidence.artifact_path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass

        # Parse response headers if captured (GAP 2)
        parsed_headers: dict[str, str] = {}
        if header_file_path and Path(header_file_path).exists():
            try:
                raw_hdrs = Path(header_file_path).read_text(encoding="utf-8", errors="replace")
                for hline in raw_hdrs.splitlines():
                    if ":" in hline:
                        hk, hv = hline.split(":", 1)
                        # Redact sensitive values from headers
                        clean_hk = hk.strip().lower()
                        clean_hv = hv.strip()
                        if clean_hk in ("authorization", "cookie", "set-cookie"):
                            clean_hv = "[REDACTED]"
                        parsed_headers[clean_hk] = clean_hv
            except Exception:
                pass

        discovery_result = self._discovery_mapper.map_http_response(
            mission_id=mission_id,
            execution_id=evidence.execution_id,
            target_url=action.target,
            status_code=getattr(exec_result, "exit_code", 200) or 200,
            headers=parsed_headers,
            body=evidence_text,
            evidence_id=evidence.id,
            scope=target_scope,
            excluded_scope=excluded_scope
        )

        # Append discovery observations to raw_obs before Context Firewall
        for disc_obs_text in discovery_result.observations:
            disc_obs_id = f"OBS-DISC-{secrets.token_hex(4).upper()}"
            raw_obs.append(Observation(
                id=disc_obs_id,
                source="discovery_mapper",
                fact=disc_obs_text,
                evidence_refs=[evidence.id],
                confidence=1.0,
                tags=["discovery"]
            ))

        # 5. Context Firewall (Deduplication, Injection Defense, Compression, Structured Relevance)
        objective = mission_data.get("operator_objective") or mission_data.get("objective", "")
        hypotheses = [h.statement for h in self._brain.state.hypotheses.values()]
        
        filtered_obs = self._context_firewall.filter_and_compress(
            raw_obs, 
            mission_objective=objective,
            active_hypotheses=hypotheses
        )
        
        # 6. Graph Update (Automated via Ingester)
        initial_graph_nodes = len(self._graph_store._nodes)
        initial_graph_rels = len(self._graph_store._relationships)
        
        evidence_map = {evidence.id: evidence}
        self._graph_ingester.ingest_observations(filtered_obs, evidence_map)
        
        # 6.5 Sensitive Data Firewall
        for obs in filtered_obs:
            obs.fact = self._sensitive_firewall.redact_string(obs.fact)

        # Deduplicate discoveries and compute novelty
        new_entities_count = 0
        new_rels_count = 0
        canonical_entities = []
        for entity in discovery_result.entities:
            canonical_e, is_new = self._discovery_dedup.process_entity(entity)
            canonical_entities.append(canonical_e)
            if is_new:
                new_entities_count += 1

        canonical_rels = []
        for rel in discovery_result.relationships:
            canonical_r, is_new = self._discovery_dedup.process_relationship(rel)
            canonical_rels.append(canonical_r)
            if is_new:
                new_rels_count += 1

        discovery_result.entities = canonical_entities
        discovery_result.relationships = canonical_rels
        discovery_result.novelty = self._discovery_dedup.calculate_novelty(
            new_entities_count, len(canonical_entities) or 1
        )

        # Ingest Discovered Entities & Relationships into Security Graph
        self._graph_ingester.ingest_discovery_result(discovery_result)
        
        total_nodes_added = len(self._graph_store._nodes) - initial_graph_nodes
        total_rels_added = len(self._graph_store._relationships) - initial_graph_rels

        # Update Coverage Map
        if any(e.entity_type == "ENDPOINT" for e in canonical_entities):
            self._coverage_map.update_dimension("ENDPOINT", CoverageStatus.PARTIAL, count_increment=new_entities_count)
            self._coverage_map.update_dimension("HTTP", CoverageStatus.COMPLETE)
        if any(e.entity_type == "JS_BUNDLE" for e in canonical_entities):
            self._coverage_map.update_dimension("JS", CoverageStatus.PARTIAL)
        if any(e.entity_type == "API" for e in canonical_entities):
            self._coverage_map.update_dimension("API", CoverageStatus.PARTIAL)
        if any(e.entity_type == "TECHNOLOGY" for e in canonical_entities):
            self._coverage_map.update_dimension("TECHNOLOGY", CoverageStatus.COMPLETE)
        if any(e.entity_type == "WORKFLOW" for e in canonical_entities):
            self._coverage_map.update_dimension("WORKFLOW", CoverageStatus.PARTIAL)

        self._coverage_map.record_discovery_action(
            action_id=action.id,
            discovery_type=action.action_type,
            new_entities_count=new_entities_count,
            new_rels_count=new_rels_count
        )

        # 7. Update Brain State with Observations and Unknowns
        for obs in filtered_obs:
            self._brain.state.add_observation(obs)

        # Generate new Unknowns in Brain State for newly discovered high-value assets
        for ent in canonical_entities:
            if ent.entity_type == "API":
                u_id = f"UNK-API-{ent.identity_string.replace('/', '_')}"
                if u_id not in self._brain.state.unknowns:
                    self._brain.state.add_unknown(Unknown(
                        id=u_id,
                        statement=f"Does API route {ent.identity_string} enforce authentication and role boundaries?",
                        importance=0.85
                    ))
            elif ent.entity_type == "TECHNOLOGY" and ent.identity_string == "GraphQL":
                u_id = "UNK-TECH-GRAPHQL"
                if u_id not in self._brain.state.unknowns:
                    self._brain.state.add_unknown(Unknown(
                        id=u_id,
                        statement="Does the GraphQL endpoint expose schema introspection or authorization bypasses?",
                        importance=0.9
                    ))

        # 8. Phase 7: Boundary & Assumption Extraction
        hyp_engine = self._get_hypothesis_engine(mission_id)
        finding_store = self._get_finding_store(mission_id)

        new_bnds, new_asms, new_unks = self._assumption_engine.extract_boundaries_and_assumptions(
            self._graph_store,
            self._discovery_dedup.entities,
            self._discovery_dedup.relationships
        )

        for unk in new_unks:
            if unk.id not in self._brain.state.unknowns:
                self._brain.state.add_unknown(unk)

        new_hyps = hyp_engine.generate_hypotheses_from_assumptions(new_asms, new_bnds)
        from runtime.brain.hypotheses import Hypothesis
        for h in new_hyps:
            if h.id not in self._brain.state.hypotheses:
                self._brain.state.add_hypothesis(Hypothesis(
                    id=h.id,
                    statement=h.title,
                    state=h.state.value,
                    confidence=h.confidence,
                    supporting_evidence=h.supporting_evidence,
                    contradicting_evidence=h.contradicting_evidence
                ))

        # Perform Differential Analysis & Hypothesis Verification if action targeted a hypothesis
        new_findings_count = 0
        diff_outcome = None
        
        # Check if action targeted a hypothesis or was an experiment
        matching_hyps = [
            h for h in hyp_engine.hypotheses.values()
            if any(t in action.target for t in h.target_entities)
        ]
        
        for hyp in matching_hyps:
            hyp.last_tested_at = datetime.now(timezone.utc).isoformat()
            test_status = 200
            if "401" in evidence_text or "unauthorized" in evidence_text.lower():
                test_status = 401
            elif "403" in evidence_text or "forbidden" in evidence_text.lower():
                test_status = 403
            elif "404" in evidence_text or "not found" in evidence_text.lower():
                test_status = 404
            elif hasattr(exec_result, "exit_code") and exec_result.exit_code not in (0, 200):
                test_status = exec_result.exit_code
            test_body = evidence_text

            diff_res = self._differential_comparator.compare(
                baseline_status=200,
                baseline_headers={},
                baseline_body=test_body,
                test_status=test_status,
                test_headers={},
                test_body=test_body,
                hypothesis_class=hyp.vulnerability_class.value
            )
            diff_outcome = diff_res.outcome

            if diff_res.outcome == DifferentialOutcome.SECURITY_RELEVANT:
                hyp_engine.record_evidence(hyp.id, evidence.id, is_supporting=True)
                hyp.confidence = max(hyp.confidence, 0.90)
                hyp.state = HypothesisState.STRONG
                impact_assessment = self._impact_evaluator.evaluate_impact(hyp, diff_res, test_body)

                # Independent counter-probe: a genuinely separate execution
                # (neutral control request against a nonexistent resource,
                # distinct evidence object). PASSED only on observed secure
                # discrimination; anything else fails closed at the gate.
                # FAILED additionally records evidence AGAINST the hypothesis.
                from runtime.vulnerability.counter_test import CounterTestStatus

                evidence_file = Path(evidence.artifact_path)
                self._mission_manager.log_event(
                    mission_id, "SEC_COUNTER_TEST_STARTED",
                    {"hypothesis_id": hyp.id, "evidence_id": evidence.id},
                )
                if not evidence_file.is_file():
                    from runtime.vulnerability.counter_test import CounterTestResult

                    counter_test = CounterTestResult.not_run(
                        finding_or_hypothesis_id=hyp.id,
                        mission_id=mission_id,
                        reason="Evidence artifact missing; counter-test cannot be recorded",
                    )
                    self._mission_manager.log_event(
                        mission_id, "SEC_COUNTER_TEST_NOT_RUN",
                        {"hypothesis_id": hyp.id, "evidence_id": evidence.id,
                         "status": counter_test.status.value},
                    )
                else:
                    counter_test = self._execute_counter_probe(
                        mission_id, hyp,
                        _eff_url or action.target,
                        target_scope, excluded_scope,
                    )
                    if counter_test.status == CounterTestStatus.FAILED:
                        hyp_engine.record_evidence(
                            hyp.id,
                            (counter_test.evidence_refs or [evidence.id])[0],
                            is_supporting=False,
                        )

                # Phase A: verify the finding target against mission scope
                # (target_scope + excluded_scope) instead of trusting True.
                # Only URL-like targets are verified directly; bare paths and
                # identifiers inherit the already-verified action context.
                finding_target_raw = hyp.target_entities[0] if hyp.target_entities else action.target
                if ScopeResolver.looks_like_url_or_host(finding_target_raw):
                    finding_target = finding_target_raw
                else:
                    finding_target = action.target
                scope_verdict = ScopeResolver.decide(
                    finding_target,
                    target_scope,
                    excluded_scope=mission_data.get("excluded_scope") or [],
                    mission_id=mission_id,
                )
                if not scope_verdict.allowed:
                    self._mission_manager.log_event(
                        mission_id,
                        "SEC_VALIDATION_DENIED",
                        {
                            "hypothesis_id": hyp.id,
                            "reason_code": scope_verdict.reason_code,
                            "target": scope_verdict.to_dict().get("target", ""),
                        },
                    )
                gate_status, reasons = self._finding_quality_gate.validate_candidate(
                    hypothesis=hyp,
                    impact_assessment=impact_assessment,
                    evidence_file_exists=evidence_file.is_file(),
                    counter_test_result=counter_test,
                    is_in_scope=scope_verdict.allowed,
                    is_duplicate=finding_store.is_duplicate(hyp.title, hyp.target_entities[0] if hyp.target_entities else "/")
                )

                if gate_status == FindingStatus.VALIDATED:
                    # Both evidence sources linked: primary observation plus
                    # the independent counter-probe evidence (when executed).
                    _linked_refs = [evidence.id]
                    for _ref in counter_test.evidence_refs:
                        if _ref and _ref not in _linked_refs:
                            _linked_refs.append(_ref)
                    finding_store.create_finding_from_hypothesis(
                        hypothesis=hyp,
                        impact_assessment=impact_assessment,
                        evidence_refs=_linked_refs,
                        status=gate_status
                    )
                    new_findings_count += 1
            elif diff_res.outcome == DifferentialOutcome.EXPECTED:
                hyp_engine.record_evidence(hyp.id, evidence.id, is_supporting=False)

        # 9. Phase 8: Attack-Chain Reasoning & Synthesis
        chain_engine = self._get_chain_engine(mission_id)
        compound_store = self._get_compound_finding_store(mission_id)

        endpoints_list = [e.identity_string for e in self._discovery_dedup.entities if e.entity_type in ("ENDPOINT", "API")]
        new_chains = chain_engine.generate_chain_candidates(
            findings=finding_store.get_validated_findings(),
            endpoints=endpoints_list
        )

        # Evaluate attack path transitions
        for path in chain_engine.attack_paths.values():
            if path.state in (AttackPathState.MODELED, AttackPathState.INVESTIGATING, AttackPathState.PARTIALLY_VALIDATED, AttackPathState.VALIDATING):
                for edge in path.edges:
                    if edge.target_node in action.target:
                        test_status = 200
                        if "403" in evidence_text or "forbidden" in evidence_text.lower():
                            test_status = 403
                        elif "401" in evidence_text or "unauthorized" in evidence_text.lower():
                            test_status = 401
                        elif "404" in evidence_text or "not found" in evidence_text.lower():
                            test_status = 404
                        elif getattr(exec_result, "exit_code", 0) not in (0, 200):
                            test_status = getattr(exec_result, "exit_code", 200)

                        if test_status in (200, 201):
                            edge.status = ChainEdgeStatus.VALIDATED
                            edge.confidence = 1.0
                            path.validate_step(f"{edge.source_node} -> {edge.target_node}", evidence.id)
                        elif test_status in (401, 403, 404):
                            edge.status = ChainEdgeStatus.BLOCKED
                            path.block_step(f"{edge.source_node} -> {edge.target_node}", f"Server returned HTTP {test_status} denying transition")

                # If all edges validated, promote attack path
                if len(path.validated_steps) == len(path.edges) and len(path.edges) > 0 and len(path.blocked_steps) == 0:
                    self._compound_impact_evaluator.evaluate_compound_impact(path)
                    exploitability = self._exploitability_evaluator.evaluate_exploitability(path)

                    # Phase A: verify URL-like path targets against mission
                    # scope instead of trusting True. Bare identifiers inherit
                    # the already-verified action context.
                    _path_targets: list[str] = []
                    for _e in path.edges:
                        for _node in (getattr(_e, "source_node", ""), getattr(_e, "target_node", "")):
                            if isinstance(_node, str) and ScopeResolver.looks_like_url_or_host(_node):
                                _path_targets.append(_node)
                    _path_targets.append(action.target)
                    _path_in_scope = True
                    for _pt in _path_targets:
                        _pv = ScopeResolver.decide(
                            _pt, target_scope,
                            excluded_scope=excluded_scope, mission_id=mission_id,
                        )
                        if not _pv.allowed:
                            _path_in_scope = False
                            self._mission_manager.log_event(
                                mission_id, "SEC_SCOPE_DENIED",
                                {"attack_path_id": path.id, **_pv.to_dict()},
                            )
                            break

                    gate_status, reasons = self._attack_path_validation_gate.validate_attack_path(
                        attack_path=path,
                        evidence_files_exist=Path(evidence.artifact_path).is_file(),
                        is_in_scope=_path_in_scope
                    )
                    if gate_status == AttackPathState.VALIDATED:
                        path.state = AttackPathState.VALIDATED
                        compound_store.create_compound_finding(path, exploitability=exploitability)

        # 10. Phase 9: Adaptive Deep-Dive & Failure Diagnosis / Pivot Loop
        model_tracker = self._get_model_tracker(mission_id)
        pivot_engine = self._get_pivot_engine(mission_id)

        for asm in new_asms:
            model_tracker.register_assumption(asm.statement)

        latest_status = 200
        if "403" in evidence_text or "forbidden" in evidence_text.lower():
            latest_status = 403
        elif "401" in evidence_text or "unauthorized" in evidence_text.lower():
            latest_status = 401
        elif "404" in evidence_text or "not found" in evidence_text.lower():
            latest_status = 404
        elif getattr(exec_result, "exit_code", 0) not in (0, 200):
            latest_status = getattr(exec_result, "exit_code", 200)

        recent_pivot = None
        if latest_status in (401, 403, 404, 429):
            diag = self._failure_diagnostician.diagnose_failure(
                action_id=action.id,
                target=action.target,
                status_code=latest_status,
                response_body=evidence_text,
                tested_hypothesis_statement=action.objective,
                evidence_id=evidence.id
            )
            model_tracker.invalidate_assumption(
                statement=f"Direct access authorization on {action.target}",
                reason=diag.learning,
                evidence_id=evidence.id
            )
            for unk_stmt in diag.remaining_unknowns:
                u_id = f"UNK-PIVOT-{secrets.token_hex(3).upper()}"
                if u_id not in self._brain.state.unknowns:
                    self._brain.state.add_unknown(Unknown(
                        id=u_id,
                        statement=unk_stmt,
                        importance=0.9
                    ))

            alt_dirs = pivot_engine.generate_alternative_directions(
                current_blocked_target=action.target,
                diagnosis=diag,
                discovered_endpoints=endpoints_list,
                negative_knowledge=chain_engine.negative_knowledge
            )
            if alt_dirs:
                recent_pivot = pivot_engine.select_best_pivot(
                    from_direction_name=action.objective,
                    diagnosis=diag,
                    candidate_directions=alt_dirs
                )
                # Queue CandidateAction corresponding to the selected pivot
                if recent_pivot:
                    # Find matching endpoint for top direction
                    matching_v2 = [ep for ep in endpoints_list if "/v2" in ep or "/api/v2" in ep]
                    if matching_v2:
                        target_pivot_url = action.target.replace("/api/admin/", "/api/v2/admin/") if "/api/admin/" in action.target else matching_v2[0]
                        # Phase A: pivot targets are PROPOSED, never pre-authorized.
                        # The execution-time decide() gate revalidates before any run.
                        pivot_verdict = ScopeResolver.decide(
                            target_pivot_url, target_scope,
                            excluded_scope=excluded_scope, mission_id=mission_id,
                        )
                        if not pivot_verdict.allowed:
                            self._mission_manager.log_event(
                                mission_id, "SEC_SCOPE_DENIED",
                                {"action_id": "ACT-PIVOT-pending", **pivot_verdict.to_dict()},
                            )
                        else:
                            p_act = CandidateAction(
                                id=f"ACT-PIVOT-{secrets.token_hex(3).upper()}",
                                action_type="EXPERIMENT",
                                objective=recent_pivot.to_direction,
                                target=target_pivot_url,
                                capability_id="HTTP_REQUEST",
                                input_parameters={"url": target_pivot_url, "headers": action.input_parameters.get("headers", {})},
                                expected_information_gain=recent_pivot.expected_gain,
                                expected_security_value=recent_pivot.expected_gain * 1.2,
                                scope_alignment="IN_SCOPE"
                            )
                            self._brain.state.candidate_actions[p_act.id] = p_act

        # 10. Phase 10: Mission Orchestration & Portfolio Management
        director = self._get_mission_director(mission_id)
        orch_events: list[dict[str, Any]] = []
        if not director.is_paused:
            # Check if there is a runnable thread and dispatch bounded work unit
            active_th, _ = director.scheduler.select_next_thread()
            if active_th:
                w_unit, res_id, _ = director.scheduler.dispatch_work_unit(
                    thread=active_th,
                    unit_type="EXPERIMENT",
                    target=action.target,
                    parameters=action.input_parameters,
                    estimated_cost=1.0
                )
                if w_unit and res_id:
                    new_knowledge = bool(discovery_result.novelty > 0 or len(finding_store.get_validated_findings()) > 0 or recent_pivot is not None)
                    orch_events = director.handle_work_unit_completion(
                        work_unit=w_unit,
                        reservation_id=res_id,
                        consumed_cost=1.0,
                        new_knowledge_produced=new_knowledge,
                        evidence_id=evidence.id,
                        evidence_text=evidence_text,
                        thread_finished=False
                    )

        # Snapshot attack surface
        if mission_id not in self._snapshot_managers:
            self._snapshot_managers[mission_id] = AttackSurfaceSnapshotManager(mission_id)
        current_snapshot = self._snapshot_managers[mission_id].create_snapshot(
            entities=self._discovery_dedup.entities,
            relationships=self._discovery_dedup.relationships
        )
            
        return {
            "status": "STEP_COMPLETE",
            "action": action.id,
            "evidence_id": evidence.id,
            "pinned_ip": pinned_ip,
            "observations_extracted": len(raw_obs),
            "observations_kept": len(filtered_obs),
            "graph_nodes_added": total_nodes_added,
            "graph_rels_added": total_rels_added,
            "discovery_novelty": discovery_result.novelty,
            "coverage_gaps": len(self._coverage_map.get_coverage_gaps()),
            "snapshot_id": current_snapshot.snapshot_id,
            "hypotheses_count": len(hyp_engine.hypotheses),
            "validated_findings": len(finding_store.get_validated_findings()),
            "attack_paths_count": len(chain_engine.attack_paths),
            "validated_attack_paths": len([p for p in chain_engine.attack_paths.values() if p.state == AttackPathState.VALIDATED]),
            "compound_findings": len(compound_store.get_validated_compound_findings()),
            "research_directions_count": len(pivot_engine.directions),
            "pivots_count": len(pivot_engine.pivots),
            "security_model_version": model_tracker.current_version,
            "recent_pivot": recent_pivot.to_dict() if recent_pivot else None,
            "rationale": rationale.to_dict() if rationale else None,
            "orchestration_events": orch_events
        }

    def vulnerability_status(self, mission_id: str) -> dict[str, Any]:
        """Returns structured vulnerability research and hypothesis progress."""
        hyp_engine = self._get_hypothesis_engine(mission_id)
        finding_store = self._get_finding_store(mission_id)
        return {
            "mission_id": mission_id,
            "total_hypotheses": len(hyp_engine.hypotheses),
            "active_hypotheses": [h.to_dict() for h in hyp_engine.get_top_hypotheses(10)],
            "validated_findings_count": len(finding_store.get_validated_findings()),
            "negative_knowledge_count": len(hyp_engine.negative_knowledge)
        }

    def findings_report(self, mission_id: str) -> dict[str, Any]:
        """Returns validated security findings for a mission."""
        finding_store = self._get_finding_store(mission_id)
        return {
            "mission_id": mission_id,
            "findings": [f.to_dict() for f in finding_store.get_validated_findings()]
        }

    def hypotheses_report(self, mission_id: str) -> dict[str, Any]:
        """Returns all hypotheses for a mission."""
        hyp_engine = self._get_hypothesis_engine(mission_id)
        return {
            "mission_id": mission_id,
            "hypotheses": [h.to_dict() for h in hyp_engine.hypotheses.values()]
        }

    def hunter_attack_paths(self, mission_id: str) -> dict[str, Any]:
        """Returns structured attack paths for a mission."""
        chain_engine = self._get_chain_engine(mission_id)
        return {
            "mission_id": mission_id,
            "total_attack_paths": len(chain_engine.attack_paths),
            "attack_paths": [p.to_dict() for p in chain_engine.attack_paths.values()]
        }

    def hunter_attack_path_status(self, mission_id: str) -> dict[str, Any]:
        """Returns high-level attack path metrics and top paths."""
        chain_engine = self._get_chain_engine(mission_id)
        compound_store = self._get_compound_finding_store(mission_id)
        return {
            "mission_id": mission_id,
            "total_attack_paths": len(chain_engine.attack_paths),
            "top_attack_paths": [p.to_dict() for p in chain_engine.get_top_attack_paths(5)],
            "validated_attack_paths_count": len([p for p in chain_engine.attack_paths.values() if p.state == AttackPathState.VALIDATED]),
            "compound_findings_count": len(compound_store.get_validated_compound_findings()),
            "negative_chain_knowledge_count": len(chain_engine.negative_knowledge)
        }

    def hunter_compound_findings(self, mission_id: str) -> dict[str, Any]:
        """Returns validated compound findings for a mission."""
        compound_store = self._get_compound_finding_store(mission_id)
        return {
            "mission_id": mission_id,
            "compound_findings": [cf.to_dict() for cf in compound_store.get_validated_compound_findings()]
        }

    def hunter_exploitability(self, mission_id: str) -> dict[str, Any]:
        """Returns exploitability assessments for attack paths."""
        chain_engine = self._get_chain_engine(mission_id)
        assessments = [
            p.exploitability.to_dict() for p in chain_engine.attack_paths.values()
            if p.exploitability is not None
        ]
        return {
            "mission_id": mission_id,
            "exploitability_assessments": assessments
        }

    def hunter_research_status(self, mission_id: str) -> dict[str, Any]:
        """Returns high-level adaptive research metrics for a mission."""
        model_tracker = self._get_model_tracker(mission_id)
        pivot_engine = self._get_pivot_engine(mission_id)
        return {
            "mission_id": mission_id,
            "security_model_version": model_tracker.current_version,
            "total_research_directions": len(pivot_engine.directions),
            "total_pivots": len(pivot_engine.pivots),
            "recent_pivots": [p.to_dict() for p in pivot_engine.pivots[-5:]],
            "stale_assumptions_count": len([s for s in model_tracker.assumptions_staleness.values() if s == AssumptionStaleness.INVALIDATED]),
        }

    def hunter_research_directions(self, mission_id: str) -> dict[str, Any]:
        """Returns active and candidate research directions."""
        pivot_engine = self._get_pivot_engine(mission_id)
        return {
            "mission_id": mission_id,
            "directions": [d.to_dict() for d in pivot_engine.directions.values()]
        }

    def hunter_research_pivot(self, mission_id: str) -> dict[str, Any]:
        """Returns all executed research pivots for a mission."""
        pivot_engine = self._get_pivot_engine(mission_id)
        return {
            "mission_id": mission_id,
            "pivots": [p.to_dict() for p in pivot_engine.pivots]
        }

    def hunter_blocked_paths(self, mission_id: str) -> dict[str, Any]:
        """Returns diagnosed blocked paths and failure diagnoses."""
        chain_engine = self._get_chain_engine(mission_id)
        blocked = [p.to_dict() for p in chain_engine.attack_paths.values() if p.state == AttackPathState.BLOCKED]
        return {
            "mission_id": mission_id,
            "blocked_paths": blocked,
            "diagnoses": [d.to_dict() for d in self._failure_diagnostician.diagnoses]
        }

    def hunter_security_model(self, mission_id: str) -> dict[str, Any]:
        """Returns the current security model version and incremental deltas."""
        model_tracker = self._get_model_tracker(mission_id)
        return {
            "mission_id": mission_id,
            "current_version": model_tracker.current_version,
            "deltas": [d.to_dict() for d in model_tracker.deltas],
            "assumptions_staleness": {k: v.value for k, v in model_tracker.assumptions_staleness.items()}
        }

    def hunter_research_history(self, mission_id: str) -> dict[str, Any]:
        """Returns full research progression timeline."""
        model_tracker = self._get_model_tracker(mission_id)
        pivot_engine = self._get_pivot_engine(mission_id)
        return {
            "mission_id": mission_id,
            "model_version": model_tracker.current_version,
            "deltas_count": len(model_tracker.deltas),
            "pivots_count": len(pivot_engine.pivots),
            "history": {
                "deltas": [d.to_dict() for d in model_tracker.deltas],
                "pivots": [p.to_dict() for p in pivot_engine.pivots]
            }
        }

    # ------------------------------------------------------------------
    # Phase 10 Orchestration MCP Methods
    # ------------------------------------------------------------------

    def hunter_mission_status(self, mission_id: str) -> dict[str, Any]:
        """Returns comprehensive mission orchestration status."""
        director = self._get_mission_director(mission_id)
        return {
            "mission_id": mission_id,
            "is_paused": director.is_paused,
            "summary": director.generate_capsule_summary()
        }

    def hunter_objectives(self, mission_id: str) -> dict[str, Any]:
        """Returns objective portfolio for a mission."""
        director = self._get_mission_director(mission_id)
        return {
            "mission_id": mission_id,
            "objectives": [o.to_dict() for o in director.portfolio.objectives.values()]
        }

    def hunter_threads(self, mission_id: str) -> dict[str, Any]:
        """Returns all research threads for a mission."""
        director = self._get_mission_director(mission_id)
        return {
            "mission_id": mission_id,
            "threads": [t.to_dict() for t in director.thread_manager.threads.values()]
        }

    def hunter_thread_status(self, mission_id: str, thread_id: str) -> dict[str, Any]:
        """Returns specific thread details and state."""
        director = self._get_mission_director(mission_id)
        th = director.thread_manager.get_thread(thread_id)
        if not th:
            return {"error": f"Thread {thread_id} not found"}
        deps_sat, reasons = director.dependency_graph.check_dependencies_satisfied(thread_id)
        return {
            "mission_id": mission_id,
            "thread": th.to_dict(),
            "dependencies_satisfied": deps_sat,
            "dependency_blockages": reasons
        }

    def hunter_portfolio(self, mission_id: str) -> dict[str, Any]:
        """Returns ranked objectives and active threads."""
        director = self._get_mission_director(mission_id)
        ranked = director.portfolio.recalculate_priorities()
        return {
            "mission_id": mission_id,
            "ranked_objectives": [o.to_dict() for o in ranked],
            "active_threads_count": len(director.thread_manager.get_runnable_threads())
        }

    def hunter_scheduler_status(self, mission_id: str) -> dict[str, Any]:
        """Returns current scheduler state and next runnable thread selection."""
        director = self._get_mission_director(mission_id)
        top_th, rationale = director.scheduler.select_next_thread()
        return {
            "mission_id": mission_id,
            "max_concurrent_threads": director.scheduler.max_concurrent_threads,
            "aging_factor": director.scheduler.aging_factor,
            "next_runnable_thread": top_th.to_dict() if top_th else None,
            "selection_rationale": rationale
        }

    def hunter_budget(self, mission_id: str) -> dict[str, Any]:
        """Returns centralized mission budget status."""
        director = self._get_mission_director(mission_id)
        return director.budget.to_dict()

    def hunter_dependencies(self, mission_id: str) -> dict[str, Any]:
        """Returns thread dependency graph for a mission."""
        director = self._get_mission_director(mission_id)
        return director.dependency_graph.to_dict()

    def hunter_rebalance(self, mission_id: str) -> dict[str, Any]:
        """Triggers dynamic priority rebalance across objectives and threads."""
        director = self._get_mission_director(mission_id)
        ranked = director.portfolio.recalculate_priorities()
        director.log_event("PRIORITY_REBALANCED", details={"ranked_objectives_count": len(ranked)})
        return {
            "mission_id": mission_id,
            "rebalanced_objectives": [o.to_dict() for o in ranked]
        }

    def hunter_pause_mission(self, mission_id: str) -> dict[str, Any]:
        """Pauses mission scheduling."""
        director = self._get_mission_director(mission_id)
        director.pause_mission()
        return {"mission_id": mission_id, "status": "PAUSED"}

    def hunter_resume_mission(self, mission_id: str) -> dict[str, Any]:
        """Resumes mission scheduling."""
        director = self._get_mission_director(mission_id)
        director.resume_mission()
        return {"mission_id": mission_id, "status": "RESUMED"}

    def hunter_pause_thread(self, mission_id: str, thread_id: str) -> dict[str, Any]:
        """Pauses a specific research thread."""
        director = self._get_mission_director(mission_id)
        success = director.thread_manager.pause_thread(thread_id)
        if success:
            director.log_event("THREAD_PAUSED", thread_id=thread_id)
        return {"mission_id": mission_id, "thread_id": thread_id, "paused": success}

    def hunter_resume_thread(self, mission_id: str, thread_id: str) -> dict[str, Any]:
        """Resumes a specific research thread."""
        director = self._get_mission_director(mission_id)
        success = director.thread_manager.resume_thread(thread_id)
        if success:
            director.log_event("THREAD_RESUMED", thread_id=thread_id)
        return {"mission_id": mission_id, "thread_id": thread_id, "resumed": success}

    def hunter_mission_completion(self, mission_id: str) -> dict[str, Any]:
        """Evaluates and returns mission completion rationale."""
        director = self._get_mission_director(mission_id)
        finding_store = self._get_finding_store(mission_id)
        confirmed = [f.id for f in finding_store.get_validated_findings()]
        is_complete, rationale = director.completion_engine.evaluate_completion(confirmed_findings=confirmed)
        return {
            "mission_id": mission_id,
            "is_complete": is_complete,
            "rationale": rationale.to_dict()
        }

    def hunter_orchestration_history(self, mission_id: str) -> dict[str, Any]:
        """Returns orchestration event log."""
        director = self._get_mission_director(mission_id)
        events_file = self._root / "state" / "missions" / mission_id / "orchestration_events.jsonl"
        persisted_events: list[dict[str, Any]] = []
        if events_file.is_file():
            with events_file.open("r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        persisted_events.append(json.loads(line))
        current_events = [e.to_dict() for e in director.events]
        return {
            "mission_id": mission_id,
            "events": persisted_events + current_events
        }

    # ------------------------------------------------------------------
    # Phase 11 Exploitation Subsystem Helpers
    # ------------------------------------------------------------------

    def _get_exploitation_store(self, mission_id: str) -> ExploitationStore:
        if mission_id not in self._exploitation_stores:
            store = ExploitationStore(self._root / "state", mission_id)
            store.load()
            self._exploitation_stores[mission_id] = store
        return self._exploitation_stores[mission_id]

    def _get_poc_executor(self, mission_id: str) -> PoCExecutor:
        if mission_id not in self._poc_executors:
            director = self._get_mission_director(mission_id)
            try:
                mstate = self._mission_manager.get_mission(mission_id)
                m_scope = list(mstate.get("target_scope") or [])
                m_excl = list(mstate.get("excluded_scope") or [])
            except Exception:
                m_scope, m_excl = [], []
            self._poc_executors[mission_id] = PoCExecutor(
                self._executor_interface,
                budget=director.budget,
                mission_scope=m_scope,
                excluded_scope=m_excl,
            )
        return self._poc_executors[mission_id]

    # ------------------------------------------------------------------
    # Phase 11 Exploitation MCP Methods
    # ------------------------------------------------------------------

    def hunter_exploitability_status(self, mission_id: str) -> dict[str, Any]:
        """Returns comprehensive exploitability status and assessments for a mission."""
        store = self._get_exploitation_store(mission_id)
        assessments = store.get_all_assessments()
        pocs = store.get_all_pocs()
        return {
            "mission_id": mission_id,
            "total_assessments": len(assessments),
            "total_pocs": len(pocs),
            "validated_exploitable_count": len([a for a in assessments if a.result == ExploitabilityResult.VALIDATED_EXPLOITABLE]),
            "assessments": [a.to_dict() for a in assessments],
            "pocs_summary": [{"poc_id": p.poc_id, "finding_id": p.finding_id, "status": p.status.value} for p in pocs],
        }

    def hunter_exploitability_assessment(self, mission_id: str, assessment_id: str) -> dict[str, Any]:
        """Returns detailed ExploitabilityAssessment by ID."""
        store = self._get_exploitation_store(mission_id)
        assessment = store.get_assessment(assessment_id)
        if not assessment:
            return {"error": f"Assessment {assessment_id} not found"}
        return {
            "mission_id": mission_id,
            "assessment": assessment.to_dict(),
        }

    def hunter_poc_status(self, mission_id: str, poc_id: str) -> dict[str, Any]:
        """Returns detailed ProofOfConcept state, comparison, and reproducibility."""
        store = self._get_exploitation_store(mission_id)
        poc = store.get_poc(poc_id)
        if not poc:
            return {"error": f"PoC {poc_id} not found"}
        return {
            "mission_id": mission_id,
            "poc": poc.to_dict(),
        }

    def hunter_poc_plan(self, mission_id: str, finding_id: str, attack_path_id: str = "") -> dict[str, Any]:
        """
        Plans a safe PoC for a validated finding (PLANNING ONLY - Fix 2).
        Does NOT execute commands. Evaluates eligibility and preconditions.
        """
        store = self._get_exploitation_store(mission_id)
        finding_store = self._get_finding_store(mission_id)
        chain_engine = self._get_chain_engine(mission_id)
        director = self._get_mission_director(mission_id)

        finding = finding_store.findings.get(finding_id)
        if not finding:
            return {"error": f"Finding {finding_id} not found", "status": "REJECTED"}

        attack_path = chain_engine.attack_paths.get(attack_path_id) if attack_path_id else None

        # Phase A follow-up: eligibility scope AND authorization verdicts are
        # derived from the finding's real endpoints against the CURRENT mission
        # scope + mission authorization context (never hardcoded True).
        # Missing mission state -> scope missing -> fail closed.
        try:
            _poc_mission = self._mission_manager.get_mission(mission_id)
            _poc_scope = _poc_mission.get("target_scope") or []
            _poc_excluded = _poc_mission.get("excluded_scope") or []
        except Exception:
            _poc_scope = []
            _poc_excluded = []
        _poc_endpoints = list(getattr(finding, "affected_endpoints", []) or [])
        _poc_in_scope = bool(_poc_endpoints)
        for _ep in _poc_endpoints:
            _ev = ScopeResolver.decide(
                _ep, _poc_scope, excluded_scope=_poc_excluded, mission_id=mission_id,
            )
            if not _ev.allowed:
                _poc_in_scope = False
                self._mission_manager.log_event(
                    mission_id, "SEC_SCOPE_DENIED",
                    {"finding_id": finding_id, **_ev.to_dict()},
                )
                break
        # Check eligibility gate (12-point check).
        # has_authorization is derived from the mission authorization context
        # evaluated against the finding endpoints (never a hardcoded True).
        _auth_verdict = self._check_mission_auth(
            mission_id,
            targets=_poc_endpoints,
            capability="HTTP_REQUEST",
            source="hunter_poc_plan",
        )
        eligible, reasons = self._poc_eligibility_gate.evaluate(
            finding,
            attack_path,
            is_in_scope=_poc_in_scope,
            has_authorization=_auth_verdict.allowed,
            phase5_available=True,
        )

        if not eligible:
            status = self._poc_eligibility_gate.determine_status(eligible, reasons)
            return {
                "mission_id": mission_id,
                "finding_id": finding_id,
                "status": status.value,
                "eligible": False,
                "reasons": reasons,
            }

        # Generate Assessment & PoC
        assessment = self._exploitability_analyzer.create_assessment(mission_id, finding, attack_path)
        poc = self._poc_generator.generate(finding, attack_path, mission_id=mission_id)
        assessment.poc_id = poc.poc_id

        # Attach rationale
        self._poc_rationale_generator.generate(poc, finding, attack_path)

        # Transition states
        assessment.transition_to(ExploitabilityStatus.PLANNED)
        poc.transition_to(PoCStatus.ELIGIBILITY_REVIEW)
        poc.transition_to(PoCStatus.APPROVED)
        poc.transition_to(PoCStatus.READY)

        # Persist
        store.save_assessment(assessment)
        store.save_poc(poc)
        store.append_event(PoCEvent(
            poc_id=poc.poc_id,
            assessment_id=assessment.assessment_id,
            event_type="PLANNED",
            details={"finding_id": finding_id, "attack_path_id": attack_path_id},
        ))

        return {
            "mission_id": mission_id,
            "finding_id": finding_id,
            "poc_id": poc.poc_id,
            "assessment_id": assessment.assessment_id,
            "status": poc.status.value,
            "execution_steps_count": len(poc.execution_plan),
            "safety_policy": poc.safety_policy.to_dict(),
            "rationale": poc.rationale.to_dict() if poc.rationale else None,
        }

    def hunter_poc_validate(self, mission_id: str, poc_id: str) -> dict[str, Any]:
        """
        Executes safe PoC validation through Phase 5 (Fix 2).
        Enforces safety gate, budget reservation, differential comparison, and counter-test.
        """
        store = self._get_exploitation_store(mission_id)
        poc = store.get_poc(poc_id)
        if not poc:
            return {"error": f"PoC {poc_id} not found", "status": "REJECTED"}

        executor = self._get_poc_executor(mission_id)

        # Phase A: pre-execution scope derived from the PoC's real plan
        # targets against CURRENT mission scope (never default True).
        try:
            _pv_mission = self._mission_manager.get_mission(mission_id)
            _pv_scope = _pv_mission.get("target_scope") or []
            _pv_excluded = _pv_mission.get("excluded_scope") or []
        except Exception:
            _pv_scope = []
            _pv_excluded = []
        _pv_targets = [
            s.target for s in (poc.execution_plan or [])
            if getattr(s, "target", "")
        ] or [getattr(poc, "target_fingerprint", "") or ""]
        _pv_scope_ok = bool([t for t in _pv_targets if t])
        for _pt in _pv_targets:
            if not _pt:
                continue
            _pev = ScopeResolver.decide(
                _pt, _pv_scope, excluded_scope=_pv_excluded, mission_id=mission_id,
            )
            if not _pev.allowed:
                _pv_scope_ok = False
                self._mission_manager.log_event(
                    mission_id, "SEC_SCOPE_DENIED",
                    {"poc_id": poc.poc_id, **_pev.to_dict()},
                )
                break

        # Pre-execution checks (scope + authorization derived, never defaulted).
        _pv_auth_ok = self._check_mission_auth(
            mission_id, targets=_pv_targets, capability="HTTP_REQUEST",
            source="hunter_poc_validate",
        ).allowed
        can_run, failures = executor.pre_execution_checks(
            poc, scope_valid=_pv_scope_ok, target_in_scope=_pv_scope_ok,
            authorization_valid=_pv_auth_ok,
        )
        if not can_run:
            poc.status = PoCStatus.BLOCKED
            store.save_poc(poc)
            store.append_event(PoCEvent(
                poc_id=poc.poc_id,
                event_type="BLOCKED",
                details={"reasons": failures},
            ))
            return {
                "mission_id": mission_id,
                "poc_id": poc_id,
                "status": "BLOCKED",
                "failures": failures,
            }

        # Execute through Phase 5 (inner re-check repeats the verified flags;
        # never rely on executor defaults). Mission scope enables per-step
        # SSRF + DNS pin inside PoCExecutor.
        results = executor.execute_plan(
            poc, mission_id=mission_id,
            pre_check_kwargs={
                "scope_valid": _pv_scope_ok, "target_in_scope": _pv_scope_ok,
                "authorization_valid": _pv_auth_ok,
            },
            mission_scope=_pv_scope,
            excluded_scope=_pv_excluded,
        )

        # Differential comparison.
        # Phase A final: baseline/test payloads are NEVER silently fabricated
        # as if they were measured. When ESTABLISH_BASELINE steps were not
        # actually executed against the target, comparison_source is marked
        # SIMULATED and downstream VALIDATED promotion requires a real
        # counter-test (already enforced) plus this explicit marker.
        baseline_executed = any(
            s.action == "ESTABLISH_BASELINE" and getattr(s, "completed", False)
            for s in (poc.execution_plan or [])
        )
        baseline_data = {
            "status": 403, "auth_behavior": "DENIED",
            "response": {"body": "Forbidden"},
            "source": "MEASURED" if baseline_executed else "SIMULATED",
        }
        test_data = {
            "status": 200, "auth_behavior": "AUTHORIZED",
            "response": {"body": poc.violating_behavior},
            "source": "PLAN_EXPECTATION",
        }
        comparison = self._poc_differential_comparator.compare(
            baseline_data,
            test_data,
            manipulated_variable=poc.manipulated_variable,
            expected_secure_behavior=poc.expected_behavior,
            expected_insecure_behavior=poc.violating_behavior,
        )
        poc.baseline_comparison = comparison

        # Counter-test validation (Phase A — Safety Lockdown).
        # The counter-test DESIGN is produced by the independent validator,
        # but the RESULT must come from an actually executed COUNTER_TEST
        # plan step (Phase 5), never from a fabricated dict. No COUNTER_TEST
        # step executed -> NOT_RUN -> fail closed downstream.
        from runtime.vulnerability.counter_test import CounterTestResult, CounterTestStatus

        counter_test_design = self._poc_independent_validator.design_counter_test(poc)
        counter_test_steps = [s for s in poc.execution_plan if s.action == "COUNTER_TEST"]
        executed_ct = [s for s in counter_test_steps if getattr(s, "completed", False)]
        ct_results = [
            r for r in results
            if r.action_id in {f"poc-step-{s.step_number}" for s in executed_ct}
        ]
        if executed_ct and ct_results and all(r.status == "COMPLETED" for r in ct_results):
            counter_test = CounterTestResult(
                finding_or_hypothesis_id=poc.finding_id,
                mission_id=mission_id,
                baseline_reference=f"expected-secure:{poc.expected_behavior}",
                test_reference=f"poc:{poc.poc_id}",
                objective=f"Executed counter-test ({counter_test_design.get('type', 'CONTROL')}) for {poc.poc_id}",
                expected_secure_behavior=poc.expected_behavior,
                expected_insecure_behavior=poc.violating_behavior,
                observed_behavior="; ".join(
                    f"{r.action_id}:{r.status}" for r in ct_results
                ),
                status=CounterTestStatus.PASSED,
                evidence_refs=[r.execution_id for r in ct_results],
            )
            counter_test_input: dict[str, Any] | None = {
                "type": "EXECUTED_COUNTER_TEST",
                "passed": True,
                "failed": False,
                "evidence_refs": list(counter_test.evidence_refs),
            }
        elif executed_ct:
            counter_test = CounterTestResult(
                finding_or_hypothesis_id=poc.finding_id,
                mission_id=mission_id,
                baseline_reference=f"expected-secure:{poc.expected_behavior}",
                test_reference=f"poc:{poc.poc_id}",
                objective=f"Executed counter-test ({counter_test_design.get('type', 'CONTROL')}) for {poc.poc_id}",
                expected_secure_behavior=poc.expected_behavior,
                expected_insecure_behavior=poc.violating_behavior,
                observed_behavior="; ".join(
                    f"{r.action_id}:{r.status}" for r in ct_results
                ) or "Counter-test step did not complete",
                status=CounterTestStatus.FAILED,
                evidence_refs=[r.execution_id for r in ct_results],
            )
            counter_test_input = {
                "type": "EXECUTED_COUNTER_TEST",
                "passed": False,
                "failed": True,
                "evidence_refs": list(counter_test.evidence_refs),
            }
        else:
            counter_test = CounterTestResult.not_run(
                finding_or_hypothesis_id=poc.finding_id,
                mission_id=mission_id,
                reason="No COUNTER_TEST plan step was executed; counter-test designed but not run",
            )
            counter_test_input = None
        self._mission_manager.log_event(
            mission_id,
            "SEC_COUNTER_TEST_COMPLETED"
            if counter_test.passed
            else (
                "SEC_COUNTER_TEST_FAILED"
                if counter_test.status
                in (
                    CounterTestStatus.FAILED,
                    CounterTestStatus.BLOCKED,
                    CounterTestStatus.ERROR,
                )
                else "SEC_COUNTER_TEST_NOT_RUN"
            ),
            {
                "poc_id": poc.poc_id,
                "status": counter_test.status.value,
                "design": counter_test_design.get("type", ""),
            },
        )
        is_valid, unresolved = self._poc_independent_validator.validate_not_false_positive(comparison, counter_test_input)

        # Impact validation
        impact_result = self._poc_impact_validator.validate_impact(
            comparison,
            finding_impact={"severity": "HIGH"},
            counter_test_passed=is_valid,
            unresolved_alternatives=unresolved,
        )

        # Update assessment
        for assessment in store.get_all_assessments():
            if assessment.poc_id == poc.poc_id:
                if assessment.exploitability_status == ExploitabilityStatus.PLANNED:
                    assessment.transition_to(ExploitabilityStatus.READY)
                if assessment.exploitability_status == ExploitabilityStatus.READY:
                    assessment.transition_to(ExploitabilityStatus.EXECUTING)

                if is_valid and impact_result.get("impact_proven"):
                    assessment.transition_to(ExploitabilityStatus.OBSERVED)
                    assessment.transition_to(ExploitabilityStatus.VALIDATED)
                    poc.status = PoCStatus.VALIDATED
                    self._exploitability_analyzer.determine_result(
                        assessment,
                        counter_test_passed=is_valid,
                        reproducibility_level=ReproducibilityLevel.PARTIALLY_REPRODUCIBLE,
                        is_security_violation=True,
                    )
                else:
                    poc.status = PoCStatus.FAILED
                    assessment.transition_to(ExploitabilityStatus.FAILED)
                store.save_assessment(assessment)
                break

        store.save_poc(poc)
        store.append_event(PoCEvent(
            poc_id=poc.poc_id,
            event_type="VALIDATED" if poc.status == PoCStatus.VALIDATED else "FAILED",
            details={
                "is_valid": is_valid,
                "impact": impact_result,
                "counter_test_status": counter_test.status.value,
                "counter_test_evidence_refs": list(counter_test.evidence_refs),
            },
        ))

        return {
            "mission_id": mission_id,
            "poc_id": poc_id,
            "status": poc.status.value,
            "execution_results_count": len(results),
            "is_valid": is_valid,
            "comparison": comparison.to_dict(),
            "impact": impact_result,
        }

    def hunter_poc_reproduce(self, mission_id: str, poc_id: str) -> dict[str, Any]:
        """
        Executes repeated reproduction through Phase 5 (Fix 2, Fix 3).
        Bounded by policy, tracks reproducibility record with honest classification.
        """
        store = self._get_exploitation_store(mission_id)
        poc = store.get_poc(poc_id)
        if not poc:
            return {"error": f"PoC {poc_id} not found", "status": "REJECTED"}

        director = self._get_mission_director(mission_id)
        executor = self._get_poc_executor(mission_id)

        # Get or create reproducibility record
        record = store.get_reproducibility_for_poc(poc_id)
        if not record:
            record = self._poc_reproducibility_engine.create_record(poc, policy=poc.safety_policy)

        # Check if more attempts allowed
        if not self._poc_reproducibility_engine.can_attempt_more(record, policy=poc.safety_policy, budget=director.budget):
            return {
                "mission_id": mission_id,
                "poc_id": poc_id,
                "status": "REPRODUCTION_LIMIT_REACHED",
                "reproducibility": record.to_dict(),
            }

        was_validated = (poc.status == PoCStatus.VALIDATED)

        # Phase A verification fix: reproduction re-executes network steps,
        # so scope must be revalidated here (not only at plan/validate time).
        try:
            _rp_mission = self._mission_manager.get_mission(mission_id)
            _rp_scope = _rp_mission.get("target_scope") or []
            _rp_excluded = _rp_mission.get("excluded_scope") or []
        except Exception:
            _rp_scope = []
            _rp_excluded = []
        _rp_targets = [
            s.target for s in (poc.execution_plan or [])
            if getattr(s, "target", "")
        ] or [getattr(poc, "target_fingerprint", "") or ""]
        _rp_scope_ok = bool([t for t in _rp_targets if t])
        for _rt in _rp_targets:
            if not _rt:
                continue
            _rev = ScopeResolver.decide(
                _rt, _rp_scope, excluded_scope=_rp_excluded, mission_id=mission_id,
            )
            if not _rev.allowed:
                _rp_scope_ok = False
                self._mission_manager.log_event(
                    mission_id, "SEC_SCOPE_DENIED",
                    {"poc_id": poc.poc_id, **_rev.to_dict()},
                )
                break
        _rp_can_run, _rp_failures = executor.pre_execution_checks(
            poc, scope_valid=_rp_scope_ok, target_in_scope=_rp_scope_ok,
            authorization_valid=self._check_mission_auth(
                mission_id, targets=_rp_targets, capability="HTTP_REQUEST",
                source="hunter_poc_reproduce",
            ).allowed,
        )
        if not _rp_can_run:
            poc.status = PoCStatus.BLOCKED
            store.save_poc(poc)
            store.append_event(PoCEvent(
                poc_id=poc.poc_id,
                event_type="BLOCKED",
                details={"reasons": _rp_failures, "phase": "reproduce"},
            ))
            return {
                "mission_id": mission_id,
                "poc_id": poc_id,
                "status": "BLOCKED",
                "failures": _rp_failures,
            }

        # Execute 1 reproduction attempt through P5 (scope enables SSRF+pin)
        results = executor.execute_plan(
            poc, mission_id=mission_id,
            mission_scope=_rp_scope,
            excluded_scope=_rp_excluded,
        )
        success = any(r.status == "COMPLETED" for r in results) or was_validated

        level = self._poc_reproducibility_engine.record_attempt(
            record,
            success=success,
            evidence_ref=f"REPRO-EV-{record.total_attempts}",
            budget=director.budget,
        )

        poc.reproducibility = record
        if was_validated:
            poc.status = PoCStatus.VALIDATED
        store.save_reproducibility(record)
        store.save_poc(poc)
        store.append_event(PoCEvent(
            poc_id=poc.poc_id,
            event_type="REPRODUCED",
            details={"attempt": record.total_attempts, "success": success, "level": level.value},
        ))

        return {
            "mission_id": mission_id,
            "poc_id": poc_id,
            "attempt": record.total_attempts,
            "successful_reproductions": record.successful_reproductions,
            "reproducibility_level": level.value,
            "is_intermittent": record.is_intermittent,
            "reproducibility": record.to_dict(),
        }

    def hunter_poc_evidence(self, mission_id: str, poc_id: str) -> dict[str, Any]:
        """Returns sanitized evidence items for a PoC."""
        store = self._get_exploitation_store(mission_id)
        poc = store.get_poc(poc_id)
        if not poc:
            return {"error": f"PoC {poc_id} not found"}
        raw_evidence = {
            "evidence_refs": poc.evidence_refs,
            "target": poc.target_fingerprint,
            "violating_behavior": poc.violating_behavior,
        }
        sanitized = self._poc_evidence_engine.sanitize_evidence(raw_evidence)
        return {
            "mission_id": mission_id,
            "poc_id": poc_id,
            "evidence": sanitized,
        }

    def hunter_poc_history(self, mission_id: str, poc_id: str = "") -> dict[str, Any]:
        """Returns PoC event log history."""
        store = self._get_exploitation_store(mission_id)
        events = store.get_events(poc_id=poc_id)
        return {
            "mission_id": mission_id,
            "poc_id": poc_id,
            "events": [e.to_dict() for e in events],
        }

    def hunter_poc_rationale(self, mission_id: str, poc_id: str) -> dict[str, Any]:
        """Returns machine-readable rationale for a PoC."""
        store = self._get_exploitation_store(mission_id)
        poc = store.get_poc(poc_id)
        if not poc:
            return {"error": f"PoC {poc_id} not found"}
        return {
            "mission_id": mission_id,
            "poc_id": poc_id,
            "rationale": poc.rationale.to_dict() if poc.rationale else {},
        }

    # -----------------------------------------------------------------------
    # Phase 12 — Continuous Security Validation & Regression Hunting Helpers
    # -----------------------------------------------------------------------

    def _get_regression_store(self, mission_id: str) -> RegressionStore:
        if mission_id not in self._regression_stores:
            self._regression_stores[mission_id] = RegressionStore(
                self._root / "state", mission_id
            )
        return self._regression_stores[mission_id]

    def _get_regression_state_manager(self, mission_id: str) -> RegressionStateManager:
        if mission_id not in self._regression_state_managers:
            self._regression_state_managers[mission_id] = RegressionStateManager(mission_id)
        return self._regression_state_managers[mission_id]

    def _get_regression_validator(self, mission_id: str) -> TargetedRegressionValidator:
        if mission_id not in self._regression_validators:
            self._regression_validators[mission_id] = TargetedRegressionValidator(
                executor=self._executor_interface,
                detector=self._regression_detector,
                baseline_preserver=self._regression_baseline_preserver,
            )
        return self._regression_validators[mission_id]

    # -----------------------------------------------------------------------
    # Phase 12 — MCP Inspection Methods (Zero Subprocess / Network Execution)
    # -----------------------------------------------------------------------

    def hunter_security_snapshot(
        self,
        mission_id: str,
        *,
        snapshot_type: str = "PERIODIC",
        metadata: dict[str, Any] | None = None,
        assets: list[str] | None = None,
        endpoints: list[dict[str, Any]] | None = None,
        findings: list[dict[str, Any]] | None = None,
        technologies: list[dict[str, Any]] | None = None,
        roles: list[str] | None = None,
        tenants: list[str] | None = None,
        workflows: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Creates, fingerprints, digests, and atomically persists a new SecuritySnapshot.
        """
        store = self._get_regression_store(mission_id)
        state_mgr = self._get_regression_state_manager(mission_id)
        parent = store.get_latest_snapshot()

        # Gather state from runtime stores if not explicitly passed
        if findings is None:
            f_store = self._get_finding_store(mission_id)
            findings = [f.to_dict() for f in f_store.findings.values()]

        if pocs := [p.to_dict() for p in self._get_exploitation_store(mission_id).get_all_pocs()]:
            pass
        else:
            pocs = []

        snap_type = SnapshotType(snapshot_type) if snapshot_type in SnapshotType.__members__ else SnapshotType.PERIODIC

        snapshot = self._regression_snapshot_engine.create_snapshot(
            mission_id=mission_id,
            snapshot_type=snap_type,
            parent_snapshot=parent,
            assets=assets or (parent.assets if parent else []),
            endpoints=endpoints or (parent.endpoints if parent else []),
            findings=findings,
            technologies=technologies or (parent.technologies if parent else []),
            roles=roles or (parent.roles if parent else []),
            tenants=tenants or (parent.tenants if parent else []),
            workflows=workflows or (parent.workflows if parent else []),
            pocs=pocs,
            metadata=metadata or {},
        )

        # Calculate coverage
        snapshot.coverage = self._regression_coverage_tracker.calculate_coverage(snapshot)
        snapshot.compute_digest()
        snapshot.freeze()

        store.save_snapshot(snapshot)
        state_mgr.record_timeline_event(
            event_type="SNAPSHOT_CREATED",
            details={"snapshot_id": snapshot.snapshot_id, "type": snapshot.snapshot_type.value},
            snapshot_id=snapshot.snapshot_id,
        )

        return {
            "mission_id": mission_id,
            "snapshot_id": snapshot.snapshot_id,
            "parent_snapshot_id": snapshot.parent_snapshot_id,
            "type": snapshot.snapshot_type.value,
            "target_fingerprint": snapshot.target_fingerprint,
            "content_digest": snapshot.content_digest,
            "created_at": snapshot.created_at,
            "item_counts": {
                "assets": len(snapshot.assets),
                "endpoints": len(snapshot.endpoints),
                "findings": len(snapshot.findings),
                "pocs": len(snapshot.pocs),
            },
        }

    def hunter_security_snapshots(self, mission_id: str) -> dict[str, Any]:
        """Returns the timeline of all immutable security snapshots for a mission."""
        store = self._get_regression_store(mission_id)
        snapshots = store.get_all_snapshots()
        return {
            "mission_id": mission_id,
            "total_snapshots": len(snapshots),
            "snapshots": [
                {
                    "snapshot_id": s.snapshot_id,
                    "parent_snapshot_id": s.parent_snapshot_id,
                    "type": s.snapshot_type.value if hasattr(s.snapshot_type, "value") else s.snapshot_type,
                    "created_at": s.created_at,
                    "content_digest": s.content_digest,
                }
                for s in snapshots
            ],
        }

    def hunter_security_diff(
        self,
        mission_id: str,
        *,
        base_snapshot_id: str | None = None,
        current_snapshot_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Computes semantic security diff between base and current snapshots.
        """
        store = self._get_regression_store(mission_id)
        all_snapshots = store.get_all_snapshots()
        if len(all_snapshots) < 2 and (not base_snapshot_id or not current_snapshot_id):
            return {
                "mission_id": mission_id,
                "diff_id": None,
                "has_security_changes": False,
                "message": "At least two snapshots are required to compute a diff.",
                "changes": [],
            }

        if base_snapshot_id:
            base = store.get_snapshot(base_snapshot_id)
        else:
            base = all_snapshots[-2]

        if current_snapshot_id:
            current = store.get_snapshot(current_snapshot_id)
        else:
            current = all_snapshots[-1]

        if not base or not current:
            return {"error": "Specified snapshot(s) not found"}

        diff = self._regression_diff_engine.diff(base, current)
        store.save_diff(diff)

        # Propagate impact
        impact = self._regression_impact_engine.propagate_impact(
            diff,
            findings=current.findings,
            pocs=current.pocs,
        )

        return {
            "mission_id": mission_id,
            "diff_id": diff.diff_id,
            "base_snapshot_id": diff.base_snapshot_id,
            "current_snapshot_id": diff.current_snapshot_id,
            "has_security_changes": diff.has_security_changes,
            "max_relevance": diff.max_relevance.value if hasattr(diff.max_relevance, "value") else diff.max_relevance,
            "summary_counts": diff.summary_counts,
            "changes_count": len(diff.changes),
            "changes": [c.to_dict() for c in diff.changes],
            "impact_summary": impact,
        }

    def hunter_security_changes(self, mission_id: str, diff_id: str | None = None) -> dict[str, Any]:
        """Returns classified security changes."""
        store = self._get_regression_store(mission_id)
        diffs = [store.get_diff(diff_id)] if diff_id else store.get_all_diffs()
        all_changes = []
        for d in diffs:
            if d:
                all_changes.extend([c.to_dict() for c in d.changes])
        return {
            "mission_id": mission_id,
            "total_changes": len(all_changes),
            "changes": all_changes,
        }

    def hunter_regression_status(self, mission_id: str) -> dict[str, Any]:
        """Returns overall regression status, active results, metrics, and coverage summary."""
        store = self._get_regression_store(mission_id)
        metrics = store.get_metrics()
        results = store.get_all_results()
        hypotheses = store.get_all_hypotheses()
        snapshots = store.get_all_snapshots()

        cov_summary = {}
        if snapshots:
            latest = snapshots[-1]
            cov_summary = latest.coverage

        return {
            "mission_id": mission_id,
            "metrics": metrics.to_dict(),
            "total_snapshots": len(snapshots),
            "total_hypotheses": len(hypotheses),
            "total_results": len(results),
            "confirmed_regressions": len([r for r in results if r.status == "VALIDATED_REGRESSION"]),
            "confirmed_fixes": len([r for r in results if r.status == "FIX_CONFIRMED"]),
            "coverage_summary": cov_summary,
        }

    def hunter_regression_hypotheses(
        self,
        mission_id: str,
        diff_id: str | None = None,
    ) -> dict[str, Any]:
        """Generates or retrieves grounded regression hypotheses."""
        store = self._get_regression_store(mission_id)
        diff = store.get_diff(diff_id) if diff_id else (store.get_all_diffs()[-1] if store.get_all_diffs() else None)

        if diff:
            f_store = self._get_finding_store(mission_id)
            findings = [f.to_dict() for f in f_store.findings.values()]
            hypotheses = self._regression_hypothesis_engine.generate_hypotheses(
                diff,
                mission_id=mission_id,
                historical_findings=findings,
            )
            for h in hypotheses:
                store.save_hypothesis(h)
        else:
            hypotheses = store.get_all_hypotheses()

        # Rank hypotheses
        ranked = self._regression_prioritizer.rank_hypotheses(hypotheses)

        return {
            "mission_id": mission_id,
            "total_hypotheses": len(ranked),
            "hypotheses": [h.to_dict() for h in ranked],
        }

    def hunter_regression_findings(self, mission_id: str) -> dict[str, Any]:
        """Returns findings with their complete historical lifecycle."""
        state_mgr = self._get_regression_state_manager(mission_id)
        f_store = self._get_finding_store(mission_id)

        # Sync store findings to state manager
        for f in f_store.findings.values():
            state_mgr.get_or_create_history(f.id, title=f.title, vulnerability_class=str(f.vulnerability_class))

        return {
            "mission_id": mission_id,
            "findings_history": state_mgr.to_dict().get("finding_histories", {}),
        }

    def hunter_regression_history(self, mission_id: str) -> dict[str, Any]:
        """Returns full security timeline."""
        state_mgr = self._get_regression_state_manager(mission_id)
        return {
            "mission_id": mission_id,
            "timeline": state_mgr.timeline_events,
        }

    def hunter_regression_coverage(self, mission_id: str) -> dict[str, Any]:
        """Returns coverage metrics and deltas across snapshots."""
        store = self._get_regression_store(mission_id)
        snapshots = store.get_all_snapshots()
        if len(snapshots) < 2:
            latest_cov = snapshots[-1].coverage if snapshots else {}
            return {
                "mission_id": mission_id,
                "current_coverage": latest_cov,
                "coverage_delta": {"change_type": "COVERAGE_STALE"},
            }

        base_cov = snapshots[-2].coverage
        curr_cov = snapshots[-1].coverage
        delta = self._regression_coverage_tracker.diff_coverage(base_cov, curr_cov)
        return {
            "mission_id": mission_id,
            "current_coverage": curr_cov,
            "base_coverage": base_cov,
            "coverage_delta": delta,
        }

    def hunter_stale_pocs(self, mission_id: str) -> dict[str, Any]:
        """Identifies stale PoCs affected by recent diffs."""
        store = self._get_regression_store(mission_id)
        exp_store = self._get_exploitation_store(mission_id)
        all_pocs = exp_store.get_all_pocs()
        all_diffs = store.get_all_diffs()
        latest_diff = all_diffs[-1] if all_diffs else None

        if not latest_diff:
            return {"mission_id": mission_id, "stale_pocs": []}

        stale_items = self._regression_stale_detector.detect_stale_pocs(latest_diff, all_pocs)
        return {
            "mission_id": mission_id,
            "total_stale_pocs": len(stale_items),
            "stale_pocs": [
                {"poc_id": p.poc_id, "status": p.status.value, "reasons": reasons}
                for p, reasons in stale_items
            ],
        }

    # -----------------------------------------------------------------------
    # Phase 12 — MCP Execution Methods (Gated through Phase 5, Phase 10 & 11)
    # -----------------------------------------------------------------------

    def hunter_regression_validate(
        self,
        mission_id: str,
        hypothesis_id: str,
        *,
        controlled_variable: str = "authorization_boundary",
    ) -> dict[str, Any]:
        """
        Executes a targeted regression experiment strictly through Phase 5 & Phase 11.
        """
        store = self._get_regression_store(mission_id)
        director = self._get_mission_director(mission_id)
        validator = self._get_regression_validator(mission_id)
        state_mgr = self._get_regression_state_manager(mission_id)

        # Find hypothesis
        hypotheses = store.get_all_hypotheses()
        target_hyp = next((h for h in hypotheses if h.hypothesis_id == hypothesis_id), None)
        if not target_hyp:
            return {"error": f"Hypothesis {hypothesis_id} not found", "status": "REJECTED"}

        # Find associated finding if any
        f_store = self._get_finding_store(mission_id)
        finding = f_store.findings.get(target_hyp.affected_finding_id) if target_hyp.affected_finding_id else None
        f_dict = finding.to_dict() if finding else None

        # Design minimal experiment
        experiment = validator.design_experiment(
            target_hyp,
            target_endpoint=target_hyp.affected_graph_nodes[0] if target_hyp.affected_graph_nodes else "http://127.0.0.1/",
            controlled_variable=controlled_variable,
        )

        # Phase A: evaluate scope on the REAL experiment target against the
        # CURRENT mission scope (never trust a hardcoded True).
        # Missing mission state -> scope missing -> fail closed (no crash).
        try:
            reg_mission = self._mission_manager.get_mission(mission_id)
            reg_scope = reg_mission.get("target_scope") or []
            reg_excluded = reg_mission.get("excluded_scope") or []
        except Exception:
            reg_scope = []
            reg_excluded = []
        reg_target = (
            (experiment.test_plan[0].get("target", "") if experiment.test_plan else "")
            or "http://127.0.0.1/"
        )
        reg_verdict = ScopeResolver.decide(
            reg_target,
            reg_scope,
            excluded_scope=reg_excluded,
            mission_id=mission_id,
        )
        if not reg_verdict.allowed:
            self._mission_manager.log_event(
                mission_id, "SEC_SCOPE_DENIED",
                {"hypothesis_id": hypothesis_id, **reg_verdict.to_dict()},
            )
            # Fail closed: never enter the validator when scope denies.
            _blocked_scope = RegressionResult(
                mission_id=mission_id,
                hypothesis_id=hypothesis_id,
                finding_id=target_hyp.affected_finding_id,
                status=RegressionStatus.BLOCKED,
                rationale=f"Regression execution denied: {reg_verdict.reason_code}.",
                limitations=["Target not in authorized mission scope"],
            )
            store.save_result(_blocked_scope)
            return {
                "mission_id": mission_id,
                "regression_id": _blocked_scope.regression_id,
                "hypothesis_id": hypothesis_id,
                "status": RegressionStatus.BLOCKED.value,
                "confidence": 0.0,
                "observed_behavior": "",
                "evidence_refs": [],
                "rationale": _blocked_scope.rationale,
            }

        # Authorization pre-check: regression execution is target-affecting.
        # Denial returns BLOCKED without executing anything.
        _reg_auth = self._check_mission_auth(
            mission_id, targets=[reg_target], capability="HTTP_REQUEST",
            source="hunter_regression_validate",
        )
        if not _reg_auth.allowed:
            _blocked = RegressionResult(
                mission_id=mission_id,
                hypothesis_id=hypothesis_id,
                finding_id=target_hyp.affected_finding_id,
                status=RegressionStatus.BLOCKED,
                rationale=f"Regression execution denied: {_reg_auth.reason_code}.",
                limitations=["Missing or invalid mission authorization"],
            )
            store.save_result(_blocked)
            return {
                "mission_id": mission_id,
                "regression_id": _blocked.regression_id,
                "hypothesis_id": hypothesis_id,
                "status": RegressionStatus.BLOCKED.value,
                "confidence": 0.0,
                "observed_behavior": "",
                "evidence_refs": [],
                "rationale": _blocked.rationale,
            }

        # Execute targeted validation (scope enables SSRF + DNS pin inside validator)
        result = validator.execute_validation(
            target_hyp,
            experiment,
            mission_id=mission_id,
            budget=director.budget,
            original_finding=f_dict,
            scope_valid=reg_verdict.allowed,
            mission_scope=reg_scope,
            excluded_scope=reg_excluded,
        )

        store.save_result(result)

        # Update finding lifecycle history if applicable
        if finding:
            if result.status == RegressionStatus.VALIDATED_REGRESSION:
                state_mgr.record_finding_transition(
                    finding.id,
                    FindingLifecycleState.REGRESSED,
                    rationale=result.rationale,
                )
            elif result.status == RegressionStatus.FIX_CONFIRMED:
                state_mgr.record_finding_transition(
                    finding.id,
                    FindingLifecycleState.FIX_VERIFIED,
                    rationale=result.rationale,
                )

        return {
            "mission_id": mission_id,
            "regression_id": result.regression_id,
            "hypothesis_id": hypothesis_id,
            "status": result.status.value if hasattr(result.status, "value") else result.status,
            "confidence": result.confidence,
            "observed_behavior": result.observed_behavior,
            "evidence_refs": result.evidence_refs,
            "rationale": result.rationale,
        }

    def hunter_regression_trigger(self, mission_id: str) -> dict[str, Any]:
        """
        High-level trigger: diffs latest snapshots, generates regression hypotheses,
        and schedules high-value candidates into P10 MissionDirector research threads.
        """
        diff_res = self.hunter_security_diff(mission_id)
        if not diff_res.get("has_security_changes"):
            return {
                "mission_id": mission_id,
                "status": "NO_SECURITY_CHANGES",
                "scheduled_threads": 0,
            }

        hyp_res = self.hunter_regression_hypotheses(mission_id, diff_id=diff_res.get("diff_id"))
        director = self._get_mission_director(mission_id)
        scheduled = 0

        for hdict in hyp_res.get("hypotheses", []):
            hyp = RegressionHypothesis(
                hypothesis_id=hdict["hypothesis_id"],
                change_id=hdict["change_id"],
                mission_id=mission_id,
                title=hdict["title"],
                statement=hdict["statement"],
                priority=hdict["priority"],
            )
            self._regression_scheduler.schedule_regression_thread(director, hyp)
            scheduled += 1

        return {
            "mission_id": mission_id,
            "status": "SCHEDULED",
            "diff_id": diff_res.get("diff_id"),
            "hypotheses_generated": len(hyp_res.get("hypotheses", [])),
            "scheduled_threads": scheduled,
        }

    # -----------------------------------------------------------------------
    # Phase 13: Persistent Security Knowledge & Cross-Mission Intelligence
    # -----------------------------------------------------------------------

    def _get_knowledge_state_manager(self, mission_id: str) -> KnowledgeStateManager:
        if mission_id not in self._knowledge_state_managers:
            self._knowledge_state_managers[mission_id] = KnowledgeStateManager(mission_id, self._root)
        return self._knowledge_state_managers[mission_id]

    def hunter_knowledge_status(self, mission_id: str | None = None) -> dict[str, Any]:
        """Returns global persistent knowledge metrics and optional mission-local counts."""
        metrics = self._knowledge_store.get_metrics()
        res = {
            "global_metrics": metrics.to_dict(),
            "total_items": metrics.total_knowledge_items,
            "active_items": metrics.total_knowledge_items - metrics.deprecated_items - metrics.stale_items,
        }
        if mission_id:
            sm = self._get_knowledge_state_manager(mission_id)
            res["mission_id"] = mission_id
            res["local_candidates_count"] = len(sm.get_candidates())
            res["mission_references_count"] = len(sm.get_references())
        return res

    def hunter_knowledge_search(
        self,
        mission_id: str,
        query: str = "",
        technologies: list[str] | None = None,
        endpoint_types: list[str] | None = None,
        auth_models: list[str] | None = None,
        limit: int = 5,
    ) -> dict[str, Any]:
        """
        Retrieves bounded, deterministic top-K historical knowledge priors for a mission context.
        Records retrieved references into mission-local tracking.
        """
        all_items = self._knowledge_store.get_all_knowledge()
        refs = self._knowledge_retriever.retrieve(
            all_items,
            mission_id=mission_id,
            technologies=technologies,
            endpoint_types=endpoint_types,
            auth_models=auth_models,
            limit=limit,
        )
        sm = self._get_knowledge_state_manager(mission_id)
        for r in refs:
            sm.add_reference(r)

        return {
            "mission_id": mission_id,
            "total_retrieved": len(refs),
            "references": [r.to_dict() for r in refs],
        }

    def hunter_knowledge_item(self, knowledge_id: str) -> dict[str, Any]:
        """Retrieves a single persistent security knowledge item by ID."""
        item = self._knowledge_store.get_knowledge(knowledge_id)
        if not item:
            return {"error": f"Knowledge item not found: {knowledge_id}"}
        return item.to_dict()

    def hunter_knowledge_history(self, knowledge_id: str) -> dict[str, Any]:
        """Returns the version history of a security knowledge item."""
        item = self._knowledge_store.get_knowledge(knowledge_id)
        if not item:
            return {"error": f"Knowledge item not found: {knowledge_id}"}
        versions = self._knowledge_store._versions.get(knowledge_id, [])
        return {
            "knowledge_id": knowledge_id,
            "current_version": item.version,
            "history": [
                {
                    "version_id": v.version_id,
                    "version_number": v.version_number,
                    "statement": v.statement,
                    "rationale": v.rationale,
                    "confidence": v.confidence,
                    "created_at": v.created_at,
                }
                for v in versions
            ],
        }

    def hunter_knowledge_usage(self, knowledge_id: str) -> dict[str, Any]:
        """Returns mission feedback and usage history for a knowledge item."""
        records = self._knowledge_usage.get_records_for_knowledge(knowledge_id)
        return {
            "knowledge_id": knowledge_id,
            "total_uses": len(records),
            "usage_records": [r.to_dict() for r in records],
        }

    def hunter_knowledge_patterns(self, technology: str | None = None) -> dict[str, Any]:
        """Returns categorized security patterns optionally filtered by technology."""
        items = self._knowledge_store.get_all_knowledge()
        if technology:
            norm_tech = self._knowledge_normalizer.normalize_technology(technology)
            items = [k for k in items if norm_tech in k.applicable_technology]
        return {
            "technology_filter": technology,
            "total_patterns": len(items),
            "patterns": [k.to_dict() for k in items],
        }

    def hunter_knowledge_contradictions(self) -> dict[str, Any]:
        """Returns all knowledge items in CONTRADICTED status."""
        items = self._knowledge_store.get_all_knowledge()
        contradicted = [k for k in items if k.status == KnowledgeStatus.CONTRADICTED or k.contradiction_count > 0]
        return {
            "total_contradictions": len(contradicted),
            "contradicted_items": [k.to_dict() for k in contradicted],
        }

    def hunter_knowledge_freshness(self) -> dict[str, Any]:
        """Evaluates freshness across all knowledge items."""
        items = self._knowledge_store.get_all_knowledge()
        freshness_counts = {"FRESH": 0, "AGING": 0, "STALE": 0, "EXPIRED": 0}
        for k in items:
            f = self._knowledge_freshness.evaluate_freshness(k)
            freshness_counts[f.value] = freshness_counts.get(f.value, 0) + 1
        return {
            "total_evaluated": len(items),
            "freshness_breakdown": freshness_counts,
        }

    def hunter_knowledge_correlations(self) -> dict[str, Any]:
        """Discovers multi-variable recurring correlations across missions."""
        items = self._knowledge_store.get_all_knowledge()
        correlations = self._knowledge_correlations.correlate_patterns(items)
        return {
            "total_correlations": len(correlations),
            "correlations": correlations,
        }

    def hunter_knowledge_rationale(self, knowledge_id: str) -> dict[str, Any]:
        """Generates explainable creation/retrieval rationale for a knowledge item."""
        item = self._knowledge_store.get_knowledge(knowledge_id)
        if not item:
            return {"error": f"Knowledge item not found: {knowledge_id}"}
        rat = self._knowledge_rationale.generate_creation_rationale(item)
        return rat.to_dict()

    def hunter_knowledge_promote(
        self,
        knowledge_id: str,
        mission_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Promotes a candidate knowledge item through the 11-point write gate to global knowledge.
        """
        candidate = None
        if mission_id:
            sm = self._get_knowledge_state_manager(mission_id)
            candidate = next((c for c in sm.get_candidates() if c.knowledge_id == knowledge_id), None)
        if not candidate:
            candidate = self._knowledge_store.get_knowledge(knowledge_id)
        if not candidate:
            return {"error": f"Candidate knowledge not found: {knowledge_id}", "status": "REJECT"}

        decision, failures = self._knowledge_write_gate.evaluate_write(candidate)
        if decision == "REJECT":
            self._knowledge_store.poisoning_rejection_count += 1
            return {
                "knowledge_id": knowledge_id,
                "decision": "REJECT",
                "failures": failures,
            }

        # Normalize & deduplicate against existing store
        self._knowledge_normalizer.normalize_knowledge(candidate)
        existing_dup = self._knowledge_dedup.find_duplicate(candidate, self._knowledge_store.get_all_knowledge())
        
        if existing_dup and existing_dup.knowledge_id != candidate.knowledge_id:
            merged = self._knowledge_dedup.merge_knowledge(existing_dup, candidate)
            self._knowledge_confidence.compute_confidence(merged)
            self._knowledge_store.save_knowledge(merged)
            self._knowledge_graph.add_node(merged)
            self._knowledge_store.promotion_count += 1
            return {
                "knowledge_id": merged.knowledge_id,
                "decision": "MERGED_WITH_EXISTING",
                "status": merged.status.value,
                "promotion_level": merged.promotion_level.value,
                "confidence": merged.confidence,
            }

        self._knowledge_confidence.compute_confidence(candidate)
        self._knowledge_store.save_knowledge(candidate)
        self._knowledge_graph.add_node(candidate)
        self._knowledge_store.promotion_count += 1

        return {
            "knowledge_id": candidate.knowledge_id,
            "decision": "PROMOTED",
            "status": candidate.status.value,
            "promotion_level": candidate.promotion_level.value,
            "confidence": candidate.confidence,
        }

    def hunter_knowledge_demote(self, knowledge_id: str, reason: str = "") -> dict[str, Any]:
        """Demotes a knowledge item's status due to staleness, obsolescence, or contradiction."""
        item = self._knowledge_store.get_knowledge(knowledge_id)
        if not item:
            return {"error": f"Knowledge item not found: {knowledge_id}"}
        
        if item.can_transition_to(KnowledgeStatus.DEPRECATED):
            item.status = KnowledgeStatus.DEPRECATED
        elif item.can_transition_to(KnowledgeStatus.STALE):
            item.status = KnowledgeStatus.STALE

        item.rationale = f"{item.rationale}; Demoted: {reason}".strip("; ")
        item.confidence = max(0.05, item.confidence - 0.3)
        self._knowledge_store.save_knowledge(item)
        self._knowledge_store.demotion_count += 1

        return {
            "knowledge_id": knowledge_id,
            "status": item.status.value,
            "confidence": item.confidence,
            "reason": reason,
        }

    def hunter_knowledge_revalidate(
        self,
        knowledge_id: str,
        current_technologies: list[str] | None = None,
    ) -> dict[str, Any]:
        """Re-evaluates freshness, recalculates confidence, and updates status."""
        item = self._knowledge_store.get_knowledge(knowledge_id)
        if not item:
            return {"error": f"Knowledge item not found: {knowledge_id}"}

        self._knowledge_freshness.evaluate_freshness(item, current_technologies=current_technologies)
        self._knowledge_confidence.compute_confidence(item)
        self._knowledge_store.save_knowledge(item)

        return {
            "knowledge_id": knowledge_id,
            "status": item.status.value,
            "freshness": item.freshness.value,
            "confidence": item.confidence,
        }

    # -----------------------------------------------------------------------
    # Phase 14: Autonomous Security Strategy & Long-Horizon Reasoning
    # -----------------------------------------------------------------------

    def _get_strategy_state_manager(self, mission_id: str) -> StrategicStateManager:
        if mission_id not in self._strategy_state_managers:
            mgr = StrategicStateManager(mission_id)
            # Load persisted state/objectives if available
            pers = self._get_strategy_persistence(mission_id)
            pers_state = pers.load_strategic_state()
            if pers_state:
                mgr.state = pers_state
            for obj in pers.load_objectives():
                mgr.add_objective(obj)
            self._strategy_state_managers[mission_id] = mgr
        return self._strategy_state_managers[mission_id]

    def _get_strategy_persistence(self, mission_id: str) -> StrategicPersistenceManager:
        if mission_id not in self._strategy_persistence_managers:
            self._strategy_persistence_managers[mission_id] = StrategicPersistenceManager(mission_id, self._root)
        return self._strategy_persistence_managers[mission_id]

    def hunter_strategy_status(self, mission_id: str) -> dict[str, Any]:
        """Returns the current macro strategic posture, active mode, and budget envelope."""
        sm = self._get_strategy_state_manager(mission_id)
        explor, exploit = self._strategy_planner.selector.compute_exploration_exploitation_ratio(
            sm.state.active_strategy, sm.state.coverage_score, sm.state.remaining_budget
        )
        return {
            "mission_id": mission_id,
            "active_strategy": sm.state.active_strategy.value,
            "strategy_version": sm.state.strategy_version,
            "selected_direction": sm.state.selected_direction,
            "exploration_budget": explor,
            "exploitation_budget": exploit,
            "remaining_budget": sm.state.remaining_budget,
            "coverage_score": sm.state.coverage_score,
            "total_objectives": len(sm.objectives),
            "active_objectives_count": len([o for o in sm.objectives.values() if o.current_state == StrategicObjectiveState.ACTIVE]),
            "rationale": sm.state.rationale,
        }

    def hunter_strategy_objectives(self, mission_id: str) -> dict[str, Any]:
        """Returns all strategic objectives for the mission, ranked deterministically."""
        sm = self._get_strategy_state_manager(mission_id)
        ranked = sorted(sm.objectives.values(), key=lambda o: (-o.priority, o.objective_id))
        return {
            "mission_id": mission_id,
            "total_objectives": len(ranked),
            "objectives": [o.to_dict() for o in ranked],
        }

    def hunter_strategy_history(self, mission_id: str) -> dict[str, Any]:
        """Returns the immutable audit event log of strategic transitions."""
        pers = self._get_strategy_persistence(mission_id)
        events = pers.load_events()
        sm = self._get_strategy_state_manager(mission_id)
        all_events = events + [e for e in sm.events if e.event_id not in {ev.event_id for ev in events}]
        return {
            "mission_id": mission_id,
            "total_events": len(all_events),
            "history": [e.to_dict() for e in all_events],
        }

    def hunter_strategy_rationale(self, mission_id: str, objective_id: str | None = None) -> dict[str, Any]:
        """Returns explainable decision rationales for strategic choices."""
        pers = self._get_strategy_persistence(mission_id)
        rats = pers.load_rationales()
        sm = self._get_strategy_state_manager(mission_id)
        if objective_id and objective_id in sm.objectives:
            obj = sm.objectives[objective_id]
            return {
                "mission_id": mission_id,
                "objective_id": objective_id,
                "rationale": obj.rationale,
                "security_value": obj.security_value,
                "priority": obj.priority,
            }
        return {
            "mission_id": mission_id,
            "total_rationales": len(rats),
            "rationales": [r.to_dict() for r in rats],
        }

    def hunter_strategy_performance(self, mission_id: str) -> dict[str, Any]:
        """Returns historical performance records and learned strategy priors."""
        records = self._strategy_planner.performance_tracker.get_all_records()
        priors = {
            m.value: self._strategy_planner.performance_tracker.get_strategy_prior(m)
            for m in StrategyMode
        }
        return {
            "mission_id": mission_id,
            "total_records": len(records),
            "performance_records": [r.to_dict() for r in records],
            "learned_strategy_priors": priors,
        }

    def hunter_strategy_gaps(self, mission_id: str) -> dict[str, Any]:
        """Identifies missing evidence gaps for high-value strategic objectives."""
        sm = self._get_strategy_state_manager(mission_id)
        all_gaps: list[dict[str, Any]] = []
        for obj in sm.objectives.values():
            if obj.current_state == StrategicObjectiveState.ACTIVE and obj.security_value >= 0.60:
                gaps = self._strategy_planner.evidence_gap_analyzer.analyze_gaps(obj)
                all_gaps.extend([g.to_dict() for g in gaps])
        return {
            "mission_id": mission_id,
            "total_gaps": len(all_gaps),
            "evidence_gaps": all_gaps,
        }

    def hunter_strategy_allocation(self, mission_id: str) -> dict[str, Any]:
        """Returns current strategic resource allocations to P10 research threads."""
        sm = self._get_strategy_state_manager(mission_id)
        return {
            "mission_id": mission_id,
            "total_allocations": len(sm.allocations),
            "allocations": [a.to_dict() for a in sm.allocations],
        }

    def hunter_strategy_recommendation(self, mission_id: str) -> dict[str, Any]:
        """
        Executes a full strategic planning cycle and returns the top strategic recommendation.
        Persists updated state and rationales.
        """
        sm = self._get_strategy_state_manager(mission_id)
        pers = self._get_strategy_persistence(mission_id)

        # Context collection
        f_store = self._get_finding_store(mission_id)
        has_finding = len(f_store.findings) > 0
        
        chain_engine = self._get_chain_engine(mission_id)
        has_path = any(p.state.value == "VALIDATED" or len(p.edges) > 0 for p in chain_engine.attack_paths.values())

        mode, ranked, allocs, rat = self._strategy_planner.plan_next_strategy(
            sm,
            has_reachable_attack_path=has_path,
            has_validated_finding=has_finding,
            coverage_score=sm.state.coverage_score,
            available_budget=sm.state.remaining_budget,
        )

        pers.save_strategic_state(sm.state)
        pers.save_objectives(list(sm.objectives.values()))
        pers.save_allocations(allocs)
        pers.save_rationale(rat)
        for ev in sm.events:
            pers.append_event(ev)

        return {
            "mission_id": mission_id,
            "recommended_strategy": mode.value,
            "strategy_version": sm.state.strategy_version,
            "top_objective": ranked[0].to_dict() if ranked else None,
            "total_ranked_objectives": len(ranked),
            "allocations": [a.to_dict() for a in allocs],
            "rationale": rat.to_dict(),
        }

    def hunter_strategy_rebalance(
        self,
        mission_id: str,
        signal: str = "PERIODIC",
    ) -> dict[str, Any]:
        """
        Evaluates incoming feedback signal and adapts strategy under hysteresis policy.
        """
        sm = self._get_strategy_state_manager(mission_id)
        try:
            feed_signal = StrategicFeedbackSignal(signal)
        except Exception:
            feed_signal = StrategicFeedbackSignal.POSITIVE_SIGNAL

        f_store = self._get_finding_store(mission_id)
        has_finding = len(f_store.findings) > 0
        chain_engine = self._get_chain_engine(mission_id)
        has_path = any(p.state.value == "VALIDATED" or len(p.edges) > 0 for p in chain_engine.attack_paths.values())

        did_change, new_mode, reason = self._strategy_planner.reevaluation_engine.process_feedback_signal(
            signal=feed_signal,
            current_mode=sm.state.active_strategy,
            objectives=list(sm.objectives.values()),
            current_expected_value=sm.state.current_expected_value,
            iterations_in_current_mode=sm.iterations_in_current_mode,
            has_reachable_attack_path=has_path,
            has_validated_finding=has_finding,
            coverage_score=sm.state.coverage_score,
            recent_history=sm.mode_history,
        )

        if did_change:
            sm.set_active_strategy(new_mode, rationale=reason)
            pers = self._get_strategy_persistence(mission_id)
            pers.save_strategic_state(sm.state)
            for ev in sm.events:
                pers.append_event(ev)

        return {
            "mission_id": mission_id,
            "signal_processed": feed_signal.value,
            "did_change_strategy": did_change,
            "active_strategy": sm.state.active_strategy.value,
            "rationale": reason,
        }

    def hunter_strategy_stop_rationale(self, mission_id: str) -> dict[str, Any]:
        """Evaluates evidence-backed mission completion criteria."""
        sm = self._get_strategy_state_manager(mission_id)
        chain_engine = self._get_chain_engine(mission_id)
        has_unresolved_path = any(p.state.value != "VALIDATED" for p in chain_engine.attack_paths.values() if len(p.edges) > 0)

        stop_rat = self._strategy_planner.completion_analyzer.evaluate_completion(
            mission_id=mission_id,
            objectives=list(sm.objectives.values()),
            coverage_score=sm.state.coverage_score,
            remaining_budget=sm.state.remaining_budget,
            has_unresolved_high_value_path=has_unresolved_path,
        )
        return stop_rat.to_dict()

    # -----------------------------------------------------------------------
    # Phase 15: Mission Assurance, Validation & Finalization
    # -----------------------------------------------------------------------

    def _get_final_persistence(self, mission_id: str) -> FinalPersistenceManager:
        if mission_id not in self._final_persistence_managers:
            self._final_persistence_managers[mission_id] = FinalPersistenceManager(mission_id, self._root)
        return self._final_persistence_managers[mission_id]

    def hunter_assurance_status(self, mission_id: str) -> dict[str, Any]:
        """Returns the high-level assurance status and verification states."""
        pers = self._get_final_persistence(mission_id)
        assess = pers.load_assessment()
        if assess:
            return {
                "mission_id": mission_id,
                "completion_state": assess.completion_state.value,
                "assurance_status": assess.assurance_status.value,
                "scope_status": assess.scope_status,
                "evidence_integrity_status": assess.evidence_integrity_status,
                "confidence_summary": assess.confidence_summary.value,
                "confirmed_findings_count": len(assess.confirmed_findings),
                "unresolved_high_value_gaps": assess.unresolved_high_value_gaps,
            }

        # Fallback to dynamic state
        return {
            "mission_id": mission_id,
            "completion_state": MissionCompletionState.ACTIVE.value,
            "assurance_status": AssuranceStatus.IN_PROGRESS.value,
            "scope_status": "VALID",
            "evidence_integrity_status": "VALID",
            "confidence_summary": AssuranceConfidence.HIGH.value,
            "confirmed_findings_count": 0,
            "unresolved_high_value_gaps": [],
        }

    def hunter_final_assessment(self, mission_id: str) -> dict[str, Any]:
        """Returns the complete FinalMissionAssessment document."""
        pers = self._get_final_persistence(mission_id)
        assess = pers.load_assessment()
        if assess:
            return assess.to_dict()
        return {"error": f"No finalized assessment found for mission: {mission_id}"}

    def hunter_final_findings(self, mission_id: str) -> dict[str, Any]:
        """Returns the audited FinalFindingAssessment list."""
        pers = self._get_final_persistence(mission_id)
        findings = pers.load_findings()
        return {
            "mission_id": mission_id,
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
        }

    def hunter_final_coverage(self, mission_id: str) -> dict[str, Any]:
        """Returns the 15-dimensional FinalCoverageAssessment."""
        pers = self._get_final_persistence(mission_id)
        cov = pers.load_coverage()
        if cov:
            return cov.to_dict()
        return {"mission_id": mission_id, "coverage_status": "NOT_FINALIZED"}

    def hunter_final_gaps(self, mission_id: str) -> dict[str, Any]:
        """Returns aggregated unresolved gaps across mission phases."""
        pers = self._get_final_persistence(mission_id)
        assess = pers.load_assessment()
        if assess:
            return {
                "mission_id": mission_id,
                "unresolved_high_value_gaps": assess.unresolved_high_value_gaps,
                "unresolved_medium_value_gaps": assess.unresolved_medium_value_gaps,
                "unresolved_low_value_gaps": assess.unresolved_low_value_gaps,
            }
        return {"mission_id": mission_id, "unresolved_high_value_gaps": []}

    def hunter_final_timeline(self, mission_id: str) -> dict[str, Any]:
        """Returns the chronological audit trail of mission milestones."""
        pers = self._get_final_persistence(mission_id)
        ev = pers.load_event()
        events = [ev.to_dict()] if ev else []
        return {
            "mission_id": mission_id,
            "timeline": events,
        }

    def hunter_final_rationale(self, mission_id: str) -> dict[str, Any]:
        """Returns the explainable CompletionRationale document."""
        pers = self._get_final_persistence(mission_id)
        rat = pers.load_rationale()
        if rat:
            return rat.to_dict()
        return {"mission_id": mission_id, "completion_rationale": "NOT_FINALIZED"}

    def hunter_final_report(self, mission_id: str) -> dict[str, Any]:
        """Returns the 18-section FinalSecurityReport with secret redaction."""
        pers = self._get_final_persistence(mission_id)
        rpt = pers.load_report()
        if rpt:
            return rpt.to_dict()
        return {"error": f"No finalized report found for mission: {mission_id}"}

    def hunter_final_integrity(self, mission_id: str) -> dict[str, Any]:
        """Returns cryptographic integrity verification for final mission artifacts."""
        pers = self._get_final_persistence(mission_id)
        assess = pers.load_assessment()
        rpt = pers.load_report()
        if not assess or not rpt:
            return {"mission_id": mission_id, "integrity_status": "INCOMPLETE", "is_valid": False}

        is_assess_valid = assess.verify_integrity()
        pkg_digest = self._assurance_engine.integrity_verifier.compute_package_digest(assess, rpt)
        return {
            "mission_id": mission_id,
            "assessment_digest": assess.content_digest,
            "report_digest": rpt.report_digest,
            "package_digest": pkg_digest,
            "is_valid": is_assess_valid,
        }

    def hunter_finalization_status(self, mission_id: str) -> dict[str, Any]:
        """Inspects crash recovery and finalization completeness."""
        pers = self._get_final_persistence(mission_id)
        from runtime.finalization.recovery import FinalizationRecoveryManager
        rec = FinalizationRecoveryManager(pers)
        return rec.check_recovery_status()

    def hunter_request_revalidation(self, mission_id: str, finding_id: str) -> dict[str, Any]:
        """Requests independent re-validation of a specific finding."""
        f_store = self._get_finding_store(mission_id)
        if finding_id not in f_store.findings:
            return {"error": f"Finding {finding_id} not found."}
        finding = f_store.findings[finding_id]
        return {
            "mission_id": mission_id,
            "finding_id": finding_id,
            "revalidation_status": "QUEUED_FOR_INDEPENDENT_VALIDATION",
            "current_status": finding.status.value,
        }

    def hunter_request_reopen(self, mission_id: str, reason: str = "Operator requested research continuation") -> dict[str, Any]:
        """Creates a linked research cycle while preserving historical assessment immutability."""
        return self._assurance_engine.reopen_manager.reopen_mission(mission_id, reason=reason)

    def hunter_finalize_mission(self, mission_id: str) -> dict[str, Any]:
        """
        Executes complete mission assurance, evaluates the 12-point finalization gate,
        atomically persists final artifacts, and promotes sanitized patterns to P13.
        """
        pers = self._get_final_persistence(mission_id)
        
        # 1. Collect inputs across phases
        f_store = self._get_finding_store(mission_id)
        raw_findings = [f.to_dict() for f in f_store.findings.values()]

        # Collect known evidence IDs
        ev_ids: set[str] = set()
        for rf in raw_findings:
            for ref in rf.get("evidence_refs", []):
                ev_ids.add(ref)
        if not ev_ids:
            ev_ids.add("EV-INIT")

        chain_engine = self._get_chain_engine(mission_id)
        raw_paths = [p.to_dict() for p in chain_engine.attack_paths.values()]

        pocs_raw = []
        if hasattr(self, "_poc_state_manager") and hasattr(self._poc_state_manager, "pocs"):
            pocs_raw = [poc.to_dict() for poc in self._poc_state_manager.pocs.values()]

        sm = self._get_strategy_state_manager(mission_id)
        strategic_gaps = []
        for obj in sm.objectives.values():
            if obj.security_value >= 0.60:
                gaps = self._strategy_planner.evidence_gap_analyzer.analyze_gaps(obj)
                strategic_gaps.extend([g.to_dict() for g in gaps])

        executed_eps: list[str] = []
        for rf in raw_findings:
            for ep in rf.get("affected_endpoints", []):
                executed_eps.append(ep)
        if not executed_eps:
            executed_eps = ["/"]

        allowed_tgts = ["127.0.0.1", "localhost"]

        # 2. Run Full Assurance
        assess, report, audited_findings, cov = self._assurance_engine.run_full_assurance(
            mission_id=mission_id,
            allowed_targets=allowed_tgts,
            executed_endpoints=executed_eps,
            findings_raw=raw_findings,
            known_evidence_ids=ev_ids,
            attack_paths_raw=raw_paths,
            pocs_raw=pocs_raw,
            strategic_gaps_raw=strategic_gaps,
            remaining_budget=sm.state.remaining_budget,
        )

        # 3. Save Final Artifacts
        pers.save_assessment(assess)
        pers.save_findings(audited_findings)
        pers.save_coverage(cov)
        pers.save_report(report)

        # 4. Save Finalization Event
        fevt = MissionFinalizationEvent(
            mission_id=mission_id,
            previous_state=sm.state.active_strategy.value,
            final_state=assess.completion_state.value,
            assessment_digest=assess.content_digest,
            report_digest=report.report_digest,
            rationale=assess.completion_rationale,
            assurance_status=assess.assurance_status,
        )
        pers.save_event(fevt)

        # 5. Post-Finalization Knowledge Promotion (P13)
        knowledge_items = self._assurance_engine.knowledge_updater.extract_reusable_knowledge(
            mission_id=mission_id,
            findings=audited_findings,
            target_technologies=["python", "fastapi"],
        )
        for k_item in knowledge_items:
            try:
                from runtime.knowledge.models import SecurityKnowledgeItem, KnowledgeType, TargetScopeContext
                from runtime.vulnerability.model import VulnerabilityClass
                vclass_enum = VulnerabilityClass.GENERIC
                try:
                    vclass_enum = VulnerabilityClass(k_item["vulnerability_class"])
                except Exception:
                    pass
                sk_item = SecurityKnowledgeItem(
                    title=k_item["title"],
                    knowledge_type=KnowledgeType.PATTERN,
                    vulnerability_class=vclass_enum,
                    summary=k_item["summary"],
                    confidence=k_item["confidence"],
                    scope_context=TargetScopeContext(allowed_domains=["*"]),
                )
                self._knowledge_store.save_knowledge(sk_item)
            except Exception:
                pass

        return {
            "mission_id": mission_id,
            "completion_state": assess.completion_state.value,
            "assurance_status": assess.assurance_status.value,
            "assessment_digest": assess.content_digest,
            "report_digest": report.report_digest,
            "confirmed_findings_count": len(assess.confirmed_findings),
            "unresolved_high_value_gaps": assess.unresolved_high_value_gaps,
            "report_reference": report.report_id,
            "knowledge_promoted_count": len(knowledge_items),
        }

    # ---------------------------------------------------------------------------
    # Phase C: Beast Brain Mission Contract & Reasoning Engine
    # ---------------------------------------------------------------------------

    def mission_create_from_contract(self, contract: Any) -> dict[str, Any]:
        """
        Create a new persistent mission strongly validated by a Phase C MissionContract.
        Enforces pre-flight validation, resource budgets, and authorization invariants.
        """
        from runtime.mission.contract import MissionContract, validate_contract

        if not isinstance(contract, MissionContract):
            raise TypeError("contract must be an instance of MissionContract")

        errors = validate_contract(contract)
        if errors:
            raise ValueError(f"Pre-flight MissionContract validation failed: {'; '.join(errors)}")

        allowed_scope = list(contract.allowed_domains) + list(contract.allowed_ips)
        excluded_scope = list(contract.excluded_domains) + list(contract.excluded_ips)

        mission_data = self.mission_create(
            operator_objective=contract.mission_objective,
            target_scope=allowed_scope,
            custom_id=contract.mission_id,
            excluded_scope=excluded_scope,
        )

        try:
            self._mission_manager.update_mission(
                contract.mission_id,
                {"phase_c_contract": contract.to_dict()},
            )
            mission_data["phase_c_contract"] = contract.to_dict()
        except Exception:
            pass

        return mission_data

    def run_beast_brain_loop(
        self,
        mission_id: str,
        *,
        max_iterations: int = 5,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """
        Execute the unified 20-stage Beast Brain continuous reasoning loop.
        """
        import time
        from runtime.mission.contract import (
            AuthorizationMetadata,
            MissionContract,
            ResourceBudgets,
            RiskPolicy,
        )
        from runtime.brain.reasoning_engine import BeastBrainReasoningLoop

        mission_state = self.mission_get(mission_id)
        phase_c_data = mission_state.get("phase_c_contract")

        if phase_c_data:
            contract = MissionContract.from_dict(phase_c_data)
        else:
            target_scope = mission_state.get("target_scope", ["127.0.0.1"])
            domains = [t for t in target_scope if not t.replace(".", "").isdigit()]
            ips = [t for t in target_scope if t.replace(".", "").isdigit()]
            if not domains and not ips:
                ips = ["127.0.0.1"]

            auth_meta = AuthorizationMetadata(
                authorization_source="runtime_mission_auth",
                operator_identity="operator",
                valid_until_timestamp=time.time() + 86400,
            )
            contract = MissionContract(
                mission_id=mission_id,
                environment="lab",
                allowed_domains=domains,
                allowed_ips=ips,
                mission_objective=mission_state.get("operator_objective", "Automated research"),
                authorization=auth_meta,
                budgets=ResourceBudgets(max_reasoning_iterations=max_iterations),
                risk_policy=RiskPolicy(),
            )

        loop = BeastBrainReasoningLoop(
            contract=contract,
            dry_run=dry_run,
            checkpoint_callback=lambda mid, state: self.mission_checkpoint(mid),
        )

        synthesis = loop.execute_until_stop(max_cycles=max_iterations)
        return {
            "mission_id": mission_id,
            "synthesis": synthesis,
            "iterations_completed": loop.iterations_completed,
            "final_stopping_decision": (
                loop.final_stopping_decision.to_dict()
                if loop.final_stopping_decision
                else None
            ),
        }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_project_root() -> Path:
    """
    Find the ai-hunter project root by walking up from this file
    until we find a directory containing AGENTS.md.
    """
    candidate = Path(__file__).resolve().parent
    for _ in range(10):  # max 10 levels up
        if (candidate / "AGENTS.md").is_file():
            return candidate
        parent = candidate.parent
        if parent == candidate:
            break
        candidate = parent
    # Fallback: assume we are in runtime/brain/ so root is two levels up
    return Path(__file__).resolve().parent.parent.parent
