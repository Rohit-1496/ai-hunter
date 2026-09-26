"""Runtime scope management package."""

from runtime.scope.authorization import (
    AUTH_POLICY_VERSION,
    AuthStatus,
    AuthVerdict,
    AuthorizationContext,
    AuthorizationGate,
)
from runtime.scope.decision import (
    ScopeDecision,
    ScopeVerdict,
    UNTRUSTED_PROPOSAL_FIELDS,
    redact_target_for_log,
    strip_untrusted_proposal_fields,
)
from runtime.scope.authz_provider import (
    AuthMode,
    AuthorizationProvider,
    FileSignedAuthorizationProvider,
    ProviderStatus,
    UnavailableAuthorizationProvider,
    build_provider_config,
    evaluate_external_authorization,
    resolve_auth_mode,
)
from runtime.scope.resolver import ScopeResolver

__all__ = [
    "AUTH_POLICY_VERSION",
    "AuthStatus",
    "AuthVerdict",
    "AuthorizationContext",
    "AuthorizationGate",
    "AuthMode",
    "AuthorizationProvider",
    "FileSignedAuthorizationProvider",
    "ProviderStatus",
    "UnavailableAuthorizationProvider",
    "build_provider_config",
    "evaluate_external_authorization",
    "resolve_auth_mode",
    "ScopeDecision",
    "ScopeVerdict",
    "ScopeResolver",
    "UNTRUSTED_PROPOSAL_FIELDS",
    "redact_target_for_log",
    "strip_untrusted_proposal_fields",
]
