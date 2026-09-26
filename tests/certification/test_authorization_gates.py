"""
Level 5 Certification — Phase R Unit Tests: Authorization Gates

Tests:
- Missing authorization -> deny
- Expired authorization -> deny
- Out-of-scope target -> deny
- Excluded asset -> deny
- Prohibited action -> deny
- Tampered authorization hash -> deny
- Fail-closed semantics
"""

import pytest
from runtime.validation.certification.authorization import AuthorizationGate
from runtime.validation.certification.models import AuthorizationRecord


@pytest.fixture
def base_auth():
    record = AuthorizationRecord(
        target_identifier="TARGET-TEST",
        authorized_by="Lead Security Auditor",
        authorization_reference="AUTH-TEST-2026",
        authorization_timestamp="2026-01-01T00:00:00Z",
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2026-12-31T23:59:59Z",
        in_scope_assets=["127.0.0.1:8080", "test.example.com"],
        excluded_assets=["127.0.0.1:8080/admin/reset", "internal.test.example.com"],
        permitted_testing=["GET", "POST", "IDOR testing", "PASSIVE_RECONNAISSANCE"],
        prohibited_testing=["Denial of service", "DROP TABLE", "Destructive"],
    )
    record.authorization_hash = record.compute_hash()
    return record


def test_missing_authorization_denied():
    gate = AuthorizationGate()
    ok, msg = gate.authorize_target(auth=None, target="http://127.0.0.1:8080")
    assert not ok
    assert "missing" in msg.lower()


def test_expired_authorization_denied(base_auth):
    base_auth.valid_until = "2020-01-01T00:00:00Z"
    base_auth.authorization_hash = base_auth.compute_hash()
    gate = AuthorizationGate(base_auth)
    ok, errs = gate.is_authorized("http://127.0.0.1:8080")
    assert not ok
    assert any("expired" in e.lower() for e in errs)


def test_out_of_scope_target_denied(base_auth):
    gate = AuthorizationGate(base_auth)
    ok, errs = gate.is_authorized("http://malicious.corp.net/api")
    assert not ok
    assert any("outside authorized in_scope_assets" in e.lower() for e in errs)


def test_excluded_asset_path_denied(base_auth):
    gate = AuthorizationGate(base_auth)
    # Excluded path: /admin/reset
    ok, errs = gate.is_authorized("http://127.0.0.1:8080/admin/reset")
    assert not ok
    assert any("excluded_assets" in e.lower() for e in errs)


def test_excluded_subdomain_denied(base_auth):
    gate = AuthorizationGate(base_auth)
    # Excluded asset: internal.test.example.com
    ok, errs = gate.is_authorized("http://internal.test.example.com/api")
    assert not ok
    assert any("excluded_assets" in e.lower() for e in errs)


def test_permitted_asset_and_action_authorized(base_auth):
    gate = AuthorizationGate(base_auth)
    ok, errs = gate.is_authorized("http://127.0.0.1:8080/api/users", requested_action="IDOR testing")
    assert ok
    assert len(errs) == 0


def test_prohibited_action_denied(base_auth):
    gate = AuthorizationGate(base_auth)
    ok, errs = gate.is_authorized("http://127.0.0.1:8080/api/users", requested_action="Denial of service attack")
    assert not ok
    assert any("violates prohibition" in e.lower() for e in errs)


def test_unpermitted_action_denied(base_auth):
    gate = AuthorizationGate(base_auth)
    ok, errs = gate.is_authorized("http://127.0.0.1:8080/api/users", requested_action="UNREGISTERED_EXPLOIT")
    assert not ok
    assert any("not in permitted_testing" in e.lower() for e in errs)


def test_tampered_authorization_record_denied(base_auth):
    gate = AuthorizationGate(base_auth)
    # Mutate in_scope_assets without recalculating hash
    base_auth.in_scope_assets.append("unauthorized-site.com")
    ok, errs = gate.is_authorized("http://unauthorized-site.com")
    assert not ok
    assert any("hash mismatch" in e.lower() for e in errs)


def test_mid_run_authorization_mutation_denied(base_auth):
    gate = AuthorizationGate(base_auth)
    run_id = "RUN-TEST-01"
    gate.lock_authorization(run_id, base_auth)

    # Mutate and rehash
    base_auth.in_scope_assets.append("tampered.com")
    base_auth.authorization_hash = base_auth.compute_hash()

    ok, msg = gate.authorize_target(auth=base_auth, target="http://tampered.com", run_id=run_id)
    assert not ok
    assert "mutated mid-run" in msg.lower()
