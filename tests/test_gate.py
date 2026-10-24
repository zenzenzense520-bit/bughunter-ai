"""AuthorizationGate tests."""

from datetime import datetime, timedelta, timezone

import pytest

from bughunter.core.enums import TargetStatus
from bughunter.core.errors import AuthorizationError
from bughunter.core.gate import AuthorizationGate

NOW = datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc)


def test_unknown_target_rejected(factories, session):
    with pytest.raises(AuthorizationError):
        AuthorizationGate(session).assert_active(999, now=NOW)


def test_draft_without_authorization_rejected(factories, session):
    t = factories.target()
    with pytest.raises(AuthorizationError):
        AuthorizationGate(session).assert_active(t.id, now=NOW)


def test_unconfirmed_authorization_rejected(factories, session):
    t = factories.target()
    factories.authz(t.id, confirmed=False)
    with pytest.raises(AuthorizationError):
        AuthorizationGate(session).assert_active(t.id, now=NOW)


def test_confirmed_in_date_authorization_active(factories, session):
    t = factories.target()
    factories.authz(t.id, confirmed=True)
    out = AuthorizationGate(session).assert_active(t.id, now=NOW)
    assert out.id == t.id
    assert out.status == TargetStatus.DRAFT.value  # gate does not flip status itself


def test_expired_authorization_rejected(factories, session):
    t = factories.target()
    a = factories.authz(t.id, confirmed=True)
    a.valid_to = NOW - timedelta(days=1)
    session.add(a)
    session.flush()
    with pytest.raises(AuthorizationError, match="过期"):
        AuthorizationGate(session).assert_active(t.id, now=NOW)


def test_not_yet_valid_authorization_rejected(factories, session):
    t = factories.target()
    a = factories.authz(t.id, confirmed=True)
    a.valid_from = NOW + timedelta(days=1)
    a.valid_to = NOW + timedelta(days=10)
    session.add(a)
    session.flush()
    with pytest.raises(AuthorizationError, match="尚未生效"):
        AuthorizationGate(session).assert_active(t.id, now=NOW)


def test_archived_target_rejected(factories, session):
    t = factories.target(status=TargetStatus.ARCHIVED.value)
    factories.authz(t.id, confirmed=True)
    with pytest.raises(AuthorizationError, match="归档"):
        AuthorizationGate(session).assert_active(t.id, now=NOW)


def test_ready_for_scan_requires_include_scope(factories, session):
    t = factories.target()
    factories.authz(t.id, confirmed=True)
    with pytest.raises(AuthorizationError, match="include"):
        AuthorizationGate(session).assert_ready_for_scan(t.id, now=NOW)
    factories.include_host(t.id, "127.0.0.1")
    ready = AuthorizationGate(session).assert_ready_for_scan(t.id, now=NOW)
    assert ready.id == t.id
