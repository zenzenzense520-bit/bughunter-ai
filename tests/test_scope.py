"""ScopeGuard decision tests."""

import pytest
from sqlmodel import select

from bughunter.core.enums import ScopeKind, ScopeRuleType
from bughunter.core.errors import ScopeViolationError
from bughunter.core.models import ScopeEntry
from bughunter.core.scope import ScopeGuard


def entries_for(session, target_id: int) -> list[ScopeEntry]:
    return list(
        session.exec(
            select(ScopeEntry).where(ScopeEntry.target_id == target_id)
        ).all()
    )


def test_exact_host_and_port_allowed(factories, session):
    t = factories.target()
    factories.include_host(t.id, "127.0.0.1")
    factories.include_suffix(t.id, "example.com")
    factories.exclude_path(t.id, r"^/admin")
    g = ScopeGuard(entries_for(session, t.id))
    assert g.check("http://127.0.0.1:3000/#/login")[0] is True
    assert g.check("https://example.com/search?q=1")[0] is True


def test_bounded_suffix_blocks_lookalike_domain(factories, session):
    t = factories.target()
    factories.include_suffix(t.id, "example.com")
    g = ScopeGuard(entries_for(session, t.id))
    assert g.check("http://api.example.com/path")[0] is True
    allowed, reason = g.check("http://evil-example.com/")
    assert allowed is False
    assert "scope" in reason


def test_bare_ip_unregistered_is_rejected(factories, session):
    t = factories.target()
    factories.include_suffix(t.id, "example.com")
    g = ScopeGuard(entries_for(session, t.id))
    allowed, reason = g.check("http://8.8.8.8/")
    assert allowed is False
    assert "IP" in reason or "scope" in reason


def test_ip_exact_registration_allows_only_that_ip(factories, session):
    t = factories.target()
    factories.include_host(t.id, "127.0.0.1")
    g = ScopeGuard(entries_for(session, t.id))
    assert g.check("http://127.0.0.1:3000/")[0] is True
    assert g.check("http://localhost:3000/")[0] is False


def test_ip_suffix_rule_is_rejected_by_validation_logic(factories, session):
    # Even if a malformed IP suffix row exists, IPs can only match host rules.
    t = factories.target()
    broken = ScopeEntry(
        target_id=t.id,
        kind=ScopeKind.INCLUDE.value,
        rule_type=ScopeRuleType.HOST_SUFFIX.value,
        value="0.0.1",
    )
    session.add(broken)
    session.flush()
    g = ScopeGuard(entries_for(session, t.id))
    assert g.check("http://127.0.0.1/")[0] is False


def test_exclude_path_regex_blocks(factories, session):
    t = factories.target()
    factories.include_suffix(t.id, "example.com")
    factories.exclude_path(t.id, r"^/admin")
    g = ScopeGuard(entries_for(session, t.id))
    allowed, reason = g.check("https://example.com/admin/users")
    assert allowed is False
    assert "排除" in reason
    assert g.check("https://example.com/login")[0] is True


def test_scheme_userinfo_required(factories, session):
    t = factories.target()
    factories.include_host(t.id, "127.0.0.1")
    factories.include_suffix(t.id, "example.com")
    g = ScopeGuard(entries_for(session, t.id))
    assert g.check("ftp://example.com/")[0] is False
    assert g.check("http://user:pass@127.0.0.1/")[0] is False
    assert g.check("http:///path")[0] is False


def test_empty_scope_rejects_everything(factories, session):
    factories.target()
    g = ScopeGuard([])
    assert g.check("http://127.0.0.1/")[0] is False


def test_assert_raises_typed_error(factories, session):
    t = factories.target()
    factories.include_host(t.id, "127.0.0.1")
    g = ScopeGuard(entries_for(session, t.id))
    g.assert_url_allowed("http://127.0.0.1/")
    with pytest.raises(ScopeViolationError):
        g.assert_url_allowed("http://out-of-scope.test/")
