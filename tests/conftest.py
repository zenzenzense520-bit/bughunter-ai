"""Shared fixtures: isolated temp database and object factories."""

from datetime import timedelta

import pytest

from bughunter.app import container
from bughunter.core.db import session_scope
from bughunter.core.enums import ScopeKind, ScopeRuleType
from bughunter.core.models import Authorization, ScopeEntry, Target, utcnow


@pytest.fixture
def engine(tmp_path, monkeypatch):
    monkeypatch.setenv("BUGHUNTER_GENERAL__HOME", str(tmp_path / "data"))
    monkeypatch.setenv("BUGHUNTER_GENERAL__LOG_DIR", str(tmp_path / "logs"))
    container.reset_cache()
    eng = container.get_engine()
    yield eng
    container.reset_cache()


@pytest.fixture
def session(engine):
    with session_scope(engine) as s:
        yield s


@pytest.fixture
def factories(session):
    class Factory:
        def target(self, name: str = "lab", status: str = "draft") -> Target:
            t = Target(name=name, status=status)
            session.add(t)
            session.flush()
            return t

        def authz(self, target_id: int, confirmed: bool = False, days: int = 7) -> Authorization:
            now = utcnow()
            a = Authorization(
                target_id=target_id,
                source="local-lab",
                scope_ref="n/a",
                grantor="self",
                valid_from=now - timedelta(days=1),
                valid_to=now + timedelta(days=days),
                confirmed_by="tester" if confirmed else None,
                confirmed_at=now if confirmed else None,
            )
            session.add(a)
            session.flush()
            return a

        def scope(self, target_id: int, kind: str, rule_type: str, value: str) -> ScopeEntry:
            s = ScopeEntry(target_id=target_id, kind=kind, rule_type=rule_type, value=value)
            session.add(s)
            session.flush()
            return s

        def include_host(self, target_id: int, value: str) -> ScopeEntry:
            return self.scope(target_id, ScopeKind.INCLUDE.value, ScopeRuleType.HOST.value, value)

        def include_suffix(self, target_id: int, value: str) -> ScopeEntry:
            return self.scope(
                target_id, ScopeKind.INCLUDE.value, ScopeRuleType.HOST_SUFFIX.value, value
            )

        def exclude_path(self, target_id: int, regex: str) -> ScopeEntry:
            return self.scope(
                target_id, ScopeKind.EXCLUDE.value, ScopeRuleType.PATH_REGEX.value, regex
            )

    return Factory()
