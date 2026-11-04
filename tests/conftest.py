"""Shared fixtures: isolated temp database, factories, docker gate."""

from datetime import timedelta
from pathlib import Path

import pytest

from bughunter.app import container
from bughunter.core.enums import ScopeKind, ScopeRuleType
from bughunter.core.models import Authorization, ScopeEntry, Target, session_scope, utcnow

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VULN_APP = PROJECT_ROOT / "tests" / "fixtures" / "vuln_app"
SEMGREP_RULES = PROJECT_ROOT / "assets" / "rules" / "semgrep"
SAMPLE_REPORT = PROJECT_ROOT / "tests" / "fixtures" / "semgrep_sample.json"


def pytest_addoption(parser):
    parser.addoption(
        "--run-docker",
        action="store_true",
        default=False,
        help="run integration tests that require Docker images",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-docker"):
        return
    skip_docker = pytest.mark.skip(reason="needs --run-docker and a pulled image")
    for item in items:
        if "docker" in item.keywords:
            item.add_marker(skip_docker)


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
def conftest_sample():
    """Text of the bundled desensitized Semgrep sample report."""
    return SAMPLE_REPORT.read_text(encoding="utf-8")


@pytest.fixture
def semgrep_rules_dir():
    return SEMGREP_RULES


@pytest.fixture
def sast_config(tmp_path):
    from bughunter.scanners.service import SastConfig

    return SastConfig(
        image="semgrep/semgrep:test",
        rules_dir=SEMGREP_RULES,
        raw_dir=tmp_path / "raw",
        mem_limit_mb=512,
        timeout_sec=60,
        extra_configs=(),
    )


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

        def active_target(self, name: str = "lab", host: str = "127.0.0.1") -> Target:
            """Target with confirmed in-date authorization and an include scope."""
            target = self.target(name=name, status="active")
            self.authz(target.id, confirmed=True)
            self.include_host(target.id, host)
            return target

    return Factory()
