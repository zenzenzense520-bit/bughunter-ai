"""End-to-end ScanService tests with a fake runner (no Docker)."""

import json
from pathlib import Path

import pytest
from sqlmodel import select

from bughunter.core.enums import (
    FindingStatus,
    ScanStatus,
    TaskStatus,
)
from bughunter.core.errors import AuthorizationError, ScannerError, ScopeViolationError
from bughunter.core.models import Finding, Scan, Task
from bughunter.scanners.normalize import normalize_semgrep
from bughunter.scanners.service import ScanService, validate_code_path


class FakeRunner:
    def __init__(self, sample_text: str, fail: bool = False):
        self.sample_text = sample_text
        self.fail = fail
        self.calls: list[Path] = []

    def run(self, code_path: Path):
        self.calls.append(code_path)
        if self.fail:
            raise ScannerError("simulated runner failure")
        return normalize_semgrep(self.sample_text)


def _service(session, config, monkeypatch, sample_text, *, fail=False):
    service = ScanService(session, config, actor="tester")
    fake = FakeRunner(sample_text, fail=fail)
    monkeypatch.setattr(service, "_build_runner", lambda: fake)
    return service, fake


def _code_dir(tmp_path):
    code_dir = tmp_path / "project"
    code_dir.mkdir()
    return code_dir


def test_sast_creates_task_scan_findings_and_raw(
    session, factories, sast_config, conftest_sample, monkeypatch, tmp_path
):
    target = factories.active_target()
    code_dir = _code_dir(tmp_path)
    service, fake = _service(session, sast_config, monkeypatch, conftest_sample)

    outcome = service.run_sast(target.id, code_dir)

    assert fake.calls == [code_dir.resolve()]
    assert outcome.new_count == 2
    assert outcome.duplicate_count == 0

    task = session.exec(select(Task)).one()
    assert task.status == TaskStatus.COMPLETED.value
    params = json.loads(task.params_json)
    assert Path(params["path"]) == code_dir.resolve()
    assert params["backend"] == "docker"
    assert params["network"] == "none"

    scan = session.exec(select(Scan)).one()
    assert scan.status == ScanStatus.COMPLETED.value
    assert scan.tool_version == "1.120.0"
    assert scan.findings_count == 2
    assert Path(scan.raw_report_path).exists()

    findings = session.exec(select(Finding)).all()
    assert len(findings) == 2
    assert all(f.status == FindingStatus.NEW.value for f in findings)
    assert {f.cwe_id for f in findings} == {"CWE-95", "CWE-295"}


def test_second_run_folds_duplicates(
    session, factories, sast_config, conftest_sample, monkeypatch, tmp_path
):
    target = factories.active_target()
    code_dir = _code_dir(tmp_path)
    service, _ = _service(session, sast_config, monkeypatch, conftest_sample)

    first = service.run_sast(target.id, code_dir)
    second = service.run_sast(target.id, code_dir)

    assert first.new_count == 2
    assert second.new_count == 0
    assert second.duplicate_count == 2
    assert len(session.exec(select(Finding)).all()) == 2  # no duplicate rows


def test_sast_blocked_without_authorization(
    session, factories, sast_config, conftest_sample, monkeypatch, tmp_path
):
    target = factories.target(name="draft")  # no authz, no scope
    code_dir = _code_dir(tmp_path)
    service, fake = _service(session, sast_config, monkeypatch, conftest_sample)

    with pytest.raises(AuthorizationError):
        service.run_sast(target.id, code_dir)
    assert fake.calls == []  # scanner never invoked
    assert session.exec(select(Scan)).all() == []


def test_runner_failure_persists_failed_scan(
    session, factories, sast_config, conftest_sample, monkeypatch, tmp_path
):
    target = factories.active_target()
    code_dir = _code_dir(tmp_path)
    service, _ = _service(session, sast_config, monkeypatch, conftest_sample, fail=True)

    with pytest.raises(ScannerError):
        service.run_sast(target.id, code_dir)

    scan = session.exec(select(Scan)).one()
    assert scan.status == ScanStatus.FAILED.value
    assert "simulated runner failure" in scan.error_message
    task = session.exec(select(Task)).one()
    assert task.status == TaskStatus.FAILED.value


def test_validate_code_path_rejects_relative_and_root(tmp_path):
    with pytest.raises(ScopeViolationError):
        validate_code_path("relative/path")
    missing = tmp_path / "missing"
    with pytest.raises(ScopeViolationError):
        validate_code_path(str(missing))
    with pytest.raises(ScopeViolationError):
        validate_code_path(Path(Path("/").anchor))
