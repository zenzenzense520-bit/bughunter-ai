"""Offline triage rules, persistence, lifecycle, and optional enhancer tests."""

import pytest

from bughunter.analysis.triage import (
    FalsePositiveRisk,
    RuleBasedTriager,
    RuleType,
    TriagePriority,
    TriageResult,
    TriageService,
)
from bughunter.core.enums import AuditAction, FindingStatus
from bughunter.core.errors import IllegalTransitionError
from bughunter.core.models import (
    AuditLog,
    Finding,
    Scan,
    Task,
    TriageRecord,
)
from sqlmodel import select


def _finding(session, factories, **overrides):
    target = factories.active_target()
    assert target.id is not None
    task = Task(target_id=target.id)
    session.add(task)
    session.flush()
    assert task.id is not None
    scan = Scan(task_id=task.id, target_id=target.id)
    session.add(scan)
    session.flush()
    assert scan.id is not None
    values = {
        "target_id": target.id,
        "scan_id": scan.id,
        "dedup_key": "test-key",
        "title": "Potential SQL injection",
        "severity": "high",
        "rule_id": "bughunter.python.sql-string-concat",
        "file_path": "src/app.py",
        "line": 12,
        "message": "Dynamic SQL query",
        "cwe_id": "CWE-89",
    }
    values.update(overrides)
    finding = Finding(**values)
    session.add(finding)
    session.flush()
    assert finding.id is not None
    return finding


def test_rule_triage_is_deterministic_and_uses_security_signals(
    session, factories
):
    finding = _finding(session, factories)
    triager = RuleBasedTriager()

    first = triager.triage(finding)
    second = triager.triage(finding)

    assert first == second
    assert first.provider == "rules"
    assert first.rule_type == RuleType.INJECTION
    assert first.priority == TriagePriority.P1
    assert first.confidence == 0.9
    assert first.false_positive_risk == FalsePositiveRisk.LOW
    assert first.human_verification_checklist


def test_test_dependency_and_sample_paths_raise_fp_risk_and_lower_priority(
    session, factories
):
    finding = _finding(
        session,
        factories,
        file_path=r"tests\node_modules\vendor\example_test.py",
    )

    result = RuleBasedTriager().triage(finding)

    assert result.is_test_file
    assert result.is_dependency_file
    assert result.false_positive_risk == FalsePositiveRisk.HIGH
    assert result.priority == TriagePriority.P2
    assert any("fixture" in step or "测试" in step for step in result.human_verification_checklist)


def test_cwe_22_is_classified_as_path_traversal(session, factories):
    finding = _finding(
        session,
        factories,
        title="Path traversal",
        rule_id="security.path-traversal",
        cwe_id="CWE-22",
    )

    result = RuleBasedTriager().triage(finding)

    assert result.rule_type == RuleType.PATH_TRAVERSAL
    assert any("目录边界" in step for step in result.human_verification_checklist)


def test_triage_persists_result_and_routes_finding_to_review(session, factories):
    finding = _finding(session, factories)
    assert finding.id is not None

    result = TriageService(session, actor="tester").triage_finding(finding.id)

    session.refresh(finding)
    record = session.exec(select(TriageRecord)).one()
    audit = session.exec(
        select(AuditLog).where(AuditLog.action == AuditAction.FINDING_TRIAGED.value)
    ).one()
    stored = TriageResult.model_validate_json(record.result_json)
    assert finding.status == FindingStatus.PENDING_REVIEW.value
    assert record.provider == "rules"
    assert stored == result
    assert audit.actor == "tester"

    queue = TriageService(session).review_queue(finding.target_id)
    assert len(queue) == 1
    assert queue[0][0].id == finding.id
    assert queue[0][1] == result


def test_enhancer_is_optional_and_can_identify_its_provider(session, factories):
    finding = _finding(session, factories)
    assert finding.id is not None

    class TestEnhancer:
        def enhance(self, finding, result):
            _ = finding
            return result.model_copy(update={"provider": "test-enhancer"})

    result = TriageService(
        session, enhancer=TestEnhancer()
    ).triage_finding(finding.id)

    assert result.provider == "test-enhancer"
    assert session.exec(select(TriageRecord)).one().provider == "test-enhancer"


def test_enhancer_failure_is_audited_and_marks_triage_failed(session, factories):
    finding = _finding(session, factories)
    assert finding.id is not None

    class BrokenEnhancer:
        def enhance(self, finding, result):
            _ = finding, result
            raise RuntimeError("enhancer unavailable")

    with pytest.raises(RuntimeError, match="enhancer unavailable"):
        TriageService(session, enhancer=BrokenEnhancer()).triage_finding(finding.id)

    session.refresh(finding)
    failure = session.exec(
        select(AuditLog).where(AuditLog.action == AuditAction.TRIAGE_FAILED.value)
    ).one()
    rule_result = session.exec(select(TriageRecord)).one()
    assert finding.status == FindingStatus.TRIAGE_FAILED.value
    assert "enhancer unavailable" in failure.detail_json
    assert rule_result.provider == "rules"
    assert TriageResult.model_validate_json(rule_result.result_json).provider == "rules"


def test_failed_enhancement_can_be_explicitly_skipped_to_review(session, factories):
    finding = _finding(session, factories)
    assert finding.id is not None

    class BrokenEnhancer:
        def enhance(self, finding, result):
            _ = finding, result
            raise RuntimeError("enhancer unavailable")

    service = TriageService(session, enhancer=BrokenEnhancer())
    with pytest.raises(RuntimeError, match="enhancer unavailable"):
        service.triage_finding(finding.id)

    service.skip_failed(finding.id)

    session.refresh(finding)
    skipped = session.exec(
        select(AuditLog).where(AuditLog.action == AuditAction.TRIAGE_SKIPPED.value)
    ).one()
    review_result = service.review_queue(finding.target_id)[0][1]
    assert finding.status == FindingStatus.PENDING_REVIEW.value
    assert skipped.actor == "local"
    assert review_result is not None
    assert review_result.provider == "rules"


def test_finding_cannot_be_triaged_twice_without_a_transition(session, factories):
    finding = _finding(session, factories)
    assert finding.id is not None
    service = TriageService(session)
    service.triage_finding(finding.id)

    with pytest.raises(IllegalTransitionError):
        service.triage_finding(finding.id)
