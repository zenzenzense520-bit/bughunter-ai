"""Deterministic, offline finding triage with an optional enrichment hook."""

import re
from enum import Enum
from pathlib import PurePosixPath
from typing import Protocol

from pydantic import BaseModel, Field
from sqlalchemy import inspect, or_
from sqlmodel import Session, select

from ..core.enums import AuditAction, FindingStatus, Severity
from ..core.errors import FindingNotFoundError, IllegalTransitionError
from ..core.models import Finding, TriageRecord
from ..core.state import assert_transition
from ..infra.audit import AuditLogger


class TriagePriority(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class FalsePositiveRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RuleType(str, Enum):
    INJECTION = "injection"
    PATH_TRAVERSAL = "path_traversal"
    DESERIALIZATION = "deserialization"
    AUTHENTICATION = "authentication"
    ACCESS_CONTROL = "access_control"
    CRYPTOGRAPHY = "cryptography"
    SECRET = "secret"
    TLS = "tls"
    OTHER = "other"


class TriageResult(BaseModel):
    """Versioned, serializable output shared by rule and future LLM providers."""

    schema_version: int = 1
    provider: str = "rules"
    rule_type: RuleType
    confidence: float = Field(ge=0.0, le=1.0)
    false_positive_risk: FalsePositiveRisk
    priority: TriagePriority
    is_test_file: bool = False
    is_dependency_file: bool = False
    signals: list[str] = Field(default_factory=list)
    human_verification_checklist: list[str] = Field(default_factory=list)


class TriageEnhancer(Protocol):
    """Optional adapter for adding model-backed context to a rule result."""

    def enhance(self, finding: Finding, result: TriageResult) -> TriageResult:
        """Return an enriched result; implementations must identify their provider."""
        ...


_CWE_RE = re.compile(r"\bCWE-(\d+)\b", re.IGNORECASE)
_TEST_FILENAMES = re.compile(
    r"(^test_.*\.py$|.*_test\.py$|.*\.(test|spec)\.[^.]+$)", re.IGNORECASE
)
_SAMPLE_FILENAME_TOKENS = {
    "example",
    "examples",
    "demo",
    "demos",
    "mock",
    "mocks",
    "stub",
    "stubs",
    "fixture",
    "fixtures",
    "generated",
}
_GENERATED_FILENAME_SUFFIXES = (
    ".min.js",
    ".min.css",
    ".bundle.js",
    ".generated.py",
    ".generated.ts",
    ".generated.js",
)
_DEPENDENCY_DIRS = {
    "bower_components",
    "dist-packages",
    "node_modules",
    "site-packages",
    "third-party",
    "third_party",
    "vendor",
    "vendors",
    "venv",
    ".venv",
}
_DEPENDENCY_FILENAMES = {
    "cargo.lock",
    "composer.lock",
    "package-lock.json",
    "poetry.lock",
    "pnpm-lock.yaml",
    "requirements.lock",
    "yarn.lock",
}
_RULE_TYPE_CWES: dict[str, RuleType] = {
    "22": RuleType.PATH_TRAVERSAL,
    "78": RuleType.INJECTION,
    "79": RuleType.INJECTION,
    "89": RuleType.INJECTION,
    "95": RuleType.INJECTION,
    "287": RuleType.AUTHENTICATION,
    "295": RuleType.TLS,
    "327": RuleType.CRYPTOGRAPHY,
    "798": RuleType.SECRET,
    "862": RuleType.ACCESS_CONTROL,
    "863": RuleType.ACCESS_CONTROL,
    "502": RuleType.DESERIALIZATION,
}
_RULE_TYPE_TERMS: tuple[tuple[RuleType, tuple[str, ...]], ...] = (
    (RuleType.PATH_TRAVERSAL, ("path-traversal", "directory-traversal", "traversal")),
    (RuleType.DESERIALIZATION, ("deserializ", "pickle", "yaml-load")),
    (RuleType.AUTHENTICATION, ("authentication", "authn", "password")),
    (RuleType.ACCESS_CONTROL, ("authorization", "access-control", "permission")),
    (RuleType.CRYPTOGRAPHY, ("crypt", "weak-hash", "md5", "sha1")),
    (RuleType.SECRET, ("secret", "credential", "hardcoded")),
    (RuleType.TLS, ("tls", "ssl", "certificate", "verify-disabled")),
    (RuleType.INJECTION, ("inject", "xss", "sql", "command", "eval", "inner-html")),
)
_SEVERITY_PRIORITY = {
    Severity.CRITICAL.value: TriagePriority.P0,
    Severity.HIGH.value: TriagePriority.P1,
    Severity.MEDIUM.value: TriagePriority.P2,
    Severity.LOW.value: TriagePriority.P3,
    Severity.INFO.value: TriagePriority.P3,
}
_PRIORITY_ORDER = (
    TriagePriority.P0,
    TriagePriority.P1,
    TriagePriority.P2,
    TriagePriority.P3,
)


def _path_parts(path: str) -> tuple[str, ...]:
    normalized = path.replace("\\", "/").strip("/")
    if not normalized:
        return ()
    return tuple(part.casefold() for part in PurePosixPath(normalized).parts)


def _is_test_file(parts: tuple[str, ...]) -> bool:
    return any(part in {"test", "tests", "testing", "__tests__", "spec", "specs"}
               for part in parts) or bool(parts and _TEST_FILENAMES.match(parts[-1]))


def _is_dependency_file(parts: tuple[str, ...]) -> bool:
    return any(part in _DEPENDENCY_DIRS for part in parts) or bool(
        parts and parts[-1] in _DEPENDENCY_FILENAMES
    )


def _rule_type(finding: Finding, cwe: str) -> RuleType:
    cwe_number = cwe.removeprefix("CWE-")
    if cwe_number in _RULE_TYPE_CWES:
        return _RULE_TYPE_CWES[cwe_number]

    rule_text = " ".join((finding.rule_id, finding.title, finding.message)).casefold()
    for rule_type, terms in _RULE_TYPE_TERMS:
        if any(term in rule_text for term in terms):
            return rule_type
    return RuleType.OTHER


def _priority(severity: str, contextual_path: bool) -> TriagePriority:
    priority = _SEVERITY_PRIORITY.get(severity.casefold(), TriagePriority.P3)
    if contextual_path and priority != TriagePriority.P3:
        return _PRIORITY_ORDER[_PRIORITY_ORDER.index(priority) + 1]
    return priority


class RuleBasedTriager:
    """Produce reproducible triage signals without network or model calls."""

    def triage(self, finding: Finding) -> TriageResult:
        parts = _path_parts(finding.file_path)
        filename = parts[-1] if parts else ""
        is_test = _is_test_file(parts)
        is_dependency = _is_dependency_file(parts)
        cwe_match = _CWE_RE.search(finding.cwe_id)
        cwe = f"CWE-{cwe_match.group(1)}" if cwe_match else ""
        rule_type = _rule_type(finding, cwe)
        severity = finding.severity.casefold()
        known_severity = severity in _SEVERITY_PRIORITY
        sample_filename = any(
            token in re.split(r"[^a-z0-9]+", filename)
            for token in _SAMPLE_FILENAME_TOKENS
        ) or filename.endswith(_GENERATED_FILENAME_SUFFIXES)
        contextual_path = is_test or is_dependency or sample_filename

        confidence = 0.5
        signals = [f"severity:{severity if known_severity else 'unknown'}"]
        if known_severity:
            confidence += 0.05
        if cwe:
            confidence += 0.15
            signals.append(f"cwe:{cwe}")
        else:
            signals.append("cwe:missing-or-unrecognized")
        if rule_type != RuleType.OTHER:
            confidence += 0.15
        signals.append(f"rule_type:{rule_type.value}")
        if finding.rule_id:
            confidence += 0.05
            signals.append("rule_id:present")
        if is_test:
            confidence -= 0.15
            signals.append("file_role:test")
        if is_dependency:
            confidence -= 0.15
            signals.append("file_role:dependency")
        if sample_filename:
            confidence -= 0.1
            signals.append("filename:sample-or-generated")

        if is_test or is_dependency or sample_filename or rule_type == RuleType.OTHER:
            fp_risk = FalsePositiveRisk.HIGH
        elif not cwe:
            fp_risk = FalsePositiveRisk.MEDIUM
        else:
            fp_risk = FalsePositiveRisk.LOW

        checklist = [
            "检查命中代码及上下文，确认不可信输入能否到达该位置。",
            "核实该规则的安全前提，并检查是否已有校验、编码或安全 API。",
            "仅在授权的本地测试环境验证可复现性，并保留最小证据。",
        ]
        if not cwe:
            checklist.append("核对规则定义与 CWE 映射，避免仅凭规则名称判定影响。")
        if rule_type == RuleType.INJECTION:
            checklist.append("验证输入是否可控、是否进入解释器/查询/HTML sink，以及是否正确编码或参数化。")
        elif rule_type == RuleType.PATH_TRAVERSAL:
            checklist.append("验证用户可控路径是否经过规范化，并受预期目录边界约束。")
        elif rule_type == RuleType.DESERIALIZATION:
            checklist.append("确认反序列化数据是否不可信，以及是否允许构造对象或执行危险类型。")
        elif rule_type == RuleType.AUTHENTICATION:
            checklist.append("验证身份凭据的生命周期、验证流程与失败处理是否可被绕过。")
        elif rule_type == RuleType.ACCESS_CONTROL:
            checklist.append("比较不同身份对目标资源的访问结果，确认是否缺少服务端授权检查。")
        elif rule_type == RuleType.CRYPTOGRAPHY:
            checklist.append("确认该算法是否用于安全敏感用途，并检查协议或密钥管理的补偿控制。")
        elif rule_type == RuleType.SECRET:
            checklist.append("确认值是否为有效凭据，检查其作用范围、权限和是否已撤销/轮换。")
        elif rule_type == RuleType.TLS:
            checklist.append("确认传输是否承载敏感数据，并验证证书校验是否在相关调用路径中关闭。")
        if is_test:
            checklist.append("确认命中是否仅属于测试/fixture 代码，且不会进入生产构建。")
        if is_dependency:
            checklist.append("确认该文件是否为第三方或依赖产物，并检查受影响代码是否实际被调用。")
        if sample_filename:
            checklist.append("确认该文件是否为示例、mock、stub 或生成产物，避免将非生产代码当作可利用路径。")

        return TriageResult(
            rule_type=rule_type,
            confidence=round(max(0.0, min(0.95, confidence)), 2),
            false_positive_risk=fp_risk,
            priority=_priority(severity, contextual_path),
            is_test_file=is_test,
            is_dependency_file=is_dependency,
            signals=signals,
            human_verification_checklist=checklist,
        )


class TriageService:
    """Persist triage snapshots and route findings into the human review queue."""

    def __init__(
        self,
        session: Session,
        actor: str = "local",
        enhancer: TriageEnhancer | None = None,
        triager: RuleBasedTriager | None = None,
    ):
        self.session = session
        self.actor = actor
        self.enhancer = enhancer
        self.triager = triager or RuleBasedTriager()

    def triage_finding(self, finding_id: int) -> TriageResult:
        finding = self.session.get(Finding, finding_id)
        if finding is None:
            raise FindingNotFoundError(f"Finding 不存在: id={finding_id}")

        current = finding.status
        if current not in {
            FindingStatus.NEW.value,
            FindingStatus.TRIAGE_FAILED.value,
        }:
            raise IllegalTransitionError(
                f"Finding 状态不允许分诊: id={finding_id}, status={current}"
            )

        audit = AuditLogger(self.session, self.actor)
        try:
            rule_result = self.triager.triage(finding)
        except Exception as exc:
            self._mark_failed(finding, current, exc, audit)
            raise

        result = rule_result
        if self.enhancer is not None:
            try:
                result = self.enhancer.enhance(finding, rule_result)
            except Exception as exc:
                self.session.add(
                    TriageRecord(
                        finding_id=finding_id,
                        provider=rule_result.provider,
                        result_json=rule_result.model_dump_json(),
                    )
                )
                self._mark_failed(finding, current, exc, audit)
                raise

        assert_transition(current, FindingStatus.RULE_TRIAGED.value)
        finding.status = FindingStatus.RULE_TRIAGED.value
        assert_transition(
            finding.status,
            FindingStatus.PENDING_REVIEW.value,
        )
        finding.status = FindingStatus.PENDING_REVIEW.value
        self.session.add(
            TriageRecord(
                finding_id=finding_id,
                provider=result.provider,
                result_json=result.model_dump_json(),
            )
        )
        audit.record(
            AuditAction.FINDING_TRIAGED.value,
            finding.target_id,
            {
                "finding_id": finding_id,
                "provider": result.provider,
                "priority": result.priority.value,
                "confidence": result.confidence,
                "false_positive_risk": result.false_positive_risk.value,
            },
        )
        self.session.flush()
        return result

    def _mark_failed(
        self, finding: Finding, current: str, error: Exception, audit: AuditLogger
    ) -> None:
        if current == FindingStatus.NEW.value:
            assert_transition(current, FindingStatus.TRIAGE_FAILED.value)
            finding.status = FindingStatus.TRIAGE_FAILED.value
        audit.record(
            AuditAction.TRIAGE_FAILED.value,
            finding.target_id,
            {"finding_id": finding.id, "error": str(error)[:300]},
        )

    def skip_failed(self, finding_id: int) -> None:
        """Move a failed finding to human review without inventing triage output."""
        finding = self.session.get(Finding, finding_id)
        if finding is None:
            raise FindingNotFoundError(f"Finding 不存在: id={finding_id}")
        assert_transition(finding.status, FindingStatus.PENDING_REVIEW.value)
        if finding.status != FindingStatus.TRIAGE_FAILED.value:
            raise IllegalTransitionError(
                f"仅可跳过失败的分诊: id={finding_id}, status={finding.status}"
            )
        finding.status = FindingStatus.PENDING_REVIEW.value
        AuditLogger(self.session, self.actor).record(
            AuditAction.TRIAGE_SKIPPED.value,
            finding.target_id,
            {"finding_id": finding_id},
        )

    def triage_pending(self, target_id: int | None = None) -> list[tuple[int, TriageResult]]:
        finding_columns = inspect(Finding).columns
        statement = select(Finding).where(
            or_(
                finding_columns["status"] == FindingStatus.NEW.value,
                finding_columns["status"] == FindingStatus.TRIAGE_FAILED.value,
            )
        )
        if target_id is not None:
            statement = statement.where(
                finding_columns["target_id"] == target_id
            )
        findings = self.session.exec(
            statement.order_by(inspect(Finding).primary_key[0])
        ).all()
        results: list[tuple[int, TriageResult]] = []
        for finding in findings:
            if finding.id is not None:
                results.append((finding.id, self.triage_finding(finding.id)))
        return results

    def review_queue(self, target_id: int | None = None) -> list[tuple[Finding, TriageResult | None]]:
        finding_columns = inspect(Finding).columns
        statement = select(Finding).where(
            finding_columns["status"] == FindingStatus.PENDING_REVIEW.value
        )
        if target_id is not None:
            statement = statement.where(
                finding_columns["target_id"] == target_id
            )
        findings = self.session.exec(
            statement.order_by(inspect(Finding).primary_key[0])
        ).all()
        record_columns = inspect(TriageRecord).columns
        finding_ids = [finding.id for finding in findings if finding.id is not None]
        latest_records: dict[int, TriageRecord] = {}
        if finding_ids:
            records = self.session.exec(
                select(TriageRecord)
                .where(record_columns["finding_id"].in_(finding_ids))
                .order_by(
                    record_columns["finding_id"],
                    record_columns["created_at"].desc(),
                    inspect(TriageRecord).primary_key[0].desc(),
                )
            ).all()
            for record in records:
                latest_records.setdefault(record.finding_id, record)

        rows: list[tuple[Finding, TriageResult | None]] = []
        for finding in findings:
            record = latest_records.get(finding.id) if finding.id is not None else None
            result = TriageResult.model_validate_json(record.result_json) if record else None
            rows.append((finding, result))
        return rows
