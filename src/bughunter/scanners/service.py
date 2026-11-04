"""Application service that orchestrates a SAST run end to end.

Order of operations (red lines first):
  AuthorizationGate -> path validation -> Task/Scan rows -> SemgrepRunner
  -> raw report archival -> dedup + Finding rows -> audit.
"""

import json
from dataclasses import dataclass
from pathlib import Path

from sqlmodel import select

from ..core.enums import (
    AuditAction,
    FindingStatus,
    ScanStatus,
    TaskKind,
    TaskStatus,
    Tool,
)
from ..core.errors import ScopeViolationError
from ..core.gate import AuthorizationGate
from ..core.models import Finding, Scan, Task, utcnow
from ..infra.audit import AuditLogger
from ..infra.docker import DockerClient
from .base import NormalizedFinding
from .semgrep_runner import SemgrepRunner


@dataclass(frozen=True)
class SastConfig:
    """Everything the SAST service needs, injected by the app layer."""

    image: str
    rules_dir: Path
    raw_dir: Path
    mem_limit_mb: int
    timeout_sec: int
    extra_configs: tuple[str, ...]


@dataclass(frozen=True)
class SastOutcome:
    scan_id: int
    results: int
    new_count: int
    duplicate_count: int
    skipped_count: int
    error_count: int
    tool_version: str
    raw_path: str


def validate_code_path(raw_path: str) -> Path:
    """Accept only an existing, absolute, non-root directory."""
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        raise ScopeViolationError(f"扫描路径必须是绝对路径: {raw_path}")
    path = path.resolve()
    if not path.is_dir():
        raise ScopeViolationError(f"扫描路径不存在或不是目录: {path}")
    if path == Path(path.anchor):
        raise ScopeViolationError("禁止扫描文件系统根目录，请指定具体项目目录")
    return path


class ScanService:
    def __init__(self, session, config: SastConfig, actor: str = "local",
                 docker: DockerClient | None = None):
        self.session = session
        self.config = config
        self.actor = actor
        self.docker = docker or DockerClient()

    def _build_runner(self) -> SemgrepRunner:
        return SemgrepRunner(
            docker=self.docker,
            image=self.config.image,
            rules_dir=self.config.rules_dir,
            mem_limit_mb=self.config.mem_limit_mb,
            timeout_sec=self.config.timeout_sec,
            extra_configs=self.config.extra_configs,
        )

    def _write_raw_report(self, scan_id: int, raw_text: str) -> Path:
        raw_dir = self.config.raw_dir
        raw_dir.mkdir(parents=True, exist_ok=True)
        path = raw_dir / f"semgrep_scan_{scan_id}.json"
        path.write_text(raw_text, encoding="utf-8")
        return path

    def run_sast(self, target_id: int, code_path: Path) -> SastOutcome:
        # 1) Red-line gate: active authorization + include scope.
        AuthorizationGate(self.session).assert_ready_for_scan(target_id)
        code_path = validate_code_path(str(code_path))

        audit = AuditLogger(self.session, self.actor)

        # 2) Task + Scan rows.
        task = Task(
            target_id=target_id,
            kind=TaskKind.SAST.value,
            params_json=json.dumps(
                {"path": str(code_path), "backend": "docker", "network": "none"},
                ensure_ascii=False,
            ),
            status=TaskStatus.RUNNING.value,
        )
        self.session.add(task)
        self.session.flush()

        scan = Scan(
            task_id=task.id,
            target_id=target_id,
            tool=Tool.SEMGREP.value,
            status=ScanStatus.RUNNING.value,
        )
        self.session.add(scan)
        self.session.flush()
        audit.record(
            AuditAction.SCAN_STARTED.value,
            target_id,
            {"scan_id": scan.id, "task_id": task.id, "path": str(code_path)},
        )

        # 3) Run the scanner.
        try:
            result = self._build_runner().run(code_path)
        except Exception as exc:
            scan.status = ScanStatus.FAILED.value
            scan.finished_at = utcnow()
            scan.error_message = str(exc)[:500]
            task.status = TaskStatus.FAILED.value
            audit.record(
                AuditAction.SCAN_FAILED.value,
                target_id,
                {"scan_id": scan.id, "error": str(exc)[:300]},
            )
            # Persist the failure despite the outer session's rollback-on-error.
            self.session.commit()
            raise

        # 4) Archive native report, persist findings.
        raw_path = self._write_raw_report(scan.id, result.raw_text)
        new_count, dup_count = self._persist_findings(scan, result.findings)

        scan.tool_version = result.tool_version
        scan.raw_report_path = str(raw_path)
        scan.findings_count = new_count
        scan.status = ScanStatus.COMPLETED.value
        scan.finished_at = utcnow()
        task.status = TaskStatus.COMPLETED.value
        audit.record(
            AuditAction.SCAN_FINISHED.value,
            target_id,
            {
                "scan_id": scan.id,
                "new": new_count,
                "duplicates": dup_count,
                "tool_errors": result.stats.errors_count,
                "skipped": result.stats.skipped_count,
            },
        )

        return SastOutcome(
            scan_id=scan.id,
            results=result.stats.results_count,
            new_count=new_count,
            duplicate_count=dup_count,
            skipped_count=result.stats.skipped_count,
            error_count=result.stats.errors_count,
            tool_version=result.tool_version,
            raw_path=str(raw_path),
        )

    def _persist_findings(
        self, scan: Scan, findings: list[NormalizedFinding]
    ) -> tuple[int, int]:
        """Insert new findings; fold hits already seen for this target as duplicates."""
        existing = set(
            self.session.exec(
                select(Finding.dedup_key).where(Finding.target_id == scan.target_id)
            ).all()
        )
        new_count = 0
        dup_count = 0
        for item in findings:
            if item.dedup_key in existing:
                dup_count += 1
                continue
            self.session.add(
                Finding(
                    target_id=scan.target_id,
                    scan_id=scan.id,
                    dedup_key=item.dedup_key,
                    title=item.title,
                    severity=item.severity,
                    tool=Tool.SEMGREP.value,
                    rule_id=item.rule_id,
                    file_path=item.file_path,
                    line=item.line,
                    end_line=item.end_line,
                    location=f"{item.file_path}:{item.line}" if item.line else item.file_path,
                    message=item.message,
                    cwe_id=item.cwe_id,
                    owasp_category=item.owasp_category,
                    references_json=json.dumps(item.references, ensure_ascii=False),
                    source_ref=item.source_ref,
                    status=FindingStatus.NEW.value,
                )
            )
            existing.add(item.dedup_key)
            new_count += 1
        self.session.flush()
        return new_count, dup_count
