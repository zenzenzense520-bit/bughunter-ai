"""scan command group: sast / list / show (active scanning is refused)."""

import typer
from rich.console import Console
from rich.table import Table
from sqlmodel import select

from ...core.enums import AuditAction, ScanStatus
from ...core.errors import FeatureDisabledError
from ...core.models import Finding, Scan
from ...infra.audit import AuditLogger
from ...scanners.service import SastConfig, ScanService
from ._helpers import actor_name, db_session
from .. import container

app = typer.Typer(no_args_is_help=True, help="扫描任务（SAST / 被动扫描）")
console = Console()


def _sast_config() -> SastConfig:
    settings = container.get_settings()
    scan = settings.scan
    return SastConfig(
        image=scan.semgrep_image,
        rules_dir=settings.semgrep_rules_dir(),
        raw_dir=settings.raw_dir(),
        mem_limit_mb=scan.semgrep_mem_limit_mb,
        timeout_sec=scan.semgrep_timeout_sec,
        extra_configs=tuple(scan.semgrep_extra_configs),
    )


@app.command("sast")
def sast(
    target_id: int = typer.Option(..., "--target", "-t", help="目标 id"),
    path: str = typer.Option(..., "--path", "-p", help="本地代码目录（绝对路径）"),
):
    """对已授权目标的本地代码做 Semgrep 静态扫描（Docker 离线、只读挂载）。"""
    with db_session() as session:
        service = ScanService(session, _sast_config(), actor_name())
        outcome = service.run_sast(target_id, path)
        console.rule(f"[bold]SAST scan #{outcome.scan_id} 完成[/bold]")
        console.print(f"命中结果（工具原始）: {outcome.results}")
        console.print(f"[green]新增 finding[/green]: {outcome.new_count}    "
                      f"重复归并: {outcome.duplicate_count}")
        console.print(f"工具错误: {outcome.error_count}    跳过文件: {outcome.skipped_count}")
        console.print(f"semgrep 版本: {outcome.tool_version or 'unknown'}")
        console.print(f"原始报告: {outcome.raw_path}")
        if outcome.error_count:
            console.print(
                "[yellow]提示: 存在工具错误（部分文件可能无法解析），详见原始报告 errors 段。[/yellow]"
            )


@app.command("list")
def list_scans(
    target_id: int = typer.Option(..., "--target", "-t", help="目标 id"),
):
    """列出某目标的全部扫描记录。"""
    with db_session() as session:
        scans = session.exec(
            select(Scan).where(Scan.target_id == target_id).order_by(Scan.id)
        ).all()
        table = Table("id", "tool", "status", "version", "findings", "started", title="Scans")
        for s in scans:
            table.add_row(
                str(s.id), s.tool, s.status, s.tool_version or "-",
                str(s.findings_count), s.started_at.isoformat(timespec="seconds"),
            )
        console.print(table)


@app.command("show")
def show(scan_id: int = typer.Option(..., "--scan", "-s", help="扫描 id")):
    """显示某次扫描归一化后的 findings。"""
    with db_session() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise FeatureDisabledError(f"扫描记录不存在: id={scan_id}")
        findings = session.exec(
            select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id)
        ).all()
        console.rule(f"[bold]Scan #{scan_id} {scan.tool} [{scan.status}][/bold]")
        if scan.error_message:
            console.print(f"[red]error: {scan.error_message}[/red]")
        table = Table("id", "severity", "location", "rule", "status")
        for f in findings:
            table.add_row(str(f.id), f.severity, f.location, f.rule_id, f.status)
        console.print(table)
        if not findings:
            console.print("(no findings)")


@app.command("active")
def active():
    """主动扫描（发送攻击 payload）——v1 硬关闭，此命令永远被拒绝。"""
    with db_session() as session:
        AuditLogger(session, actor_name()).record(
            AuditAction.ACTIVE_SCAN_BLOCKED.value,
            None,
            {"reason": "active scan hard-disabled in v1"},
        )
        session.commit()
        raise FeatureDisabledError(
            "主动扫描在 v1 硬关闭（会发送攻击 payload）；仅允许授权的被动扫描（M5）。"
        )
