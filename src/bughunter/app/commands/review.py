"""Human review queue commands."""

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import inspect
from sqlmodel import select

from ...analysis.triage import TriageResult, TriageService
from ...core.errors import FindingNotFoundError
from ...core.models import Finding, TriageRecord
from ._helpers import actor_name, db_session

app = typer.Typer(no_args_is_help=True, help="人工复核队列")
console = Console()


@app.command("queue")
def queue(
    target_id: int | None = typer.Option(None, "--target", "-t", help="仅显示该目标"),
):
    """列出等待人工验证的 findings。"""
    with db_session() as session:
        rows = TriageService(session, actor_name()).review_queue(target_id)
        table = Table("finding", "severity", "location", "type", "priority", "confidence", "FP risk")
        for finding, result in rows:
            table.add_row(
                str(finding.id),
                finding.severity,
                finding.location or finding.file_path,
                result.rule_type.value if result else "-",
                result.priority.value if result else "-",
                f"{result.confidence:.2f}" if result else "-",
                result.false_positive_risk.value if result else "-",
            )
        console.print(table)
        console.print(f"待复核: {len(rows)}")


@app.command("show")
def show(
    finding_id: int = typer.Option(..., "--finding", "-f", help="finding id"),
):
    """查看 finding 的分诊信号与人工验证清单。"""
    with db_session() as session:
        record_columns = inspect(TriageRecord).columns
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise FindingNotFoundError(f"Finding 不存在: id={finding_id}")
        record = session.exec(
            select(TriageRecord)
            .where(record_columns["finding_id"] == finding_id)
            .order_by(
                record_columns["created_at"].desc(),
                inspect(TriageRecord).primary_key[0].desc(),
            )
        ).first()

        console.rule(f"[bold]Finding #{finding_id} [{finding.status}][/bold]")
        console.print(f"{finding.severity.upper()} | {finding.location or finding.file_path}")
        console.print(f"规则: {finding.rule_id} — {finding.title}")
        console.print(f"证据说明: {finding.message}")
        if record is None:
            console.print("暂无分诊结果（可由人工直接复核）。")
            return

        result = TriageResult.model_validate_json(record.result_json)
        console.print(
            f"分诊: {result.provider} | {result.rule_type.value} | "
            f"{result.priority.value} | confidence={result.confidence:.2f} | "
            f"误报风险={result.false_positive_risk.value}"
        )
        console.print("信号: " + ", ".join(result.signals))
        console.print("人工验证清单:")
        for step in result.human_verification_checklist:
            console.print(f"  • {step}")


@app.command("skip-triage")
def skip_triage(
    finding_id: int = typer.Option(..., "--finding", "-f", help="失败的 finding id"),
):
    """人工跳过失败分诊，将 finding 放入待复核队列。"""
    with db_session() as session:
        TriageService(session, actor_name()).skip_failed(finding_id)
        console.print(f"Finding #{finding_id} 已放入人工复核队列。")
