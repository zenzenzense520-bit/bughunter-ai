"""Finding triage commands."""

import typer
from rich.console import Console
from rich.table import Table

from ...analysis.triage import TriageResult, TriageService
from ._helpers import actor_name, db_session

app = typer.Typer(no_args_is_help=True, help="Finding 分诊")
console = Console()


def _print_result(finding_id: int, result: TriageResult) -> None:
    console.print(
        f"Finding #{finding_id}: {result.provider} | {result.rule_type.value} | "
        f"{result.priority.value} | confidence={result.confidence:.2f} | "
        f"误报风险={result.false_positive_risk.value}"
    )


@app.command("triage")
def triage(
    finding_id: int | None = typer.Option(None, "--finding", "-f", help="单个 finding id"),
    target_id: int | None = typer.Option(None, "--target", "-t", help="仅处理该目标的 finding"),
):
    """使用离线规则分诊新 finding，并送入人工复核队列。"""
    if finding_id is not None and target_id is not None:
        raise typer.BadParameter("--finding 与 --target 不能同时使用")

    with db_session() as session:
        service = TriageService(session, actor_name())
        if finding_id is not None:
            _print_result(finding_id, service.triage_finding(finding_id))
            return

        results = service.triage_pending(target_id)
        table = Table("finding", "provider", "type", "priority", "confidence", "FP risk")
        for item_id, result in results:
            table.add_row(
                str(item_id),
                result.provider,
                result.rule_type.value,
                result.priority.value,
                f"{result.confidence:.2f}",
                result.false_positive_risk.value,
            )
        console.print(table)
        console.print(f"已送入人工复核队列: {len(results)}")
