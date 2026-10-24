"""audit command group: inspect trail and verify hash chain."""

import typer
from rich.console import Console
from rich.table import Table
from sqlmodel import select

from ...core.models import AuditLog
from ...infra.audit import verify_chain
from ._helpers import db_session

app = typer.Typer(no_args_is_help=True, help="审计日志")
console = Console()


@app.command("tail")
def tail(limit: int = typer.Option(20, "--limit", "-n", help="显示最近 N 条")):
    """查看最近的审计记录。"""
    with db_session() as session:
        rows = session.exec(
            select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
        ).all()
        table = Table("id", "ts", "actor", "action", "target", "hash", title="Audit log")
        for e in reversed(rows):
            table.add_row(
                str(e.id),
                e.ts.isoformat(timespec="seconds"),
                e.actor,
                e.action,
                str(e.target_id or "-"),
                e.hash[:8],
            )
        console.print(table)


@app.command("verify")
def verify():
    """校验审计链完整性（输出 broken 条目 id，空表示完整）。"""
    with db_session() as session:
        broken = verify_chain(session)
        if broken:
            console.print(f"[bold red]审计链被破坏，异常条目 id: {broken}[/bold red]")
            raise typer.Exit(code=1)
        console.print("[green]审计链完整，无异常。[/green]")
