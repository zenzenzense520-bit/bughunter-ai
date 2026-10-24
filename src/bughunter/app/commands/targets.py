"""target command group: add / list / show / archive."""

import typer
from rich.console import Console
from rich.table import Table
from sqlmodel import select

from ...core.enums import AuditAction, ScopeKind, TargetStatus
from ...core.errors import AuthorizationError, BugHunterError
from ...core.gate import AuthorizationGate
from ...core.models import Authorization, ScopeEntry, Target, utcnow
from ...infra.audit import AuditLogger
from ._helpers import actor_name, db_session

app = typer.Typer(no_args_is_help=True, help="目标管理")
console = Console()


@app.command("add")
def add(
    name: str = typer.Option(..., "--name", "-n", help="目标名称（唯一）"),
    notes: str = typer.Option("", "--notes", help="备注"),
):
    """登记一个目标（初始为 draft，需确认授权后才能扫描）。"""
    with db_session() as session:
        if session.exec(select(Target).where(Target.name == name)).first():
            raise BugHunterError(f"目标名称已存在: {name}")
        target = Target(name=name, notes=notes)
        session.add(target)
        session.flush()
        AuditLogger(session, actor_name()).record(
            AuditAction.TARGET_CREATED.value, target.id, {"name": name}
        )
        console.print(f"[green]已创建目标[/green] id={target.id} name={name} status=draft")


@app.command("list")
def list_targets():
    """列出全部目标。"""
    with db_session() as session:
        targets = session.exec(select(Target).order_by(Target.id)).all()
        table = Table("id", "name", "status", "created_at", title="Targets")
        for t in targets:
            table.add_row(str(t.id), t.name, t.status, t.created_at.isoformat(timespec="seconds"))
        console.print(table)


@app.command("show")
def show(target_id: int = typer.Option(..., "--target", "-t")):
    """显示目标详情、授权状态与 scope 规则。"""
    with db_session() as session:
        target = AuthorizationGate(session).get_target(target_id)
        authz_list = session.exec(
            select(Authorization)
            .where(Authorization.target_id == target_id)
            .order_by(Authorization.id.desc())
        ).all()
        scopes = session.exec(
            select(ScopeEntry).where(ScopeEntry.target_id == target_id).order_by(ScopeEntry.id)
        ).all()

        console.rule(f"[bold]Target #{target_id} {target.name}[/bold]")
        console.print(f"status={target.status}  notes={target.notes or '-'}")

        console.print("\n[bold]Authorizations[/bold]")
        for a in authz_list:
            confirmed = (
                f"confirmed_by={a.confirmed_by} at={a.confirmed_at.isoformat(timespec='seconds')}"
                if a.confirmed_at
                else "unconfirmed"
            )
            console.print(
                f"  id={a.id} {a.valid_from.date()} ~ {a.valid_to.date()} "
                f"source={a.source} grantor={a.grantor} [{confirmed}]"
            )
        if not authz_list:
            console.print("  (none)")

        console.print("\n[bold]Scope[/bold]")
        for s in scopes:
            console.print(f"  id={s.id} {s.kind:7s} {s.rule_type:12s} {s.value}")
        if not scopes:
            console.print("  (none)")

        includes = [s for s in scopes if s.kind == ScopeKind.INCLUDE.value]
        try:
            AuthorizationGate(session).assert_active(target_id)
            gate_state = "authorization: ACTIVE"
            if includes:
                gate_state += " ; ready for scan"
            else:
                gate_state += " ; missing include scope"
        except AuthorizationError as exc:
            gate_state = f"authorization: BLOCKED ({exc})"
        console.print(f"\n[yellow]{gate_state}[/yellow]")


@app.command("archive")
def archive(
    target_id: int = typer.Option(..., "--target", "-t"),
    reason: str = typer.Option(..., "--reason", help="归档原因（必填）"),
):
    """归档目标（归档后任何扫描一律拒绝）。"""
    with db_session() as session:
        target = AuthorizationGate(session).get_target(target_id)
        target.status = TargetStatus.ARCHIVED.value
        target.updated_at = utcnow()
        session.add(target)
        AuditLogger(session, actor_name()).record(
            AuditAction.TARGET_ARCHIVED.value, target_id, {"reason": reason}
        )
        console.print(f"[yellow]目标已归档[/yellow] id={target_id} reason={reason}")
