"""authz command group: register and confirm authorization."""

from datetime import datetime

import typer
from rich.console import Console
from sqlmodel import select

from ...core.enums import AuditAction, TargetStatus
from ...core.errors import BugHunterError
from ...core.gate import AuthorizationGate
from ...core.models import Authorization, Target, utcnow
from ...infra.audit import AuditLogger
from ._helpers import actor_name, db_session

app = typer.Typer(no_args_is_help=True, help="授权管理")
console = Console()


def _parse_dt(value: str, field: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise BugHunterError(f"{field} 不是合法 ISO 时间（示例 2026-10-31T00:00:00）: {value}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
    return dt


@app.command("add")
def add(
    target_id: int = typer.Option(..., "--target", "-t"),
    source: str = typer.Option(..., "--source", help="授权来源（平台项目/SRC/合同）"),
    scope_ref: str = typer.Option(..., "--scope-ref", help="授权说明 URL 或文件路径"),
    grantor: str = typer.Option(..., "--grantor", help="授权方"),
    valid_from: str = typer.Option(..., "--valid-from", help="生效时间 ISO"),
    valid_to: str = typer.Option(..., "--valid-to", help="失效时间 ISO"),
):
    """登记一条授权（未确认，不生效）。"""
    vf = _parse_dt(valid_from, "valid_from")
    vt = _parse_dt(valid_to, "valid_to")
    if vt <= vf:
        raise BugHunterError("valid_to 必须晚于 valid_from")

    with db_session() as session:
        target = AuthorizationGate(session).get_target(target_id)
        if target.status == TargetStatus.ARCHIVED.value:
            raise BugHunterError("目标已归档，不能再登记授权")
        authz = Authorization(
            target_id=target_id,
            source=source,
            scope_ref=scope_ref,
            grantor=grantor,
            valid_from=vf,
            valid_to=vt,
        )
        session.add(authz)
        session.flush()
        AuditLogger(session, actor_name()).record(
            AuditAction.AUTHORIZATION_ADDED.value,
            target_id,
            {"authz_id": authz.id, "source": source, "grantor": grantor,
             "valid_from": vf.isoformat(), "valid_to": vt.isoformat()},
        )
        console.print(
            f"[green]已登记授权[/green] id={authz.id} target={target_id} "
            f"{vf.date()} ~ {vt.date()}（待确认）"
        )


@app.command("confirm")
def confirm(
    target_id: int = typer.Option(..., "--target", "-t"),
    authz_id: int = typer.Option(None, "--authz", help="不指定则确认最新一条未确认授权"),
):
    """人工二次确认授权并激活目标。"""
    with db_session() as session:
        target = AuthorizationGate(session).get_target(target_id)
        if authz_id is None:
            authz = session.exec(
                select(Authorization)
                .where(
                    Authorization.target_id == target_id,
                    Authorization.confirmed_at.is_(None),  # type: ignore[arg-type]
                )
                .order_by(Authorization.id.desc())
            ).first()
        else:
            authz = session.get(Authorization, authz_id)
        if authz is None or authz.target_id != target_id:
            raise BugHunterError("未找到待确认的授权记录")
        if authz.valid_to <= utcnow():
            raise BugHunterError("该授权已过期，不能确认")

        console.rule("[bold red]授权确认[/bold red]")
        console.print(f"目标   : {target.name} (id={target_id})")
        console.print(f"来源   : {authz.source}")
        console.print(f"授权说明: {authz.scope_ref}")
        console.print(f"授权方 : {authz.grantor}")
        console.print(f"有效期 : {authz.valid_from.isoformat()} ~ {authz.valid_to.isoformat()}")
        console.print(
            "[red]确认即表示你已获得该目标的明确测试授权，"
            "且将仅在 scope 白名单内以低频被动方式测试。[/red]"
        )
        approved = typer.confirm("是否确认激活该授权？", default=False)
        if not approved:
            console.print("[yellow]已取消，授权未生效。[/yellow]")
            raise typer.Exit(code=1)

        actor = actor_name()
        authz.confirmed_by = actor
        authz.confirmed_at = utcnow()
        target.status = TargetStatus.ACTIVE.value
        target.updated_at = utcnow()
        session.add(authz)
        session.add(target)
        AuditLogger(session, actor).record(
            AuditAction.AUTHORIZATION_CONFIRMED.value,
            target_id,
            {"authz_id": authz.id, "valid_to": authz.valid_to.isoformat()},
        )
        console.print(f"[green]授权已确认，目标激活[/green] id={target_id} status=active")
