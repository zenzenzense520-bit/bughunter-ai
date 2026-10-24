"""scope command group: include/exclude rules."""

import re
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.table import Table
from sqlmodel import select

from ...core.enums import AuditAction, ScopeKind, ScopeRuleType
from ...core.errors import BugHunterError
from ...core.gate import AuthorizationGate
from ...core.models import ScopeEntry
from ...core.scope import is_ip_literal
from ...infra.audit import AuditLogger
from ._helpers import actor_name, db_session

app = typer.Typer(no_args_is_help=True, help="scope 白名单/排除规则")
console = Console()


def _validate_host(value: str, rule_type: str) -> str:
    host = value.strip().lower()
    if "://" in host or "/" in host:
        raise BugHunterError("host 规则只填写域名或 IP，不要带 scheme/路径")
    try:
        parsed = urlparse(f"http://{host}")
    except ValueError as exc:
        raise BugHunterError(f"host 无法解析: {value}") from exc
    if parsed.hostname != host:
        raise BugHunterError(f"host 包含非法字符（端口/路径）: {value}")
    if is_ip_literal(host) and rule_type != ScopeRuleType.HOST.value:
        raise BugHunterError("IP 地址只能用 host 类型精确登记，禁止 host_suffix")
    return host


@app.command("add-include")
def add_include(
    target_id: int = typer.Option(..., "--target", "-t"),
    rule_type: str = typer.Option(..., "--rule-type", help="host 或 host_suffix"),
    value: str = typer.Option(..., "--value", "-v", help="域名/IP；host_suffix 含所有子域"),
):
    """加入 scope 白名单（include 仅支持 host / host_suffix）。"""
    if rule_type not in (ScopeRuleType.HOST.value, ScopeRuleType.HOST_SUFFIX.value):
        raise BugHunterError("include 仅支持 rule_type=host 或 host_suffix")
    host = _validate_host(value, rule_type)

    with db_session() as session:
        target = AuthorizationGate(session).get_target(target_id)
        dup = session.exec(
            select(ScopeEntry).where(
                ScopeEntry.target_id == target_id,
                ScopeEntry.kind == ScopeKind.INCLUDE.value,
                ScopeEntry.rule_type == rule_type,
                ScopeEntry.value == host,
            )
        ).first()
        if dup:
            raise BugHunterError(f"规则已存在: id={dup.id}")
        entry = ScopeEntry(
            target_id=target_id,
            kind=ScopeKind.INCLUDE.value,
            rule_type=rule_type,
            value=host,
        )
        session.add(entry)
        session.flush()
        AuditLogger(session, actor_name()).record(
            AuditAction.SCOPE_ENTRY_ADDED.value,
            target_id,
            {"kind": "include", "rule_type": rule_type, "value": host},
        )
        console.print(f"[green]已加入 include[/green] id={entry.id} {rule_type}={host} ({target.name})")


@app.command("add-exclude")
def add_exclude(
    target_id: int = typer.Option(..., "--target", "-t"),
    value: str = typer.Option(..., "--value", "-v", help="路径正则，如 ^/admin/"),
):
    """加入路径排除规则（exclude 仅支持 path_regex）。"""
    try:
        re.compile(value)
    except re.error as exc:
        raise BugHunterError(f"不是合法正则: {value} ({exc})") from exc

    with db_session() as session:
        target = AuthorizationGate(session).get_target(target_id)
        entry = ScopeEntry(
            target_id=target_id,
            kind=ScopeKind.EXCLUDE.value,
            rule_type=ScopeRuleType.PATH_REGEX.value,
            value=value,
        )
        session.add(entry)
        session.flush()
        AuditLogger(session, actor_name()).record(
            AuditAction.SCOPE_ENTRY_ADDED.value,
            target_id,
            {"kind": "exclude", "rule_type": "path_regex", "value": value},
        )
        console.print(f"[green]已加入 exclude[/green] id={entry.id} path_regex={value} ({target.name})")


@app.command("list")
def list_scope(target_id: int = typer.Option(..., "--target", "-t")):
    """列出目标的全部 scope 规则。"""
    with db_session() as session:
        AuthorizationGate(session).get_target(target_id)
        entries = session.exec(
            select(ScopeEntry)
            .where(ScopeEntry.target_id == target_id)
            .order_by(ScopeEntry.kind, ScopeEntry.id)
        ).all()
        table = Table("id", "kind", "rule_type", "value", title=f"Scope of target {target_id}")
        for e in entries:
            table.add_row(str(e.id), e.kind, e.rule_type, e.value)
        console.print(table)
