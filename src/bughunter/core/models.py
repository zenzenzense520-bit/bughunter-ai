"""SQLModel tables plus the SQLite engine factory.

Tables: targets / authorizations / scope_entries / rate_events / tasks /
scans / findings / audit_log.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlmodel import Field, Session, SQLModel, create_engine

from .enums import (
    FindingStatus,
    ScanStatus,
    Severity,
    TargetStatus,
    TaskKind,
    TaskStatus,
    Tool,
)


def utcnow() -> datetime:
    """Timezone-aware UTC now (single clock source for the whole app)."""
    return datetime.now(timezone.utc)


def as_aware(dt: datetime) -> datetime:
    """Normalize a possibly naive datetime read back from SQLite to UTC-aware."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class Target(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    status: str = Field(default=TargetStatus.DRAFT.value, index=True)
    notes: str = Field(default="")
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class Authorization(SQLModel, table=True):
    """A grant of authorization. It becomes effective only after human confirm."""

    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    source: str  # platform project / SRC policy / written grant
    scope_ref: str  # URL or local file path describing the grant
    grantor: str  # granting party
    valid_from: datetime
    valid_to: datetime
    confirmed_by: Optional[str] = None
    confirmed_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utcnow)


class ScopeEntry(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    kind: str  # ScopeKind value
    rule_type: str  # ScopeRuleType value
    value: str
    created_at: datetime = Field(default_factory=utcnow)


class RateEvent(SQLModel, table=True):
    """One unit of request budget consumed by a target-facing action."""

    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(index=True)
    context: str = Field(default="")  # task kind / reason
    created_at: datetime = Field(default_factory=utcnow, index=True)


class Task(SQLModel, table=True):
    """A planned unit of work produced by the (thin) planner."""

    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    kind: str = Field(default=TaskKind.SAST.value, index=True)  # TaskKind value
    params_json: str = Field(default="{}")  # strongly typed params serialized
    status: str = Field(default=TaskStatus.PLANNED.value, index=True)
    requires_approval: bool = Field(default=False)
    approved_by: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)


class Scan(SQLModel, table=True):
    """One concrete tool execution belonging to a task."""

    id: Optional[int] = Field(default=None, primary_key=True)
    task_id: int = Field(foreign_key="task.id", index=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    tool: str = Field(default=Tool.SEMGREP.value, index=True)  # Tool value
    tool_version: str = Field(default="")
    status: str = Field(default=ScanStatus.RUNNING.value, index=True)
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: Optional[datetime] = None
    raw_report_path: str = Field(default="")
    findings_count: int = Field(default=0)
    error_message: str = Field(default="")


class Finding(SQLModel, table=True):
    """A normalized, deduplicated finding. Human review is mandatory downstream."""

    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    dedup_key: str = Field(index=True)
    title: str = Field(default="")
    severity: str = Field(default=Severity.INFO.value, index=True)
    tool: str = Field(default=Tool.SEMGREP.value)
    rule_id: str = Field(default="")
    file_path: str = Field(default="")
    line: int = Field(default=0)
    end_line: int = Field(default=0)
    location: str = Field(default="", index=True)  # human-readable file:line
    message: str = Field(default="")
    cwe_id: str = Field(default="")
    owasp_category: str = Field(default="")
    references_json: str = Field(default="[]")
    source_ref: str = Field(default="")
    status: str = Field(default=FindingStatus.NEW.value, index=True)
    created_at: datetime = Field(default_factory=utcnow)


class AuditLog(SQLModel, table=True):
    """Append-only audit trail. Each row chains to the previous one by hash."""

    id: Optional[int] = Field(default=None, primary_key=True)
    ts: datetime = Field(default_factory=utcnow, index=True)
    actor: str = Field(default="local")
    action: str = Field(index=True)
    target_id: Optional[int] = Field(default=None, index=True)
    detail_json: str = Field(default="{}")
    hash_prev: str = Field(default="")
    hash: str = Field(default="", index=True)


def make_engine(db_path: Path):
    """Create a SQLite engine, ensuring the parent directory exists."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return create_engine(
        f"sqlite:///{db_path.as_posix()}",
        echo=False,
        connect_args={"check_same_thread": False},
    )


def init_db(engine) -> None:
    """Create all tables (idempotent)."""
    SQLModel.metadata.create_all(engine)


@contextmanager
def session_scope(engine) -> Iterator[Session]:
    """Transactional session: commit on success, rollback on any exception."""
    with Session(engine) as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
