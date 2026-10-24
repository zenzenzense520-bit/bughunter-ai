"""SQLModel tables for M1: targets, authorizations, scope, rate events, audit."""

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel

from .enums import TargetStatus


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
