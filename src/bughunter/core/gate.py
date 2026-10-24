"""AuthorizationGate: no valid authorization, no target-facing action."""

from datetime import datetime

from sqlmodel import Session, select

from .enums import ScopeKind, TargetStatus
from .errors import AuthorizationError
from .models import Authorization, ScopeEntry, Target, as_aware, utcnow


class AuthorizationGate:
    def __init__(self, session: Session):
        self.session = session

    def get_target(self, target_id: int) -> Target:
        target = self.session.get(Target, target_id)
        if target is None:
            raise AuthorizationError(f"目标不存在: id={target_id}")
        return target

    def assert_active(self, target_id: int, now: datetime | None = None) -> Target:
        """Target exists, not archived, and has a confirmed, in-date authorization."""
        target = self.get_target(target_id)
        if target.status == TargetStatus.ARCHIVED.value:
            raise AuthorizationError(f"目标已归档，禁止任何测试: {target.name}")

        authz = self.latest_confirmed(target_id)
        if authz is None:
            raise AuthorizationError(
                f"目标 {target.name} 尚无已确认授权；请先执行 authz add 与 authz confirm"
            )

        now = as_aware(now) if now else utcnow()
        if as_aware(authz.valid_from) > now:
            raise AuthorizationError(
                f"授权尚未生效: {as_aware(authz.valid_from).isoformat()}"
            )
        if as_aware(authz.valid_to) <= now:
            raise AuthorizationError(
                f"授权已过期: {as_aware(authz.valid_to).isoformat()}"
            )
        return target

    def assert_ready_for_scan(self, target_id: int, now: datetime | None = None) -> Target:
        """Active authorization AND at least one include scope rule."""
        target = self.assert_active(target_id, now)
        includes = self.session.exec(
            select(ScopeEntry).where(
                ScopeEntry.target_id == target_id,
                ScopeEntry.kind == ScopeKind.INCLUDE.value,
            )
        ).all()
        if not includes:
            raise AuthorizationError(
                f"目标 {target.name} 尚无 include 范围规则；请先执行 scope add-include"
            )
        return target

    def latest_confirmed(self, target_id: int) -> Authorization | None:
        """Return the most recently confirmed authorization, or None."""
        return self.session.exec(
            select(Authorization)
            .where(
                Authorization.target_id == target_id,
                Authorization.confirmed_at.is_not(None),  # type: ignore[arg-type]
            )
            .order_by(Authorization.valid_to.desc())
        ).first()
