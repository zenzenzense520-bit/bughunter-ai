"""RateLimiter: persisted per-target token budget.

Hard-reject semantics (no silent sleep inside the tool layer):
- at most floor(requests_per_sec) events inside any rolling 1-second window;
- at most daily_budget events per UTC day.

Budget state is persisted in SQLite (RateEvent), so it survives process restarts.
"""

from datetime import datetime, timedelta

from sqlmodel import Session, select

from .errors import BudgetExceededError
from .models import RateEvent, as_aware


class RateLimiter:
    def __init__(
        self,
        session: Session,
        target_id: int,
        requests_per_sec: float,
        daily_budget: int,
        context: str = "",
    ):
        self.session = session
        self.target_id = target_id
        self.requests_per_sec = float(requests_per_sec)
        self.daily_budget = int(daily_budget)
        self.context = context
        if self.requests_per_sec <= 0 or self.daily_budget <= 0:
            raise BudgetExceededError("限速配置必须为正数")

    def acquire(self, tokens: int = 1, now: datetime | None = None) -> None:
        """Consume tokens or raise BudgetExceededError without mutating state."""
        now = as_aware(now) if now else self._now()
        if tokens <= 0:
            raise BudgetExceededError("tokens 必须为正整数")

        events = self._events()
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        used_today = sum(1 for e in events if as_aware(e.created_at) >= day_start)
        if used_today + tokens > self.daily_budget:
            raise BudgetExceededError(
                f"目标 {self.target_id} 已达每日请求预算 {self.daily_budget}"
                f"（今日已用 {used_today}，本次申请 {tokens}）"
            )

        window_start = now - timedelta(seconds=1)
        recent = sum(1 for e in events if as_aware(e.created_at) >= window_start)
        capacity = int(self.requests_per_sec)
        if capacity < 1:
            capacity = 1
        if recent + tokens > capacity:
            raise BudgetExceededError(
                f"超过每秒请求上限 {capacity}（近 1 秒已记录 {recent}，本次申请 {tokens}）"
            )

        for _ in range(tokens):
            self.session.add(
                RateEvent(target_id=self.target_id, context=self.context, created_at=now)
            )
        self.session.flush()

    def used_today(self, now: datetime | None = None) -> int:
        now = as_aware(now) if now else self._now()
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return sum(1 for e in self._events() if as_aware(e.created_at) >= day_start)

    def prune(self, now: datetime | None = None, keep_days: int = 2) -> int:
        """Delete events older than keep_days; return the number deleted."""
        now = as_aware(now) if now else self._now()
        cutoff = now - timedelta(days=keep_days)
        stale = [
            e
            for e in self._events()
            if as_aware(e.created_at) < cutoff
        ]
        for e in stale:
            self.session.delete(e)
        self.session.flush()
        return len(stale)

    def _events(self) -> list[RateEvent]:
        return list(
            self.session.exec(
                select(RateEvent).where(RateEvent.target_id == self.target_id)
            ).all()
        )

    @staticmethod
    def _now():
        from .models import utcnow

        return utcnow()
