"""RateLimiter tests with an injected clock."""

from datetime import datetime, timedelta, timezone

import pytest

from bughunter.core.errors import BudgetExceededError
from bughunter.core.ratelimit import RateLimiter

T0 = datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc)


def limiter(session, target_id: int, rps: float = 1.0, budget: int = 500) -> RateLimiter:
    return RateLimiter(session, target_id, rps, budget, context="test")


def test_second_request_same_second_rejected(factories, session):
    t = factories.target()
    rl = limiter(session, t.id)
    rl.acquire(now=T0)
    with pytest.raises(BudgetExceededError):
        rl.acquire(now=T0 + timedelta(milliseconds=500))


def test_request_allowed_after_window(factories, session):
    t = factories.target()
    rl = limiter(session, t.id)
    rl.acquire(now=T0)
    rl.acquire(now=T0 + timedelta(seconds=1, milliseconds=1))
    assert rl.used_today(now=T0 + timedelta(seconds=2)) == 2


def test_daily_budget_enforced(factories, session):
    t = factories.target()
    rl = limiter(session, t.id, rps=100.0, budget=3)
    for i in range(3):
        rl.acquire(now=T0 + timedelta(seconds=i * 2))
    with pytest.raises(BudgetExceededError):
        rl.acquire(now=T0 + timedelta(seconds=10))


def test_budget_resets_next_utc_day(factories, session):
    t = factories.target()
    rl = limiter(session, t.id, rps=100.0, budget=2)
    rl.acquire(now=T0)
    rl.acquire(now=T0 + timedelta(seconds=2))
    with pytest.raises(BudgetExceededError):
        rl.acquire(now=T0 + timedelta(seconds=10))
    next_day = (T0 + timedelta(days=1)).replace(hour=0, minute=0, second=1)
    rl.acquire(now=next_day)
    assert rl.used_today(now=next_day) == 1


def test_invalid_config_rejected(factories, session):
    t = factories.target()
    with pytest.raises(BudgetExceededError):
        RateLimiter(session, t.id, requests_per_sec=0, daily_budget=10)
    with pytest.raises(BudgetExceededError):
        RateLimiter(session, t.id, requests_per_sec=1, daily_budget=0)


def test_rejected_acquire_does_not_consume_budget(factories, session):
    t = factories.target()
    rl = limiter(session, t.id, rps=1.0, budget=10)
    rl.acquire(now=T0)
    with pytest.raises(BudgetExceededError):
        rl.acquire(now=T0)
    assert rl.used_today(now=T0) == 1
