"""Shared helpers for CLI commands."""

from contextlib import contextmanager

from ...core.db import session_scope
from .. import container


@contextmanager
def db_session():
    """Open a transactional session against the configured database."""
    engine = container.get_engine()
    with session_scope(engine) as session:
        yield session


def actor_name() -> str:
    return container.get_settings().general.actor
