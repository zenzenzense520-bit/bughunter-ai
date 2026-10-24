"""Composition root: cached settings and engine providers."""

from functools import lru_cache
from pathlib import Path

from ..core.db import init_db, make_engine
from .config import Settings


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


@lru_cache(maxsize=4)
def _get_engine(db_path: str):
    engine = make_engine(Path(db_path))
    init_db(engine)
    return engine


def get_engine():
    """Default engine bound to the configured data directory."""
    settings = get_settings()
    return _get_engine(str(settings.db_path()))


def reset_cache() -> None:
    """Clear caches (used by tests that point BUGHUNTER_HOME at temp dirs)."""
    get_settings.cache_clear()
    _get_engine.cache_clear()
