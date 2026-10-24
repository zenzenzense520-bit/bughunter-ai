"""SQLite engine factory and session scope."""

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine

# Import models so that SQLModel.metadata is fully populated before create_all.
from . import models  # noqa: F401


def make_engine(db_path: Path):
    """Create a SQLite engine, ensuring the parent directory exists."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        f"sqlite:///{db_path.as_posix()}",
        echo=False,
        connect_args={"check_same_thread": False},
    )
    return engine


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
