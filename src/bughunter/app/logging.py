"""Logging setup: rotating file handler under logs/ plus console output."""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(log_dir: Path, verbose: bool = False) -> None:
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger("bughunter")
    root.setLevel(logging.DEBUG)
    root.handlers.clear()
    root.propagate = False

    formatter = logging.Formatter(_LOG_FORMAT, _DATE_FORMAT)

    file_handler = RotatingFileHandler(
        log_dir / "bughunter.log",
        maxBytes=1_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(formatter)

    root.addHandler(file_handler)
    root.addHandler(console)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"bughunter.{name}")
