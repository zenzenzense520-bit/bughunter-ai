"""BugHunter AI CLI entry point."""

import typer
from rich.console import Console

from ..core.errors import BugHunterError
from . import container
from .commands import audit_cmd, authz, scopes, targets
from .logging import get_logger, setup_logging

app = typer.Typer(
    no_args_is_help=True,
    help="BugHunter AI - authorized bug bounty workbench (human-in-the-loop).",
)
app.add_typer(targets.app, name="target")
app.add_typer(authz.app, name="authz")
app.add_typer(scopes.app, name="scope")
app.add_typer(audit_cmd.app, name="audit")


def main() -> None:
    import sys

    settings = container.get_settings()
    setup_logging(settings.log_dir())
    logger = get_logger("cli")
    logger.info("CLI session started: %s", " ".join(sys.argv[1:]))
    try:
        app()
    except BugHunterError as exc:
        logger.warning("blocked by red-line gate: %s", exc)
        Console().print(f"[bold red][BLOCKED][/bold red] {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
