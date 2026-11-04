"""BugHunter AI CLI entry point."""

import typer
from rich.console import Console
from typer.core import TyperGroup

from ..core.errors import BugHunterError
from . import container
from .commands import audit_cmd, authz, scan, scopes, targets
from .logging import get_logger, setup_logging


class HunterGroup(TyperGroup):
    """Root group that turns any red-line BugHunterError into a printed
    [BLOCKED] line and exit code 1, instead of a raw traceback."""

    def invoke(self, ctx):
        try:
            return super().invoke(ctx)
        except BugHunterError as exc:
            Console().print(f"[bold red][BLOCKED][/bold red] {exc}")
            ctx.exit(1)


app = typer.Typer(
    no_args_is_help=True,
    cls=HunterGroup,
    help="BugHunter AI - authorized bug bounty workbench (human-in-the-loop).",
)
app.add_typer(targets.app, name="target")
app.add_typer(authz.app, name="authz")
app.add_typer(scopes.app, name="scope")
app.add_typer(scan.app, name="scan")
app.add_typer(audit_cmd.app, name="audit")


def main() -> None:
    import sys

    settings = container.get_settings()
    setup_logging(settings.log_dir())
    logger = get_logger("cli")
    logger.info("CLI session started: %s", " ".join(sys.argv[1:]))
    # Red-line errors are rendered by HunterGroup; everything else propagates.
    app()


if __name__ == "__main__":
    main()
