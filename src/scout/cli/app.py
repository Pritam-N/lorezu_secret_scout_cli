from __future__ import annotations

import typer
from rich.console import Console

from scout.cli.commands.init import app as init_app
from scout.cli.commands.scan_path import app as scan_path_app
from scout.cli.commands.scan_github import app as scan_github_app
from scout.cli.commands.rules import app as rules_app
from scout.cli.commands.baseline import app as baseline_app

app = typer.Typer(
    name="scout",
    help="Prevent accidental secret commits by scanning repos, folders, and GitHub org/user repos.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


def _version_callback(value: bool) -> None:
    if value:
        # keep version single source of truth later (importlib.metadata)
        console.print("scout 0.1.0")
        raise typer.Exit(0)


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", help="Show version and exit.", callback=_version_callback
    ),
) -> None:
    pass


# Register command groups
app.add_typer(init_app, name="init")
app.add_typer(scan_path_app, name="scan")
app.add_typer(scan_github_app, name="github")
app.add_typer(rules_app, name="rules")
app.add_typer(baseline_app, name="baseline")

# Optional direct aliases:
# scout scan-path .
# scout scan-github --org X
# If you want these, uncomment:
# from scout.cli.commands.scan_path import scan_path_cmd
# from scout.cli.commands.scan_github import scan_github_cmd
# app.command("scan-path")(scan_path_cmd)
# app.command("scan-github")(scan_github_cmd)
