from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import typer

from scout.rules.loader import load_ruleset

app = typer.Typer(help="Rules utilities (validate, list sources, etc.).")


@app.command("validate")
def validate_rules_cmd(
    path: Path = typer.Argument(
        Path("."), help="Path to resolve repo/global rules from."
    ),
    builtin: str = typer.Option("default", "--builtin", help="Builtin pack."),
    rules_file: List[Path] = typer.Option(
        [], "--rules", exists=True, dir_okay=False, help="Extra rule packs."
    ),
) -> None:
    loaded = load_ruleset(
        start_dir=path.resolve(), builtin=builtin, extra_rule_files=rules_file
    )
    typer.echo("OK")
    for s in loaded.sources:
        typer.echo(f"- {s}")
