from __future__ import annotations

import typer

app = typer.Typer(help="Baseline utilities (generate/apply).")


@app.command("gen")
def baseline_gen_cmd() -> None:
    raise typer.BadParameter("Baseline generation not implemented yet.")
