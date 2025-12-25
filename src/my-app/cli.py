import typer
from typing_extensions import Annotated

app = typer.Typer(
    name="my-app",
    help="A fantastic CLI tool for doing things.",
    add_completion=False, # cleaner help output, optional
    no_args_is_help=True,
)

@app.command()
def hello(
    name: Annotated[str, typer.Option(help="Name to greet")] = "World",
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
):
    """
    Say hello to someone.
    """
    if verbose:
        typer.echo(f"We are about to greet {name}...")
    typer.echo(f"Hello {name}!")

if __name__ == "__main__":
    app()
