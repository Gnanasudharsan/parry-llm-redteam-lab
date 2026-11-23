"""`parry` command-line interface."""

from __future__ import annotations

from pathlib import Path

import typer
from pydantic import ValidationError

from parry import __version__
from parry.config import ParryConfig, load_config
from parry.scope import ScopeError, authorize, classify_target

app = typer.Typer(
    help="Attack your LLM app before someone else does. Measure every defense.",
    no_args_is_help=True,
)
targets_app = typer.Typer(help="Inspect and authorize targets.", no_args_is_help=True)
app.add_typer(targets_app, name="targets")

ConfigOpt = typer.Option(Path("parry.yaml"), "--config", "-c", help="Path to parry.yaml.")
OwnOpt = typer.Option(
    [],
    "--i-own-this-target",
    help="Name of a target you own or are authorized to test. Repeat once per target.",
)
PublicOpt = typer.Option(
    False,
    "--allow-public-endpoints",
    help="Allow public endpoints that also set public_endpoint_acknowledged in config.",
)

EXIT_CONFIG = 2
EXIT_REFUSED = 3


def _load(path: Path) -> ParryConfig:
    try:
        return load_config(path)
    except FileNotFoundError:
        typer.echo(f"config not found: {path}", err=True)
    except ValidationError as exc:
        typer.echo(f"invalid config {path}:\n{exc}", err=True)
    raise typer.Exit(EXIT_CONFIG)


@app.command()
def version() -> None:
    """Print the Parry version."""
    typer.echo(__version__)


@targets_app.command("list")
def targets_list(config: Path = ConfigOpt) -> None:
    """List configured targets and how Parry classifies each endpoint."""
    cfg = _load(config)
    for t in cfg.targets:
        where = str(t.url) if t.url else (t.model or t.entrypoint or " ".join(t.command or []))
        typer.echo(f"{t.name}\t{t.kind}\t{classify_target(t)}\t{where}")


@targets_app.command("check")
def targets_check(
    config: Path = ConfigOpt,
    i_own_this_target: list[str] = OwnOpt,
    allow_public_endpoints: bool = PublicOpt,
) -> None:
    """Run the authorization gate without sending any traffic."""
    cfg = _load(config)
    try:
        allowed = authorize(cfg, i_own_this_target, allow_public_endpoints=allow_public_endpoints)
    except ScopeError as exc:
        typer.echo(f"refused: {exc}", err=True)
        raise typer.Exit(EXIT_REFUSED) from exc
    for a in allowed:
        typer.echo(f"authorized: {a.target.name} ({a.scope})")


if __name__ == "__main__":
    app()
