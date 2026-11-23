"""`parry` command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from pydantic import ValidationError

from parry import __version__
from parry.attacks.catalog import expand, load_templates
from parry.attacks.model import AttackCase
from parry.config import ParryConfig, load_config
from parry.scope import ScopeError, authorize, classify_target

app = typer.Typer(
    help="Attack your LLM app before someone else does. Measure every defense.",
    no_args_is_help=True,
)
targets_app = typer.Typer(help="Inspect and authorize targets.", no_args_is_help=True)
app.add_typer(targets_app, name="targets")
attacks_app = typer.Typer(help="Browse the attack catalog.", no_args_is_help=True)
app.add_typer(attacks_app, name="attacks")
judge_app = typer.Typer(help="Measure judge accuracy against human labels.", no_args_is_help=True)
app.add_typer(judge_app, name="judge")

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


def _select(seed: int, families: list[str], channels: list[str]) -> list[AttackCase]:
    cases = expand(load_templates(), seed)
    if families:
        cases = [c for c in cases if c.family in families]
    if channels:
        cases = [c for c in cases if c.channel in channels]
    return cases


@attacks_app.command("list")
def attacks_list(seed: int = typer.Option(1337, help="Seed used to expand payloads.")) -> None:
    """List attack cases with their goal and OWASP / ATLAS mapping."""
    for c in expand(load_templates(), seed):
        apps = ",".join(c.apps)
        typer.echo(
            f"{c.case_id}\t{c.family}\t{c.channel}\t{c.goal}\t{apps}\t"
            f"{' '.join(c.owasp)}\t{' '.join(c.atlas)}"
        )


def write_report(run_dir: Path) -> Path:
    from parry.engine import load_trials
    from parry.reporting.render import to_html, to_markdown
    from parry.reporting.summary import summarize

    meta = json.loads((run_dir / "run.json").read_text())
    trials = load_trials(run_dir)
    cases = expand(load_templates(), int(meta["seed"]))
    summary = summarize(trials, cases)
    (run_dir / "summary.json").write_text(json.dumps({"meta": meta, **summary}, indent=2) + "\n")
    md = to_markdown(summary, meta)
    (run_dir / "report.md").write_text(md)
    (run_dir / "report.html").write_text(to_html(md, f"Parry scan {meta['run_id']}"))
    return run_dir / "report.md"


@app.command()
def scan(
    config: Path = ConfigOpt,
    i_own_this_target: list[str] = OwnOpt,
    allow_public_endpoints: bool = PublicOpt,
    family: list[str] = typer.Option([], help="Only these attack families (repeatable)."),
    channel: list[str] = typer.Option([], help="Only these delivery channels (repeatable)."),
    out: Path = typer.Option(Path("runs"), help="Directory for run folders."),
    llm_judge: bool = typer.Option(True, help="Use the LLM judge for goals that need one."),
) -> None:
    """Run the attack suite against authorized targets and write a report."""
    from parry.engine import run_scan

    cfg = _load(config)
    try:
        allowed = authorize(cfg, i_own_this_target, allow_public_endpoints=allow_public_endpoints)
    except ScopeError as exc:
        typer.echo(f"refused: {exc}", err=True)
        raise typer.Exit(EXIT_REFUSED) from exc
    cases = _select(cfg.seed, family, channel)
    if not cases:
        typer.echo("no attack cases match the filters", err=True)
        raise typer.Exit(EXIT_CONFIG)
    run_dir = run_scan(cfg, allowed, cases, out, use_llm_judge=llm_judge, progress=typer.echo)
    report = write_report(run_dir)
    typer.echo(report.read_text().split("### ")[0])
    typer.echo(f"report: {report}")


@app.command()
def report(run_dir: Path = typer.Argument(..., help="A runs/<run_id> folder.")) -> None:
    """(Re)generate summary.json, report.md and report.html for a finished run."""
    typer.echo(f"wrote {write_report(run_dir)}")


@judge_app.command("sample")
def judge_sample(
    run_dir: Path = typer.Argument(..., help="A runs/<run_id> folder."),
    out: Path = typer.Option(Path("datasets/judge-labels/sample.jsonl")),
    n: int = typer.Option(200, help="Number of outcomes to sample."),
    config: Path = ConfigOpt,
    llm_judge: bool = typer.Option(True, help="Add a generic LLM-judge verdict to each item."),
) -> None:
    """Draw a stratified sample of outcomes for human labeling."""
    from parry.judges.labels import agreement, sample, save
    from parry.judges.llm import LlmJudge

    cfg = _load(config)
    llm = LlmJudge(str(cfg.judge.llm_url), cfg.judge.llm_model, cfg.seed) if llm_judge else None
    items = sample(run_dir, n, cfg.seed, llm)
    save(items, out)
    typer.echo(f"wrote {len(items)} items to {out}")
    if llm_judge:
        typer.echo(f"parry vs generic LLM judge (no human labels): {agreement(items)}")


@judge_app.command("label")
def judge_label(
    path: Path = typer.Argument(..., help="A sample .jsonl from `judge sample`."),
) -> None:
    """Label each outcome yourself: did the attack succeed? Judge verdicts stay hidden."""
    from parry.judges.labels import load, save

    items = load(path)
    todo = [i for i in items if i.human is None]
    typer.echo(
        f"{len(items) - len(todo)}/{len(items)} labeled. y = succeeded, n = did not, "
        "s = skip, q = save and quit."
    )
    for k, item in enumerate(todo, 1):
        typer.echo("\n" + "=" * 78)
        typer.echo(f"[{k}/{len(todo)}] {item.item_id}  goal: {item.goal}")
        typer.echo(f"Attacker objective: {item.objective}")
        payload = item.payload if isinstance(item.payload, str) else " || ".join(item.payload)
        typer.echo(f"Payload: {payload[:600]}")
        for j, r in enumerate(item.replies, 1):
            typer.echo(f"Reply {j}: {r[:1500]}")
        for e in item.evidence:
            typer.echo(f"Evidence: {e}")
        answer = typer.prompt("Did the attack succeed? [y/n/s/q]").strip().lower()
        if answer == "q":
            break
        if answer in ("y", "n"):
            item.human = answer == "y"
            save(items, path)
    save(items, path)
    typer.echo(f"saved {path}")


@judge_app.command("eval")
def judge_eval(path: Path = typer.Argument(..., help="A labeled sample .jsonl.")) -> None:
    """Accuracy, precision and recall of each judge against your labels (95% Wilson CIs)."""
    from parry.judges.labels import evaluate, load

    typer.echo(json.dumps(evaluate(load(path)), indent=2))


if __name__ == "__main__":
    app()
