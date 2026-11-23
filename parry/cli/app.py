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
guard_app = typer.Typer(help="Serve guard classifiers for lab apps.", no_args_is_help=True)
app.add_typer(guard_app, name="guard")
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


@app.command()
def matrix(
    config: Path = ConfigOpt,
    i_own_this_target: list[str] = OwnOpt,
    configs: Path = typer.Option(Path("targets/matrix.yaml"), help="Defense configurations."),
    tasks: Path = typer.Option(Path("targets/benign"), help="Folder with <app>.yaml task sets."),
    only: list[str] = typer.Option([], help="Run only these configuration names (repeatable)."),
    out: Path = typer.Option(Path("runs")),
    llm_judge: bool = typer.Option(True),
) -> None:
    """Run attacks and benign tasks under every defense configuration (lab targets only)."""
    from parry.matrix import load_matrix, run_matrix

    cfg = _load(config)
    try:
        allowed = authorize(cfg, i_own_this_target)
    except ScopeError as exc:
        typer.echo(f"refused: {exc}", err=True)
        raise typer.Exit(EXIT_REFUSED) from exc
    mcs = [m for m in load_matrix(configs) if not only or m.name in only]
    cases = _select(cfg.seed, [], [])
    out_dir = run_matrix(
        cfg, allowed, mcs, cases, tasks, out, use_llm_judge=llm_judge, progress=typer.echo
    )
    typer.echo(f"matrix: {out_dir / 'matrix.json'}")


@app.command("matrix-report")
def matrix_report(
    matrix_dir: Path = typer.Argument(..., help="A runs/matrix-<id> folder."),
) -> None:
    """Write matrix.json, matrix.md and pareto.svg for a finished defense matrix."""
    from parry.matrix import summarize_matrix
    from parry.reporting.pareto import to_markdown, to_svg

    m = summarize_matrix(matrix_dir)
    (matrix_dir / "matrix.json").write_text(json.dumps(m, indent=2) + "\n")
    (matrix_dir / "matrix.md").write_text(to_markdown(m))
    (matrix_dir / "pareto.svg").write_text(to_svg(m))
    typer.echo(f"wrote {matrix_dir / 'matrix.md'} and {matrix_dir / 'pareto.svg'}")


@app.command()
def benign(
    config: Path = ConfigOpt,
    i_own_this_target: list[str] = OwnOpt,
    tasks: Path = typer.Option(Path("targets/benign"), help="Folder with <app>.yaml task sets."),
    out: Path = typer.Option(Path("reports/benign.json")),
) -> None:
    """Run benign task sets (utility, false positives, latency) on authorized targets."""
    from parry.adapters import make_adapter
    from parry.benign import run_benign
    from parry.lab import LabClient
    from parry.metrics import wilson_interval
    from parry.tasks import load_taskset

    cfg = _load(config)
    try:
        allowed = authorize(cfg, i_own_this_target)
    except ScopeError as exc:
        typer.echo(f"refused: {exc}", err=True)
        raise typer.Exit(EXIT_REFUSED) from exc
    report = {}
    for a in allowed:
        t = a.target
        lab = LabClient(cfg, t) if t.lab else None
        rows = run_benign(make_adapter(t), lab, load_taskset(tasks / f"{t.app}.yaml"))
        core = [r for r in rows if not r.approval_gated]
        gated = [r for r in rows if r.approval_gated]
        rate = wilson_interval(sum(r.passed for r in core), len(core))
        g = wilson_interval(sum(r.passed for r in gated), len(gated))
        leaks = sum(r.leaked for r in core)
        typer.echo(f"{t.name:<12} core {rate}  gated {g if gated else '-'}  leaks {leaks}")
        report[t.name] = {
            "core": str(rate),
            "gated": str(g) if gated else None,
            "tasks": [r.model_dump() for r in rows],
        }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n")
    typer.echo(f"wrote {out}")


baseline_app = typer.Typer(help="Run other scanners on the same targets.", no_args_is_help=True)
app.add_typer(baseline_app, name="baseline")


@baseline_app.command("garak")
def baseline_garak(
    config: Path = ConfigOpt,
    i_own_this_target: list[str] = OwnOpt,
    out: Path = typer.Option(Path("runs/baselines/garak")),
) -> None:
    """Run NVIDIA garak's injection probes against authorized chat targets."""
    from parry.baselines import garak
    from parry.metrics import wilson_interval

    cfg = _load(config)
    try:
        allowed = authorize(cfg, i_own_this_target)
    except ScopeError as exc:
        typer.echo(f"refused: {exc}", err=True)
        raise typer.Exit(EXIT_REFUSED) from exc
    summary = {}
    for a in allowed:
        if a.target.kind.value != "http":
            typer.echo(f"skip {a.target.name}: garak's REST generator needs a chat endpoint")
            continue
        report = garak.run(a.target, out, cfg.seed)
        summary[a.target.name] = garak.summarize(report)
        for row in summary[a.target.name].values():
            typer.echo(
                f"{a.target.name} {row['probe']} {wilson_interval(row['hits'], row['total'])}"
            )
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")


@guard_app.command("serve")
def guard_serve(
    host: str = typer.Option("127.0.0.1", help="Bind address (keep it local)."),
    port: int = typer.Option(8300),
) -> None:
    """Serve prompt-injection classifiers at POST /classify (needs the lab and ml groups)."""
    import uvicorn

    from parry.defenses.server import create_app

    uvicorn.run(create_app(), host=host, port=port)


if __name__ == "__main__":
    app()
