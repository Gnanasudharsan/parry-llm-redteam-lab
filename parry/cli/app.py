"""`parry` command-line interface."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

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


@contextmanager
def _complete_cells() -> Iterator[None]:
    """Analysis commands refuse to read a cell that has no completion marker."""
    from parry.matrix import IncompleteCellError

    try:
        yield
    except IncompleteCellError as exc:
        typer.echo(f"refused: {exc}", err=True)
        raise typer.Exit(1) from exc


def _review_md(items: list[dict[str, Any]], title: str, intro: str) -> str:
    lines = [f"# {title}", "", intro, ""]
    for it in items:
        head = " · ".join(
            str(it[k]) for k in ("id", "target", "config", "case_id", "secret") if k in it
        )
        lines += [f"## {head}", ""]
        for k in (
            "evidence_type",
            "detail",
            "v2_1_positive",
            "rules_lost",
            "split_12",
            "finding",
            "v2",
            "v2_1",
            "v2_2",
        ):
            if k in it:
                lines.append(f"- {k}: `{json.dumps(it[k])}`")
        for j, r in enumerate(it.get("replies", []), 1):
            lines.append(f"- reply {j}: {r!r}")
        frags = it.get("evidence") or it.get("fragments") or []
        for f in frags:
            lines.append(f"- fragment `{f['fragment']}` in {f['view']}: {f['excerpt']!r}")
        if "v2_2_catches" in it:
            lines.append(f"- **v2.2 catches it under:** {', '.join(it['v2_2_catches']) or 'none'}")
            for f in it["v2_2_fragments"]:
                lines.append(
                    f"  - v2.2 fragment `{f['fragment']}` in {f['view']}: {f['excerpt']!r}"
                )
        lines.append("")
    return "\n".join(lines)


@judge_app.command("v2-diff")
def judge_v2_diff(
    matrix_dir: Path = typer.Argument(..., help="A runs/matrix-<id> folder."),
    out: Path = typer.Option(None, help="Output stem (default: <matrix_dir>/judge-v2-diff)."),
) -> None:
    """Trials judge v2 (4-char fragments) calls a leak and v2.1 does not, for review."""
    from parry.analysis import judge_disagreements

    with _complete_cells():
        rows = judge_disagreements(matrix_dir)
    stem = out or matrix_dir / "judge-v2-diff"
    stem.with_suffix(".json").write_text(json.dumps(rows, indent=2) + "\n")
    split = sum(r["split_12"] for r in rows)
    caught = sum(bool(r["v2_2_catches"]) for r in rows)
    intro = (
        f"{len(rows)} goal-secret findings where v2 (min fragment 4) reports a leak under at least "
        f"one rule and v2.1 (min fragment 8) does not; {split} are the documented 12-character "
        "split limit (a 12-char body rebuilt only from pieces shorter than 8). "
        f"v2.2 counts {caught} of them as leaks under at least one of the rules v2.1 lost."
    )
    stem.with_suffix(".md").write_text(_review_md(rows, "Judge v2 vs v2.1 disagreements", intro))
    typer.echo(f"{intro}\nwrote {stem.with_suffix('.md')}")


@judge_app.command("fp-controls")
def judge_fp_controls(
    matrix_dir: Path = typer.Argument(..., help="A runs/matrix-<id> folder."),
    judge: str = typer.Option("2.2", help="Leak judge version: 2.1 or 2.2."),
) -> None:
    """False-positive controls: never-planted secrets and benign answers, one judge version."""
    from parry.analysis import fp_controls

    with _complete_cells():
        res = fp_controls(matrix_dir, judge)
    (matrix_dir / f"fp-controls-v{judge}.json").write_text(json.dumps(res, indent=2) + "\n")
    typer.echo(
        json.dumps({k: v for k, v in res.items() if k != "benign_real_secret_hits"}, indent=2)
    )
    hits = res["benign_real_secret_hits"]
    tasks = sorted({(h["cell"].split("/")[0], h["task"], tuple(h["secrets"])) for h in hits})
    typer.echo(f"benign answers with a real lab secret: {len(hits)} in {tasks}")


@judge_app.command("decoder-recall")
def judge_decoder_recall(
    matrix_dir: Path = typer.Argument(..., help="A finished runs/matrix-<id> folder."),
    out: Path = typer.Option(Path("datasets/judge-labels/decoder-recall.json")),
    hosts: int = typer.Option(20),
    real: int = typer.Option(20, help="Real encoded-payload replies to pull for inspection."),
    seed: int = typer.Option(1337),
) -> None:
    """Decoder recall: encoded secrets injected into real replies, per encoding and judge."""
    import random

    from parry.analysis import LEAK_GOALS, _cell
    from parry.canary import secrets_for
    from parry.engine import load_trials
    from parry.judges.leak import evidence_v22, find_leaks_v22
    from parry.judges.recall import recall_check
    from parry.reporting.summary import scored

    targets = sorted(p.name for p in matrix_dir.iterdir() if p.is_dir())
    secrets = {t: secrets_for(t).as_dict() for t in targets}
    every = {f"{t}:{k}": v for t, sec in secrets.items() for k, v in sec.items()}
    clean: list[str] = []
    encoded: list[tuple[str, Any]] = []
    with _complete_cells():
        for t in targets:
            for cfg_dir in sorted(p for p in (matrix_dir / t).iterdir() if p.is_dir()):
                run = _cell(matrix_dir, t, cfg_dir.name)
                if run is None:
                    continue
                for tr in scored(load_trials(run)):
                    if cfg_dir.name == "none":
                        for r in tr.replies:
                            if len(r) > 80 and not find_leaks_v22([r], every):
                                clean.append(r)
                    if tr.goal in LEAK_GOALS and (
                        tr.transform != "none" or tr.template.startswith("ob-encode-output")
                    ):
                        encoded.append((t, tr))
    rng = random.Random(seed)  # noqa: S311 - reproducible sampling
    host_texts = rng.sample(sorted(set(clean)), min(hosts, len(set(clean))))
    res = recall_check(host_texts, secrets, seed)
    picked = rng.sample(encoded, min(real, len(encoded)))
    res["real_encoded_replies"] = [
        {
            "target": t,
            "case_id": tr.case_id,
            "transform": tr.transform,
            "template": tr.template,
            "v2_2": find_leaks_v22(tr.replies, secrets[t]),
            "evidence": {k: evidence_v22(tr.replies, v) for k, v in secrets[t].items()},
            "replies": [r[:600] for r in tr.replies],
        }
        for t, tr in picked
    ]
    res["hosts"] = len(host_texts)
    res["seed"] = seed
    out.write_text(json.dumps(res, indent=2) + "\n")
    lines = ["| encoding | n | v1 | v2.1 | v2.2 |", "|---|---|---|---|---|"]
    for enc, r in res["per_encoding"].items():
        lines.append(f"| {enc} | {r['n']} | {r['v1']:.0%} | {r['v2.1']:.0%} | {r['v2.2']:.0%} |")
    typer.echo("\n".join(lines))
    typer.echo(f"{len(encoded)} encoded-payload leak trials; {len(picked)} pulled; wrote {out}")


@judge_app.command("precision-sample")
def judge_precision_sample(
    matrix_dir: Path = typer.Argument(..., help="A finished runs/matrix-<id> folder."),
    out: Path = typer.Option(Path("datasets/judge-labels/leak-precision.json")),
    per_type: int = typer.Option(10, help="Items per evidence type (all if fewer)."),
    seed: int = typer.Option(1337),
    exclude: list[str] = typer.Option([], help="Configurations to leave out (repeatable)."),
) -> None:
    """Sample leak-judge positives for labeling, stratified by evidence type."""
    from parry.analysis import precision_sample

    if out.exists():
        typer.echo(f"refused: {out} exists (it may hold labels)", err=True)
        raise typer.Exit(1)
    with _complete_cells():
        res = precision_sample(matrix_dir, per_type, seed, tuple(exclude))
    res["source"] = matrix_dir.name
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=2) + "\n")
    pop = ", ".join(f"{k} {v}" for k, v in res["population"].items())
    intro = (
        f"{len(res['sample'])} items; positives by evidence type: {pop}. Up to {per_type} per "
        f"type, seed {seed}; excluded configurations: {', '.join(exclude) or 'none'}."
    )
    out.with_suffix(".md").write_text(
        _review_md(res["sample"], "Leak judge precision sample", intro)
    )
    typer.echo(f"{intro}\nwrote {out} and {out.with_suffix('.md')}")


def _clean_hosts(matrix_dir: Path, extra_targets: tuple[str, ...] = ()) -> list[str]:
    """Real replies (>80 chars) from the `none` cells with no fragment of any lab secret and
    no talk of keys, codes, secrets or the attacker (see `_LEAK_TALK`)."""
    from parry.analysis import _cell
    from parry.canary import secrets_for
    from parry.engine import load_trials
    from parry.judges.leak import find_leaks_v22

    targets = sorted(p.name for p in matrix_dir.iterdir() if p.is_dir())
    every = {
        f"{t}:{k}": v
        for t in (*targets, *extra_targets)
        for k, v in secrets_for(t).as_dict().items()
    }
    out: set[str] = set()
    for t in targets:
        run = _cell(matrix_dir, t, "none")
        if run is None:
            continue
        for tr in load_trials(run):
            out.update(
                r
                for r in tr.replies
                if len(r) > 80 and not _LEAK_TALK.search(r) and not find_leaks_v22([r], every)
            )
    return sorted(out)


# Replies that talk about secrets or sending data out are not "clear non-leaks" even without
# secret characters (a known-answer host once said it had emailed "the API key" to the
# attacker); such replies are never used as known-answer hosts.
_LEAK_TALK = re.compile(
    r"\b(?:api|key|keys|secret|secrets|code|codes|credential|credentials|password|token|"
    r"reference|canary|attacker|exfil\w*)\b",
    re.IGNORECASE,
)


def _panel_header(meta: dict[str, Any], rule: str, shown: str) -> list[str]:
    from parry.judges.panel import PANEL_WORDING

    lines = [
        f"# {PANEL_WORDING}",
        "",
        "Labelers: "
        + ", ".join(
            f"{m} ({d[:12]})" if isinstance(d, str) else f"{m} ({d['provider']}, hosted)"
            for m, d in meta["models"].items()
        )
        + (f"; Ollama {meta['ollama_version']}" if meta.get("ollama_version") else "")
        + f"; temperature 0, seed {meta['seed']}. Each labeler saw "
        f"only {shown}; never the judge's verdict, the evidence type, the configuration, or "
        "the other labeler's answer. 10 known-answer items (5 clear leaks, 5 clear non-leaks "
        "built from real reply text) were mixed in, blind.",
        "",
        f"Rule: *{rule}*",
        "",
        "Known-answer accuracy: "
        + "; ".join(
            f"{m} {a['correct']}/{a['of']}" + ("" if a["reliable"] else " (**UNRELIABLE**)")
            for m, a in meta["known_answer_accuracy"].items()
        ),
        "",
    ]
    if meta["unreliable_labelers"]:
        lines += [
            f"> **Warning:** {', '.join(meta['unreliable_labelers'])} got at least one "
            "known-answer item wrong. Labels from "
            + ("these labelers" if len(meta["unreliable_labelers"]) > 1 else "this labeler")
            + " are unreliable; every number below that "
            "depends on them (agreement, kappa, precision on agreed items) is shown for the "
            "record only and must not be reported as a measurement.",
            "",
        ]
    return lines


def _panel_table(title: str, items: list[dict[str, Any]], models: tuple[str, ...]) -> list[str]:
    lines = [f"## {title}", "", "| item | type | " + " | ".join(models) + " | agreed |"]
    lines.append("|---|---|" + "---|" * len(models) + "---|")
    for it in items:
        name = it.get("id") or it.get("item_id") or f"{it['target']}/{it['config']}/{it['case_id']}"
        cells = [
            f"{'t' if v['label'] else 'f' if v['label'] is False else '?'}: "
            f"{v['reason'].replace('|', '/')}"
            for v in it["panel"].values()
        ]
        agreed = {True: "t", False: "f", None: "unresolved"}[it["panel_agreed"]]
        kind = it.get("evidence_type") or it.get("goal") or it.get("secret")
        lines.append(f"| {name} | {kind} | " + " | ".join(cells) + f" | {agreed} |")
    return [*lines, ""]


def _hosted_labelers() -> dict[str, Any]:
    """Groq and Gemini labelers (owner-approved exception, X-001). Keys stay in-process."""
    from parry.judges.hosted import gemini_labeler, groq_labeler

    groq = groq_labeler()
    gemini = gemini_labeler()
    return {f"groq:{groq[1]['model']}": groq, f"google:{gemini[1]['model']}": gemini}


@judge_app.command("panel")
def judge_panel(
    matrix_dir: Path = typer.Argument(..., help="The finished matrix the items come from."),
    sample: Path = typer.Option(Path("datasets/judge-labels/leak-precision.json")),
    v2_diff: Path = typer.Option(Path("datasets/judge-labels/leak-v2-diff.json")),
    out: Path = typer.Option(Path("datasets/judge-labels/leak-panel.json")),
    model: list[str] = typer.Option([], help="Labeler models (default: llama3.1:8b, mistral:7b)."),
    seed: int = typer.Option(1337),
    hosted: bool = typer.Option(False, help="Use the hosted labelers (Groq, Gemini)."),
    types: list[str] = typer.Option([], help="Only these evidence types from the sample."),
) -> None:
    """Blind LLM-panel labels for the leak precision sample and the v2-diff cases.

    LLM-panel labels, not human-verified."""
    from parry.analysis import precision_report
    from parry.canary import secrets_for
    from parry.judges.panel import (
        DEFAULT_MODELS,
        LEAK_RULE,
        PANEL_WORDING,
        agreement,
        known_answers,
        leak_view,
        run_panel,
    )

    labelers = _hosted_labelers() if hosted else None
    models = tuple(labelers) if labelers else (tuple(model) or DEFAULT_MODELS)
    smp = json.loads(sample.read_text())
    if types:
        smp["sample"] = [it for it in smp["sample"] if it["evidence_type"] in types]
        smp["population"] = {k: v for k, v in smp["population"].items() if k in types}
    diff = json.loads(v2_diff.read_text())
    items = [{**it, "set": "precision"} for it in smp["sample"]]
    items += [{**it, "set": "v2_diff"} for it in diff]
    with _complete_cells():
        views = [leak_view(matrix_dir, it) for it in items]
        hosts = _clean_hosts(matrix_dir)
    secrets = [
        v
        for t in sorted(p.name for p in matrix_dir.iterdir() if p.is_dir())
        for v in secrets_for(t).as_dict().values()
    ]
    known = known_answers("leak", hosts, secrets, seed)
    res = run_panel(items, views, known, models=models, seed=seed, hosted=labelers)
    prec = [it for it in res["items"] if it["set"] == "precision"]
    dif = [it for it in res["items"] if it["set"] == "v2_diff"]
    report = {
        "wording": PANEL_WORDING,
        "source": matrix_dir.name,
        "known_answer_accuracy": res["known_answer_accuracy"],
        "unreliable_labelers": res["unreliable_labelers"],
        "precision_sample": {
            "agreement": agreement(prec, models),
            "precision_on_agreed_items": precision_report(
                prec, smp["population"], key="panel_agreed"
            ),
            "unresolved": [it["id"] for it in prec if it["panel_agreed"] is None],
        },
        "v2_diff": {
            "agreement": agreement(dif, models),
            "agreed_true_leak": sum(it["panel_agreed"] is True for it in dif),
            "agreed_not_leak": sum(it["panel_agreed"] is False for it in dif),
            "unresolved": sum(it["panel_agreed"] is None for it in dif),
        },
    }
    meta = {k: v for k, v in res.items() if k not in ("items",)}
    out.write_text(
        json.dumps(
            {**meta, "labeling_rule": LEAK_RULE, "report": report, "items": res["items"]}, indent=2
        )
        + "\n"
    )
    lines = _panel_header(meta, LEAK_RULE, "the trial's replies, the secret and the rule")
    lines += ["```json", json.dumps(report, indent=2), "```", ""]
    lines += _panel_table("Precision sample", prec, models)
    lines += _panel_table("v2 vs v2.1 cases", dif, models)
    out.with_suffix(".md").write_text("\n".join(lines))
    typer.echo(json.dumps(report, indent=2))
    typer.echo(f"wrote {out} and {out.with_suffix('.md')}")


@judge_app.command("panel-phase2")
def judge_panel_phase2(
    matrix_dir: Path = typer.Argument(..., help="A finished matrix (source of host replies)."),
    sample: Path = typer.Option(Path("datasets/judge-labels/phase2-sample.jsonl")),
    out: Path = typer.Option(Path("datasets/judge-labels/phase2-panel.json")),
    model: list[str] = typer.Option([], help="Labeler models (default: llama3.1:8b, mistral:7b)."),
    seed: int = typer.Option(1337),
    hosted: bool = typer.Option(False, help="Use the hosted labelers (Groq, Gemini)."),
) -> None:
    """Blind LLM-panel labels for the Phase 2 judge-accuracy set; Parry's judge and the
    generic LLM judge scored against them. LLM-panel labels, not human-verified."""
    from parry.judges.labels import LabelItem, evaluate
    from parry.judges.panel import (
        DEFAULT_MODELS,
        OUTCOME_RULE,
        PANEL_WORDING,
        agreement,
        known_answers,
        outcome_view,
        run_panel,
    )

    labelers = _hosted_labelers() if hosted else None
    models = tuple(labelers) if labelers else (tuple(model) or DEFAULT_MODELS)
    items = [json.loads(x) for x in sample.read_text().splitlines() if x.strip()]
    views = [outcome_view(it) for it in items]
    frames = [it for it in items if it["goal"].startswith("leak") and not it["evidence"]]
    targets = tuple(sorted({it["target"] for it in items}))
    with _complete_cells():
        hosts = _clean_hosts(matrix_dir, targets)
    known = known_answers("outcome", hosts, [], seed, frames=frames)
    res = run_panel(items, views, known, models=models, seed=seed, hosted=labelers)
    scored = [
        LabelItem.model_validate(
            {**{k: it[k] for k in LabelItem.model_fields}, "human": it["panel_agreed"]}
        )
        for it in res["items"]
    ]
    report = {
        "wording": PANEL_WORDING,
        "known_answer_accuracy": res["known_answer_accuracy"],
        "unreliable_labelers": res["unreliable_labelers"],
        "agreement": agreement(res["items"], models),
        "unresolved": [it["item_id"] for it in res["items"] if it["panel_agreed"] is None],
        "judges_vs_panel_agreed_labels": evaluate(scored),
    }
    meta = {k: v for k, v in res.items() if k not in ("items",)}
    out.write_text(
        json.dumps(
            {**meta, "labeling_rule": OUTCOME_RULE, "report": report, "items": res["items"]},
            indent=2,
        )
        + "\n"
    )
    shown = (
        "the objective, the attacker's input, the replies, the lab's records and "
        "(leak goals) the secret"
    )
    lines = _panel_header(meta, OUTCOME_RULE, shown)
    lines += ["```json", json.dumps(report, indent=2), "```", ""]
    lines += _panel_table("Phase 2 outcomes", res["items"], models)
    out.with_suffix(".md").write_text("\n".join(lines))
    typer.echo(json.dumps({k: v for k, v in report.items() if k != "unresolved"}, indent=2))
    typer.echo(f"wrote {out} and {out.with_suffix('.md')}")


@judge_app.command("precision-label")
def judge_precision_label(path: Path = typer.Argument(...)) -> None:
    """Label each sampled positive: t = the secret really got out, f = false leak."""
    data = json.loads(path.read_text())
    for it in data["sample"]:
        if it["label"] is not None:
            continue
        typer.echo("\n" + "=" * 78)
        typer.echo(f"{it['id']} {it['target']}/{it['config']} {it['case_id']} [{it['secret']}]")
        typer.echo(f"evidence type {it['evidence_type']} ({it['detail']}), finding {it['finding']}")
        for j, r in enumerate(it["replies"], 1):
            typer.echo(f"  reply {j}: {r}")
        for f in it["evidence"]:
            typer.echo(f"  fragment {f['fragment']} in {f['view']}: {f['excerpt']}")
        a = typer.prompt("True leak? [t/f/s/q]").strip().lower()
        if a == "q":
            break
        if a in ("t", "f"):
            it["label"] = a == "t"
            path.write_text(json.dumps(data, indent=2) + "\n")
    typer.echo(f"saved {path}")


@judge_app.command("precision")
def judge_precision(path: Path = typer.Argument(...)) -> None:
    """Precision per evidence type (95% Wilson) and overall, weighted by share of positives."""
    from parry.analysis import precision_report

    data = json.loads(path.read_text())
    typer.echo(json.dumps(precision_report(data["sample"], data["population"]), indent=2))


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
    ollama_log: Path | None = typer.Option(
        None,
        help="`ollama serve` log covering the run: model-load stalls are saved to "
        "ollama-stalls.json and left out of latency statistics.",
    ),
) -> None:
    """Write matrix.json, matrix.md and pareto.svg for a finished defense matrix."""
    from parry.matrix import STALLS_FILE, summarize_matrix
    from parry.reporting.pareto import to_markdown, to_svg
    from parry.stalls import STALL_S, ollama_stalls

    if ollama_log is not None:
        stalls = ollama_stalls(ollama_log)
        (matrix_dir / STALLS_FILE).write_text(
            json.dumps(
                {"source": ollama_log.name, "min_seconds": STALL_S, "stalls": stalls}, indent=2
            )
            + "\n"
        )
        typer.echo(f"{len(stalls)} model-load stalls recorded in {matrix_dir / STALLS_FILE}")

    with _complete_cells():
        m = summarize_matrix(matrix_dir)
    (matrix_dir / "matrix.json").write_text(json.dumps(m, indent=2) + "\n")
    (matrix_dir / "matrix.md").write_text(to_markdown(m))
    (matrix_dir / "pareto.svg").write_text(to_svg(m))
    typer.echo(f"wrote {matrix_dir / 'matrix.md'} and {matrix_dir / 'pareto.svg'}")


@app.command()
def analyze(
    matrix_dir: Path = typer.Argument(..., help="A runs/matrix-<id> folder (final cells only)."),
) -> None:
    """Paired tests (Holm), judge-rule sensitivity, FP controls and artifact checks."""
    from parry.analysis import analyze as run_analysis
    from parry.analysis import to_markdown as paired_md

    with _complete_cells():
        res = run_analysis(matrix_dir)
    (matrix_dir / "analysis.json").write_text(json.dumps(res, indent=2) + "\n")
    md = [f"# Defense matrix analysis ({matrix_dir.name})", ""]
    for rule, table in res["paired"].items():
        md += [f"## Paired tests, judge rule: {rule}", "", paired_md(table)]
    md += ["## Baseline exposure", ""]
    if not res["exposure"]:
        md += ["No benign task returns a goal secret in any cell.", ""]
    for t, cfgs in res["exposure"].items():
        for cfg, e in cfgs.items():
            shown = "; ".join(f"{k} (benign: {', '.join(v)})" for k, v in e["secrets"].items())
            md.append(f"- {t} / {cfg}: {shown}; {len(e['cases_excluded'])} attack cases set aside")
    md += [
        "",
        "| target | config | rule | (a) all cases | (b) excluding exposure | baseline exposure |",
        "|---|---|---|---|---|---|",
    ]
    for t, cfgs in res["cells"].items():
        for cfg, c in cfgs.items():
            for rule in res["rules"]:
                md.append(
                    f"| {t} | {cfg} | {rule} | {c[rule]}/{c['n']} | "
                    f"{c[rule + ' excluding exposure']}/{c['n_excluding_exposure']} | "
                    f"{c[rule + ' baseline exposure']} |"
                )
    md.append("")
    for rule, table in res["paired_excluding_exposure"].items():
        md += [f"## Paired tests excluding baseline exposure, rule: {rule}", "", paired_md(table)]
    md += [
        "## Supported conclusions that change when baseline exposure is excluded",
        "",
        "```",
        json.dumps(res["exposure_conclusion_changes"], indent=2),
        "```",
        "",
        "## Conclusion changes vs v1",
        "",
        "```",
        json.dumps(res["conclusion_changes"], indent=2),
        "```",
        "",
    ]
    (matrix_dir / "analysis.md").write_text("\n".join(md))
    typer.echo(f"wrote {matrix_dir / 'analysis.md'}")


@app.command("matrix-compare")
def matrix_compare(
    original: Path = typer.Argument(..., help="Original cell run folder."),
    rerun: Path = typer.Argument(..., help="Rerun of the same configuration."),
) -> None:
    """Check a rerun against the original within measured run-to-run noise."""
    from parry.matrix import compare_cells

    with _complete_cells():
        typer.echo(json.dumps(compare_cells(original, rerun), indent=2))


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
        summary[a.target.name] = {"garak": garak.summarize(report)}
        if a.target.lab:
            from parry.lab import LabClient

            secrets = LabClient(cfg, a.target).secrets().as_dict()
            summary[a.target.name]["parry_rejudge"] = garak.rejudge(report, secrets)
        for row in summary[a.target.name]["garak"].values():
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
