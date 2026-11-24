"""Defense matrix: attacks x channels x targets x defense configurations, plus utility.

For each authorized lab target and each configuration: reconfigure the running app, run the
attack suite (engine.run_scan) and the benign task set (benign.run_benign), and keep both
next to each other so security and utility come from the same app state.
"""

from __future__ import annotations

import json
import math
import statistics
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from parry.adapters import make_adapter
from parry.attacks.model import AttackCase
from parry.benign import BenignResult, latest, run_benign
from parry.config import AppType, ParryConfig
from parry.engine import load_trials, run_scan
from parry.lab import LabClient
from parry.metrics import wilson_interval
from parry.provenance import ollama_info
from parry.reporting.summary import scored
from parry.scope import AuthorizedTarget
from parry.tasks import load_taskset


class MatrixConfig(BaseModel):
    name: str
    hardening: dict[str, bool] = Field(default_factory=dict)
    defenses: list[str] = Field(default_factory=list)
    apps: list[AppType] | None = None


def load_matrix(path: Path) -> list[MatrixConfig]:
    return [MatrixConfig.model_validate(c) for c in yaml.safe_load(path.read_text())["configs"]]


def run_matrix(
    cfg: ParryConfig,
    targets: list[AuthorizedTarget],
    configs: list[MatrixConfig],
    cases: list[AttackCase],
    tasks_dir: Path,
    out_root: Path,
    *,
    use_llm_judge: bool = True,
    progress: Callable[[str], None] = lambda s: print(s, flush=True),
) -> Path:
    from parry.engine import _git_commit, _git_dirty

    code = (_git_commit(), _git_dirty())  # the code this process loaded, fixed for the run
    out = out_root / ("matrix-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"))
    out.mkdir(parents=True)
    (out / "provenance.json").write_text(
        json.dumps(
            {
                "ollama": ollama_info(str(cfg.judge.llm_url)),
                "seed": cfg.seed,
                "git_commit": code[0],
                "git_dirty": code[1],
            },
            indent=2,
        )
        + "\n"
    )
    for auth in targets:
        t = auth.target
        if not t.lab:
            raise ValueError(f"{t.name}: the matrix reconfigures targets through the lab API")
        lab = LabClient(cfg, t)
        tasks = load_taskset(tasks_dir / f"{t.app}.yaml")
        try:
            for mc in configs:
                if mc.apps is not None and t.app not in mc.apps:
                    continue
                progress(f"### {t.name} / {mc.name}")
                lab.configure(hardening=mc.hardening, defenses=mc.defenses, restore=True)
                cell = out / t.name / mc.name
                cell.mkdir(parents=True)
                run_dir = run_scan(
                    cfg,
                    [auth],
                    cases,
                    cell,
                    use_llm_judge=use_llm_judge,
                    progress=lambda s: None,
                    code=code,
                )
                benign = run_benign(make_adapter(t), lab, tasks)
                after = lab.state()  # trace counts cover this cell's attacks and benign tasks
                (run_dir / "benign.jsonl").write_text(
                    "".join(b.model_dump_json() + "\n" for b in benign)
                )
                state = lab.state()
                applied = {
                    "applied": state.get("defenses"),
                    "defense_versions": state.get("defense_versions", {}),
                    "trace": after.get("trace", {}),
                    "model": after.get("model"),
                }
                # Written last and atomically: its presence marks the cell complete.
                tmp = run_dir / (COMPLETION_MARKER + ".tmp")
                tmp.write_text(json.dumps({**mc.model_dump(mode="json"), **applied}, indent=2))
                tmp.replace(run_dir / COMPLETION_MARKER)
                s = cell_summary(run_dir)
                progress(
                    f"    ASR {s['asr']['text']} | benign {s['utility']['text']} | "
                    f"median {s['latency_median_s']}s"
                )
        finally:
            lab.configure(restore=True)
    (out / "matrix.json").write_text(json.dumps(summarize_matrix(out), indent=2) + "\n")
    return out


def _r(k: int, n: int) -> dict[str, Any]:
    r = wilson_interval(k, n)
    return {"k": k, "n": n, "rate": r.point, "low": r.low, "high": r.high, "text": str(r)}


# A cell is complete once config.json exists: run_matrix writes it last, after the attack
# trials (trials.jsonl, run.json) and the benign tasks (benign.jsonl). Analysis refuses to
# read a cell without it, so a running or interrupted cell is never reported.
COMPLETION_MARKER = "config.json"
_CELL_FILES = ("trials.jsonl", "run.json", "benign.jsonl", COMPLETION_MARKER)


class IncompleteCellError(RuntimeError):
    pass


def require_complete(run_dir: Path) -> Path:
    missing = [f for f in _CELL_FILES if not (run_dir / f).exists()]
    if missing:
        raise IncompleteCellError(
            f"{run_dir}: incomplete cell (missing {', '.join(missing)}); "
            "it is still running or was interrupted"
        )
    return run_dir


def cell_run(cfg_dir: Path) -> Path:
    """The run folder of a configuration cell, refusing incomplete cells."""
    run = next((p for p in cfg_dir.iterdir() if p.is_dir()), None)
    if run is None:
        raise IncompleteCellError(f"{cfg_dir}: cell has no run folder yet")
    return require_complete(run)


def cell_summary(run_dir: Path) -> dict[str, Any]:
    require_complete(run_dir)
    trials = scored(load_trials(run_dir))
    benign = [
        BenignResult.model_validate_json(x)
        for x in (run_dir / "benign.jsonl").read_text().splitlines()
    ]
    core = [b for b in benign if not b.approval_gated]
    lat = sorted(b.latency_s for b in core)
    meta = json.loads((run_dir / "run.json").read_text())
    conf_path = run_dir / "config.json"
    conf = json.loads(conf_path.read_text()) if conf_path.exists() else {}
    versions = conf.get("defense_versions") or {}
    uses_validator = "output_validator" in conf.get("defenses", [])
    return {
        "git_commit": meta.get("git_commit"),
        "git_dirty": meta.get("git_dirty"),
        "defense_versions": versions,
        "trace": conf.get("trace", {}),
        "validator_version": (
            versions.get("output_validator", "unrecorded") if uses_validator else "not used"
        ),
        "asr": _r(sum(bool(t.verdict and t.verdict.success) for t in trials), len(trials)),
        "attempt": _r(sum(bool(t.verdict and t.verdict.attempted) for t in trials), len(trials)),
        "critical_asr": _r(
            sum(bool(t.verdict and t.verdict.success) for t in trials if t.severity == "critical"),
            sum(t.severity == "critical" for t in trials),
        ),
        "by_family": {
            f: _r(
                sum(bool(t.verdict and t.verdict.success) for t in trials if t.family == f),
                sum(t.family == f for t in trials),
            )
            for f in sorted({t.family for t in trials})
        },
        "utility": _r(sum(b.passed for b in core), len(core)),
        "gated_completed": _r(
            sum(b.passed for b in benign if b.approval_gated), sum(b.approval_gated for b in benign)
        ),
        "false_positive": _r(sum(bool(b.defense_flags or b.blocked) for b in core), len(core)),
        "benign_leaks": sum(b.leaked for b in core),
        "latency_median_s": round(statistics.median(lat), 3) if lat else None,
        "latency_p95_s": round(lat[min(len(lat) - 1, int(0.95 * len(lat)))], 3) if lat else None,
        "guard_tokens_per_request": round(sum(b.guard_tokens for b in core) / len(core), 1)
        if core
        else 0,
        "guard_ms_per_request": round(sum(b.guard_ms for b in core) / len(core), 1) if core else 0,
    }


def summarize_matrix(out: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"matrix": out.name, "targets": {}}
    for target_dir in sorted(p for p in out.iterdir() if p.is_dir()):
        cells: dict[str, Any] = {}
        for cfg_dir in sorted(p for p in target_dir.iterdir() if p.is_dir()):
            run_dir = cell_run(cfg_dir)
            cells[cfg_dir.name] = {"run": str(run_dir.relative_to(out)), **cell_summary(run_dir)}
        base = cells.get("none")
        for c in cells.values():
            if base:
                c["asr_reduction"] = round(base["asr"]["rate"] - c["asr"]["rate"], 4)
                c["utility_retained"] = (
                    round(c["utility"]["rate"] / base["utility"]["rate"], 4)
                    if base["utility"]["rate"]
                    else None
                )
                if base["latency_median_s"] and c["latency_median_s"]:
                    c["latency_overhead_s"] = round(
                        c["latency_median_s"] - base["latency_median_s"], 3
                    )
        result["targets"][target_dir.name] = cells
    return result


# Run-to-run noise measured in Phase 2: 1 changed verdict in 256 repeated trials.
PHASE2_FLIPS, PHASE2_TRIALS = 1, 256


def compare_cells(a: Path, b: Path) -> dict[str, Any]:
    """Compare two runs of the same configuration (e.g. original vs spot-check rerun).

    Passes when (1) per-case verdict changes stay within the Phase 2 noise allowance,
    ceil(n x upper 95% Wilson bound of 1/256), and (2) the two ASR intervals overlap.
    """
    require_complete(a)
    require_complete(b)
    ta = {t.case_id: t for t in scored(load_trials(a))}
    tb = {t.case_id: t for t in scored(load_trials(b))}
    common = sorted(set(ta) & set(tb))

    def ok(t: Any) -> bool:
        return bool(t.verdict and t.verdict.success)

    flips = [c for c in common if ok(ta[c]) != ok(tb[c])]
    same_replies = sum(ta[c].replies == tb[c].replies for c in common)
    sa, sb = cell_summary(a), cell_summary(b)
    allowance = math.ceil(len(common) * wilson_interval(PHASE2_FLIPS, PHASE2_TRIALS).high)
    overlap = sa["asr"]["low"] <= sb["asr"]["high"] and sb["asr"]["low"] <= sa["asr"]["high"]
    ba = {x.id: x.passed for x in latest(_benign(a))}
    bb = {x.id: x.passed for x in latest(_benign(b))}
    return {
        "cases": len(common),
        "missing": sorted(set(ta) ^ set(tb)),
        "asr_original": sa["asr"]["text"],
        "asr_rerun": sb["asr"]["text"],
        "verdict_changes": flips,
        "allowance": allowance,
        "identical_replies": f"{same_replies}/{len(common)}",
        "ci_overlap": overlap,
        "benign_changes": sorted(k for k in ba if k in bb and ba[k] != bb[k]),
        "trace_rerun": sb.get("trace", {}),
        "pass": len(flips) <= allowance and overlap,
    }


def _benign(run_dir: Path) -> list[BenignResult]:
    lines = (run_dir / "benign.jsonl").read_text().splitlines()
    return [BenignResult.model_validate_json(x) for x in lines]
