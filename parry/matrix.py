"""Defense matrix: attacks x channels x targets x defense configurations, plus utility.

For each authorized lab target and each configuration: reconfigure the running app, run the
attack suite (engine.run_scan) and the benign task set (benign.run_benign), and keep both
next to each other so security and utility come from the same app state.
"""

from __future__ import annotations

import json
import statistics
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from parry.adapters import make_adapter
from parry.attacks.model import AttackCase
from parry.benign import BenignResult, run_benign
from parry.config import AppType, ParryConfig
from parry.engine import load_trials, run_scan
from parry.lab import LabClient
from parry.metrics import wilson_interval
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
    progress: Callable[[str], None] = print,
) -> Path:
    out = out_root / ("matrix-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"))
    out.mkdir(parents=True)
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
                    cfg, [auth], cases, cell, use_llm_judge=use_llm_judge, progress=lambda s: None
                )
                benign = run_benign(make_adapter(t), lab, tasks)
                (run_dir / "benign.jsonl").write_text(
                    "".join(b.model_dump_json() + "\n" for b in benign)
                )
                (run_dir / "config.json").write_text(
                    json.dumps(
                        {**mc.model_dump(mode="json"), "applied": lab.state().get("defenses")},
                        indent=2,
                    )
                )
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


def cell_summary(run_dir: Path) -> dict[str, Any]:
    trials = scored(load_trials(run_dir))
    benign = [
        BenignResult.model_validate_json(x)
        for x in (run_dir / "benign.jsonl").read_text().splitlines()
    ]
    core = [b for b in benign if not b.approval_gated]
    lat = sorted(b.latency_s for b in core)
    return {
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
            run_dir = next(p for p in cfg_dir.iterdir() if p.is_dir())
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
