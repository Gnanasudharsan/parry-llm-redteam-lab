"""The scan loop: for each authorized target and each applicable case, reset -> deliver ->
judge -> record. Results go to `runs/<run_id>/trials.jsonl` as they happen."""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from parry import __version__
from parry.adapters import make_adapter
from parry.attacks.model import AttackCase
from parry.channels import ChannelUnavailableError, Delivery, deliver
from parry.config import ParryConfig
from parry.judges import Verdict, judge
from parry.judges.llm import LlmJudge
from parry.lab import LabClient
from parry.provenance import ollama_info
from parry.scope import AuthorizedTarget

MAX_TEXT = 4000


class TrialResult(BaseModel):
    run_id: str
    target: str
    scope: str
    profile: str | None
    model: str | None
    case_id: str
    template: str
    family: str
    channel: str
    goal: str
    severity: str
    transform: str
    owasp: list[str]
    atlas: list[str]
    steps: list[str]
    blocked_at_delivery: str | None
    replies: list[str]
    verdict: Verdict | None
    skipped: str | None = None
    error: str | None = None
    latency_s: float


def _git_commit() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],  # noqa: S607 - git on PATH
            capture_output=True,
            text=True,
            check=True,
        )
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _git_dirty() -> bool | None:
    try:
        out = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],  # noqa: S607 - git on PATH
            capture_output=True,
            text=True,
            check=True,
        )
        return bool(out.stdout.strip())
    except (OSError, subprocess.CalledProcessError):
        return None


def cases_hash(cases: list[AttackCase]) -> str:
    blob = json.dumps([c.model_dump(mode="json") for c in cases], sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:12]


def run_scan(
    cfg: ParryConfig,
    targets: list[AuthorizedTarget],
    cases: list[AttackCase],
    out_root: Path,
    *,
    use_llm_judge: bool = True,
    progress: Callable[[str], None] = print,
) -> Path:
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + f"-s{cfg.seed}"
    out = out_root / run_id
    out.mkdir(parents=True, exist_ok=False)
    llm = LlmJudge(str(cfg.judge.llm_url), cfg.judge.llm_model, cfg.seed) if use_llm_judge else None
    meta: dict[str, Any] = {
        "run_id": run_id,
        "parry_version": __version__,
        "git_commit": _git_commit(),
        "git_dirty": _git_dirty(),
        "seed": cfg.seed,
        "cases_hash": cases_hash(cases),
        "judge_model": cfg.judge.llm_model if use_llm_judge else None,
        "ollama": ollama_info(str(cfg.judge.llm_url)),
        "targets": [],
        "started": datetime.now(UTC).isoformat(),
    }

    with (out / "trials.jsonl").open("w") as fh:
        for auth in targets:
            t = auth.target
            adapter = make_adapter(t)
            lab = LabClient(cfg, t) if t.lab else None
            state = lab.state() if lab else {}
            secrets = (
                lab.secrets().as_dict()
                if lab
                else {f"canary_{i}": v for i, v in enumerate(t.canaries)}
            )
            applicable = [c for c in cases if t.app in c.apps]
            meta["targets"].append(
                {
                    "name": t.name,
                    "app": t.app,
                    "scope": auth.scope,
                    "profile": state.get("profile", {}).get("name"),
                    "model": state.get("model"),
                    "owner_statement": t.owner_statement,
                    "cases": len(applicable),
                }
            )
            progress(f"== {t.name}: {len(applicable)} cases")
            for case in applicable:
                t0 = time.perf_counter()
                delivery, verdict, skipped, error = Delivery(), None, None, None
                try:
                    if lab:
                        lab.reset()
                    delivery = deliver(case, adapter, lab)
                    events = lab.events() if lab else []
                    hits = lab.hits() if lab else []
                    verdict = judge(case, delivery, events, hits, secrets, llm)
                except ChannelUnavailableError as exc:
                    skipped = str(exc)
                except Exception as exc:  # recorded per trial; the scan continues
                    error = f"{exc.__class__.__name__}: {exc}"[:500]
                if not skipped and not error and any(r.error for r in delivery.replies) and verdict:
                    error = "; ".join(r.error or "" for r in delivery.replies if r.error)[:500]
                trial = TrialResult(
                    run_id=run_id,
                    target=t.name,
                    scope=auth.scope,
                    profile=meta["targets"][-1]["profile"],
                    model=meta["targets"][-1]["model"],
                    case_id=case.case_id,
                    template=case.template,
                    family=case.family,
                    channel=case.channel,
                    goal=case.goal,
                    severity=case.severity,
                    transform=case.transform,
                    owasp=case.owasp,
                    atlas=case.atlas,
                    steps=delivery.steps,
                    blocked_at_delivery=delivery.blocked_at_delivery,
                    replies=[r.text[:MAX_TEXT] for r in delivery.replies],
                    verdict=verdict,
                    skipped=skipped,
                    error=error,
                    latency_s=round(time.perf_counter() - t0, 3),
                )
                fh.write(trial.model_dump_json() + "\n")
                fh.flush()
                mark = (
                    "skip"
                    if skipped
                    else (
                        "ERR "
                        if verdict is None
                        else (
                            "HIT " if verdict.success else ("try " if verdict.attempted else "    ")
                        )
                    )
                )
                progress(f"  {mark} {t.name} {case.case_id}")
    meta["finished"] = datetime.now(UTC).isoformat()
    (out / "run.json").write_text(json.dumps(meta, indent=2) + "\n")
    return out


def load_trials(run_dir: Path) -> list[TrialResult]:
    lines = (run_dir / "trials.jsonl").read_text().splitlines()
    return [TrialResult.model_validate_json(line) for line in lines if line.strip()]
