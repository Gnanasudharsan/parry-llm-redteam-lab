"""Aggregate trials into attack success rates with 95% Wilson intervals."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from typing import Any

from parry.attacks.model import AttackCase
from parry.engine import TrialResult
from parry.mapping import ATLAS_TECHNIQUES, OWASP_LLM_2025
from parry.metrics import wilson_interval


def _rate(rows: list[TrialResult], pred: Callable[[TrialResult], bool]) -> dict[str, Any]:
    r = wilson_interval(sum(pred(t) for t in rows), len(rows))
    return {"k": r.successes, "n": r.trials, "rate": r.point, "low": r.low, "high": r.high}


def scored(trials: Iterable[TrialResult]) -> list[TrialResult]:
    """Trials with a verdict. Skipped and errored trials are reported, never counted as 0."""
    return [t for t in trials if t.verdict is not None]


def _success(t: TrialResult) -> bool:
    return bool(t.verdict and t.verdict.success)


def _attempt(t: TrialResult) -> bool:
    return bool(t.verdict and t.verdict.attempted)


def group(
    trials: list[TrialResult], key: Callable[[TrialResult], str]
) -> dict[str, dict[str, Any]]:
    buckets: dict[str, list[TrialResult]] = defaultdict(list)
    for t in trials:
        buckets[key(t)].append(t)
    return {k: _stats(v) for k, v in sorted(buckets.items())}


def _stats(rows: list[TrialResult]) -> dict[str, Any]:
    known = [t for t in rows if t.verdict and t.verdict.delivered is not None]
    delivered = [t for t in known if t.verdict and t.verdict.delivered]
    return {
        "asr": _rate(rows, _success),
        "attempt": _rate(rows, _attempt),
        "delivered": _rate(known, lambda t: bool(t.verdict and t.verdict.delivered)),
        "asr_delivered": _rate(delivered, _success),
    }


def summarize(trials: list[TrialResult], cases: list[AttackCase] | None = None) -> dict[str, Any]:
    ok = scored(trials)
    targets = sorted({t.target for t in trials})
    out: dict[str, Any] = {
        "targets": {},
        "totals": {
            "trials": len(trials),
            "scored": len(ok),
            "skipped": sum(t.skipped is not None for t in trials),
            "errors": sum(t.error is not None and t.verdict is None for t in trials),
        },
    }
    for name in targets:
        rows = [t for t in ok if t.target == name]
        first = next(t for t in trials if t.target == name)
        out["targets"][name] = {
            "profile": first.profile,
            "model": first.model,
            "overall": _stats(rows),
            "critical": {"asr": _rate([t for t in rows if t.severity == "critical"], _success)},
            "by_family": group(rows, lambda t: t.family),
            "by_channel": group(rows, lambda t: t.channel),
            "by_goal": group(rows, lambda t: t.goal),
        }
    out["coverage"] = coverage(cases) if cases is not None else None
    return out


def coverage(cases: list[AttackCase]) -> dict[str, Any]:
    """Which OWASP / ATLAS IDs the suite exercises, generated from attack metadata."""
    table: dict[str, dict[str, Any]] = {}
    for tid, entry in {**OWASP_LLM_2025, **ATLAS_TECHNIQUES}.items():
        hits = [c for c in cases if tid in c.owasp or tid in c.atlas]
        table[tid] = {
            "name": entry.name,
            "framework": entry.framework,
            "cases": len(hits),
            "families": sorted({c.family for c in hits}),
            "channels": sorted({c.channel for c in hits}),
        }
    return table
