"""Model-load stalls in Ollama and which benign requests they may have hit.

A stall is a model load that failed or took at least STALL_S seconds (Ollama log: "starting
llama-server" until "loaded runners" or "Load failed"). Latency statistics leave out any
benign request whose time window may overlap a stall.

Request windows: results written before start times were recorded (Phase 3 matrix cells) are
bounded, not estimated. Benign tasks run one after another between the scan's `finished`
time and the moment `benign.jsonl` is written; task i cannot start before
finished + sum(latency of earlier tasks) and cannot end after
written - sum(latency of later tasks). Any overlap between that window and a stall excludes
the task (conservative: it may exclude a request that did not wait). Results with a
`started` timestamp use the exact window.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

STALL_S = 30.0
_TIME = re.compile(r'^time=(\S+) .*msg="([^"]+)"')


def ollama_stalls(log: Path, min_seconds: float = STALL_S) -> list[dict[str, Any]]:
    """Model loads in an `ollama serve` log that failed or took >= min_seconds."""
    out: list[dict[str, Any]] = []
    start: datetime | None = None
    for line in log.read_text(errors="replace").splitlines():
        m = _TIME.match(line)
        if not m:
            continue
        t = datetime.fromisoformat(m.group(1))
        msg = m.group(2)
        if msg == "starting llama-server":
            start = t
        elif start is not None and msg in ("loaded runners", "Load failed"):
            seconds = (t - start).total_seconds()
            failed = msg == "Load failed"
            if failed or seconds >= min_seconds:
                out.append(
                    {
                        "start": start.astimezone(UTC).isoformat(),
                        "end": t.astimezone(UTC).isoformat(),
                        "seconds": round(seconds, 1),
                        "outcome": "failed" if failed else "loaded",
                    }
                )
            start = None
    return out


def _intervals(stalls: list[dict[str, Any]]) -> list[tuple[datetime, datetime]]:
    return [(datetime.fromisoformat(s["start"]), datetime.fromisoformat(s["end"])) for s in stalls]


def cell_span(run_dir: Path) -> tuple[datetime, datetime]:
    """From the scan's start to the moment the benign results were written."""
    meta = json.loads((run_dir / "run.json").read_text())
    end = datetime.fromtimestamp((run_dir / "benign.jsonl").stat().st_mtime, UTC)
    return datetime.fromisoformat(meta["started"]), end


def stalls_in_cell(run_dir: Path, stalls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    lo, hi = cell_span(run_dir)
    return [s for s, (a, b) in zip(stalls, _intervals(stalls), strict=True) if a < hi and b > lo]


def stalled_benign(
    run_dir: Path, rows: list[Any], stalls: list[dict[str, Any]]
) -> set[tuple[str, int]]:
    """(task id, attempt) of benign requests whose possible window overlaps a stall.

    `rows` are the BenignResult rows in file order (all attempts)."""
    spans = _intervals(stalls)
    if not spans or not rows:
        return set()
    meta = json.loads((run_dir / "run.json").read_text())
    phase_start = datetime.fromisoformat(meta["finished"])
    written = datetime.fromtimestamp((run_dir / "benign.jsonl").stat().st_mtime, UTC)
    lats = [float(r.latency_s) for r in rows]
    out: set[tuple[str, int]] = set()
    for i, r in enumerate(rows):
        started = getattr(r, "started", None)
        if started:
            lo = datetime.fromisoformat(started)
            hi = lo + timedelta(seconds=lats[i])
        else:
            lo = phase_start + timedelta(seconds=sum(lats[:i]))
            hi = written - timedelta(seconds=sum(lats[i + 1 :]))
        if any(a < hi and b > lo for a, b in spans):
            out.add((r.id, r.attempt))
    return out
