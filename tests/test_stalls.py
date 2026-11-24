from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from parry.benign import BenignResult
from parry.stalls import ollama_stalls, stalled_benign

LOG = """\
time=2026-11-23T22:50:17.709-05:00 level=INFO msg="starting llama-server" cmd=x
time=2026-11-23T22:55:25.052-05:00 level=INFO msg="Load failed" model=y error=
time=2026-11-23T22:58:38.670-05:00 level=INFO msg="starting llama-server" cmd=x
time=2026-11-23T22:58:38.925-05:00 level=INFO msg="loaded runners" count=3
time=2026-11-23T23:00:00.000-05:00 level=INFO msg="starting llama-server" cmd=x
time=2026-11-23T23:00:40.000-05:00 level=INFO msg="loaded runners" count=2
"""


def test_parse_stalls(tmp_path: Path) -> None:
    log = tmp_path / "ollama.log"
    log.write_text(LOG)
    s = ollama_stalls(log)
    assert [(x["outcome"], x["seconds"]) for x in s] == [("failed", 307.3), ("loaded", 40.0)]
    assert s[0]["start"].startswith("2026-11-24T03:50:17")  # stored in UTC


def _row(i: str, lat: float, attempt: int = 1, err: bool = False) -> BenignResult:
    return BenignResult(
        id=i, category="c", approval_gated=False, passed=not err, leaked=False,
        failures=["error: boom"] if err else [], latency_s=lat, tools=[], answer="",
        attempt=attempt,
    )  # fmt: skip


def test_window_bounds_flag_only_overlapping_tasks(tmp_path: Path) -> None:
    run = tmp_path / "r"
    run.mkdir()
    t0 = datetime(2026, 11, 24, 4, 0, 0, tzinfo=UTC)
    (run / "run.json").write_text(
        json.dumps({"started": t0.isoformat(), "finished": t0.isoformat()})
    )
    rows = [_row("a", 10), _row("b", 10), _row("c", 10)]  # ~ 0-10 s, 10-20 s, 20-30 s
    (run / "benign.jsonl").write_text("x")
    end = t0.timestamp() + 31  # 1 s of slack between tasks in total
    os.utime(run / "benign.jsonl", (end, end))
    stall = [{"start": "2026-11-24T04:00:12+00:00", "end": "2026-11-24T04:00:15+00:00"}]
    # b certainly ran 10-21 s; a can end by 11 s at the latest; c cannot start before 20 s
    assert stalled_benign(run, rows, stall) == {("b", 1)}


def test_summary_excludes_errored_and_uses_latest(tmp_path: Path) -> None:
    from parry.matrix import cell_summary
    from tests.test_analysis import _run

    run = _run(tmp_path, "r", {"x": (True, "y")})
    rows = [_row("a", 1.0), _row("b", 50.0, err=True), _row("b", 2.0, attempt=2), _row("c", 3.0)]
    (run / "benign.jsonl").write_text("".join(r.model_dump_json() + "\n" for r in rows))
    (run / "config.json").write_text("{}")
    meta = json.loads((run / "run.json").read_text())
    meta |= {"targets": [{"retried": []}], "started": "2026-11-24T04:00:00+00:00",
             "finished": "2026-11-24T04:00:01+00:00"}  # fmt: skip
    (run / "run.json").write_text(json.dumps(meta))
    s = cell_summary(run)
    assert s["utility"]["n"] == 3 and s["utility"]["k"] == 3  # latest attempt of b counts
    assert s["latency_n"] == 3 and s["latency_median_s"] == 2.0  # the 50 s errored try is out
    assert s["had_retry"] and s["retried"]["benign"] == ["b"]
