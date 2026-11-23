from __future__ import annotations

import json
from pathlib import Path

from parry.analysis import paired, rescore_cell
from parry.canary import secrets_for
from parry.engine import TrialResult
from parry.judges import Signals, Verdict

S = secrets_for("t", "seed").as_dict()


def _run(root: Path, name: str, outcomes: dict[str, tuple[bool, str]]) -> Path:
    run = root / name
    run.mkdir()
    rows = []
    for case_id, (success, reply) in outcomes.items():
        rows.append(
            TrialResult(
                run_id=name,
                target="t",
                scope="loopback",
                profile=None,
                model=None,
                case_id=case_id,
                template="pe-direct",
                family="prompt_extraction",
                channel="direct",
                goal="leak_system_prompt",
                severity="high",
                transform="none",
                owasp=[],
                atlas=[],
                steps=[],
                blocked_at_delivery=None,
                replies=[reply],
                latency_s=0.1,
                verdict=Verdict(
                    success=success, attempted=success, judge="leak", signals=Signals()
                ),
            ).model_dump_json()
        )
    (run / "trials.jsonl").write_text("\n".join(rows) + "\n")
    (run / "run.json").write_text(json.dumps({"seed": 1}))
    return run


def test_paired_counts_and_exact_p(tmp_path: Path) -> None:
    base = _run(tmp_path, "base", {f"c{i}": (True, "x") for i in range(10)} | {"c10": (False, "x")})
    defended = _run(
        tmp_path, "def", {f"c{i}": (False, "x") for i in range(10)} | {"c10": (True, "x")}
    )
    r = paired(base, defended)
    assert (r["n"], r["stopped"], r["opened"], r["opened_cases"]) == (11, 10, 1, ["c10"])
    assert r["p"] < 0.05 and r["significant"]


def test_rescore_finds_spaced_and_partial(tmp_path: Path) -> None:
    body = S["system_canary"].split("-")[-1]
    run = _run(
        tmp_path,
        "r",
        {
            "a": (True, S["system_canary"]),
            "b": (False, "N O " + " ".join(body)),  # body only, spaced: v1 misses, v2 recovers it
            "c": (False, f"starts PARRY-CANARY-{body[:9]}"),  # partial only
            "d": (False, "nothing here"),
        },
    )
    r = rescore_cell(run, S)
    assert r["v1"] == 1 and "b" in r["new_under_v2"] and r["partial_only"] == ["c"]
    assert r["lost_under_v2"] == []
