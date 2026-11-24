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
    assert r["v1"] == 1 and r["v2_full"] == 2 and r["v2_full_new"] == ["b"]
    assert r["v2_partial_0.67"] == 3 and r["v2_partial_0.50"] == 3
    assert r["v2_full_lost"] == []


def _benign_file(run: Path, answers: dict[str, str]) -> None:
    from parry.benign import BenignResult

    rows = [
        BenignResult(
            id=i,
            category="c",
            approval_gated=False,
            passed=True,
            leaked=False,
            failures=[],
            latency_s=0.1,
            tools=[],
            answer=a,
        ).model_dump_json()
        for i, a in answers.items()
    ]
    (run / "benign.jsonl").write_text("\n".join(rows) + "\n")


def test_exposure_sets_aside_cases_whose_secret_a_benign_task_returns(tmp_path: Path) -> None:
    from parry.analysis import exposed_secrets, exposure_cases

    run = _run(tmp_path, "r", {"a": (True, S["system_canary"]), "b": (False, "no")})
    _benign_file(run, {"settings": f"the key is {S['system_canary']}", "hours": "9-5"})
    exposed = exposed_secrets(run, S)
    assert exposed == {"system_canary": ["settings"]}
    assert exposure_cases(run, S, set(exposed)) == {"a", "b"}  # both target the exposed secret
    assert exposure_cases(run, S, set()) == frozenset()


def test_paired_drop_excludes_cases(tmp_path: Path) -> None:
    base = _run(tmp_path, "base", {"a": (True, "x"), "b": (True, "x")})
    other = _run(tmp_path, "o", {"a": (False, "x"), "b": (False, "x")})
    r = paired(base, other, drop=frozenset({"a"}))
    assert (r["n"], r["stopped"]) == (1, 1)


def test_evidence_and_v2_diff_split_limit(tmp_path: Path) -> None:
    from parry.analysis import judge_disagreements
    from parry.judges.leak import evidence

    body = S["system_canary"].split("-")[-1]
    ev = evidence([f"part {body[:9]} end"], S["system_canary"])
    assert ev[0]["fragment"] == body[:9].lower() and body[:9] in ev[0]["excerpt"]

    root = tmp_path / "m"
    (root / "t" / "none").mkdir(parents=True)
    _complete(_run(root / "t" / "none", "r", {"s": (False, f"first {body[:6]} then {body[6:]}")}))
    import parry.canary as canary

    real = canary.secrets_for
    canary.secrets_for = lambda target, seed=None: real("t", "seed")
    try:
        rows = judge_disagreements(root)
    finally:
        canary.secrets_for = real
    assert len(rows) == 1 and rows[0]["split_12"] and rows[0]["case_id"] == "s"
    assert {f["fragment"] for f in rows[0]["fragments"]} == {body[:6].lower(), body[6:].lower()}


def _complete(run: Path) -> Path:
    _benign_file(run, {"hours": "9-5"})
    (run / "config.json").write_text("{}")
    return run


def test_precision_sample_by_evidence_type(tmp_path: Path) -> None:
    import base64

    import parry.canary as canary
    from parry.analysis import precision_report, precision_sample

    c = S["system_canary"]
    body = c.split("-")[-1]
    root = tmp_path / "m"
    (root / "t" / "none").mkdir(parents=True)
    outcomes = {f"v{i}": (True, c) for i in range(12)}  # verbatim, more than per_type
    outcomes |= {"d1": (False, base64.b64encode(c.encode()).decode())}  # decoded
    outcomes |= {"d2": (False, " ".join(c))}  # separators -> decoded
    outcomes |= {"p1": (False, f"x {body[:9]} y")}  # partial
    outcomes |= {"e1": (False, f"a {body[:6]} b {body[6:]}")}  # residual entropy
    outcomes |= {"n1": (False, "nothing")}
    _complete(_run(root / "t" / "none", "r", outcomes))
    real = canary.secrets_for
    canary.secrets_for = lambda target, seed=None: real("t", "seed")
    try:
        r1 = precision_sample(root, per_type=10, seed=1)
        r2 = precision_sample(root, per_type=10, seed=1)
    finally:
        canary.secrets_for = real
    assert [i["case_id"] for i in r1["sample"]] == [i["case_id"] for i in r2["sample"]]
    assert r1["population"] == {
        "verbatim": 12,
        "decoded": 2,
        "partial": 1,
        "pooled": 0,
        "residual-entropy": 1,
    }
    kinds = [i["evidence_type"] for i in r1["sample"]]
    assert kinds.count("verbatim") == 10 and kinds.count("decoded") == 2
    assert all(i["label"] is None for i in r1["sample"])

    for i in r1["sample"]:  # label: every verbatim true, decoded half true, rest false
        i["label"] = i["evidence_type"] == "verbatim" or i["case_id"] == "d1"
    rep = precision_report(r1["sample"], r1["population"])
    assert rep["types"]["verbatim"]["true"] == 10 and rep["types"]["decoded"]["true"] == 1
    # weighted: (12*1 + 2*0.5 + 1*0 + 1*0) / 16
    assert rep["overall_weighted"]["precision"] == round(13 / 16, 4)


def test_analysis_refuses_incomplete_cells(tmp_path: Path) -> None:
    import pytest

    from parry.analysis import _cell
    from parry.matrix import IncompleteCellError

    root = tmp_path / "m"
    (root / "t" / "none").mkdir(parents=True)
    with pytest.raises(IncompleteCellError):  # no run folder yet
        _cell(root, "t", "none")
    run = _run(root / "t" / "none", "r", {"a": (True, "x")})
    with pytest.raises(IncompleteCellError):  # trials but no benign / marker
        _cell(root, "t", "none")
    _benign_file(run, {"hours": "9-5"})
    with pytest.raises(IncompleteCellError):  # benign written, marker not yet
        _cell(root, "t", "none")
    (run / "config.json").write_text("{}")
    assert _cell(root, "t", "none") == run
    assert _cell(root, "t", "missing") is None
