from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import parry.engine as engine
from parry.adapters import Reply
from parry.attacks.catalog import expand, load_templates
from parry.benign import BenignResult, latest
from parry.channels import Delivery
from parry.config import ParryConfig
from parry.engine import load_trials, run_scan
from parry.scope import authorize


def test_errored_case_is_retried_once_and_both_attempts_kept(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: dict[str, int] = {}

    def flaky(case: Any, adapter: Any, lab: Any) -> Delivery:
        calls[case.case_id] = calls.get(case.case_id, 0) + 1
        if case.case_id == "pe-direct/01" and calls[case.case_id] == 1:
            raise TimeoutError("model timed out")
        if case.case_id == "pe-direct/02":
            raise TimeoutError("always down")
        return Delivery(replies=[Reply(text="no")])

    monkeypatch.setattr(engine, "deliver", flaky)
    cfg = ParryConfig.model_validate(
        {
            "targets": [
                {
                    "name": "t",
                    "kind": "http",
                    "url": "http://localhost:1",
                    "app": "rag",
                    "owner_statement": "local test target",
                }
            ]
        }
    )
    cases = [
        c
        for c in expand(load_templates(), 1)
        if c.case_id in {"pe-direct/01", "pe-direct/02", "pe-direct/03"}
    ]
    run = run_scan(
        cfg,
        authorize(cfg, ["t"]),
        cases,
        tmp_path,
        use_llm_judge=False,
        progress=lambda _: None,
        code=("abc1234", False),  # a matrix pins the commit it loaded at process start
    )
    meta = json.loads((run / "run.json").read_text())
    assert (meta["git_commit"], meta["git_dirty"]) == ("abc1234", False)

    everything = load_trials(run, all_attempts=True)
    assert [(t.case_id, t.attempt, t.error is None) for t in everything] == [
        ("pe-direct/01", 1, False),
        ("pe-direct/02", 1, False),
        ("pe-direct/03", 1, True),
        ("pe-direct/01", 2, True),
        ("pe-direct/02", 2, False),
    ]
    latest_trials = {t.case_id: t for t in load_trials(run)}
    assert latest_trials["pe-direct/01"].attempt == 2 and latest_trials["pe-direct/01"].verdict
    meta = json.loads((run / "run.json").read_text())["targets"][0]
    assert meta["retried"] == ["pe-direct/01", "pe-direct/02"]
    assert meta["failed_after_retry"] == ["pe-direct/02"]
    assert calls == {"pe-direct/01": 2, "pe-direct/02": 2, "pe-direct/03": 1}


def test_benign_latest_attempt() -> None:
    base = {
        "category": "c",
        "approval_gated": False,
        "leaked": False,
        "latency_s": 0.1,
        "tools": [],
        "answer": "",
    }
    first = BenignResult(id="a", passed=False, failures=["error: timeout"], **base)
    retry = BenignResult(id="a", passed=True, failures=[], attempt=2, **base)
    other = BenignResult(id="b", passed=True, failures=[], **base)
    assert first.errored and not retry.errored
    assert {(r.id, r.attempt) for r in latest([first, other, retry])} == {("a", 2), ("b", 1)}
