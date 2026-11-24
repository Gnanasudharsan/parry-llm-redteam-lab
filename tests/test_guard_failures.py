from __future__ import annotations

from typing import Any

import pytest

from parry import benign
from parry.canary import secrets_for
from parry.engine import guard_failures
from parry.tasks import TaskSet

EVENTS = [
    {"type": "defense", "name": "llama_guard", "data": {"hook": "input", "flagged": False,
                                                        "error": "ReadTimeout: timed out"}},
    {"type": "defense", "name": "pi_classifier", "data": {"hook": "input", "flagged": False}},
    {"type": "tool_called", "name": "x", "data": {}},
]  # fmt: skip


def test_guard_failures_lists_only_errored_decisions() -> None:
    assert guard_failures(EVENTS) == ["llama_guard@input: ReadTimeout: timed out"]
    assert guard_failures(EVENTS[1:]) == []


class _Lab:
    def __init__(self, events: list[dict[str, Any]]) -> None:
        self._events = events

    def secrets(self) -> Any:
        return secrets_for("t", "seed")

    def reset(self) -> None:
        pass

    def events(self) -> list[dict[str, Any]]:
        return self._events


def test_benign_task_with_failed_open_guard_is_errored_and_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(benign, "_run_one", lambda adapter, task: ("Open at 9.", [], None))
    tasks = TaskSet.model_validate(
        {"target_type": "rag", "tasks": [
            {"id": "hours", "category": "c", "message": "hours?", "check": {"any_of": ["9"]}}
        ]}
    )  # fmt: skip
    rows = benign.run_benign(object(), _Lab(EVENTS), tasks)  # type: ignore[arg-type]
    assert [(r.attempt, r.errored, r.passed) for r in rows] == [(1, True, False), (2, True, False)]
    assert rows[0].guard_errors == ["llama_guard@input: ReadTimeout: timed out"]
    ok = benign.run_benign(object(), _Lab(EVENTS[1:]), tasks)  # type: ignore[arg-type]
    assert [(r.attempt, r.passed) for r in ok] == [(1, True)]
