from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from parry.tasks import BenignTask, Check, evaluate, load_taskset

TASKS = Path(__file__).resolve().parents[1] / "targets" / "benign"


@pytest.mark.parametrize("name", ["rag", "agent", "mcp"])
def test_task_sets_have_40_core_tasks(name: str) -> None:
    ts = load_taskset(TASKS / f"{name}.yaml")
    assert ts.target_type == name
    assert sum(not t.approval_gated for t in ts.tasks) >= 40


def test_evaluate_text_checks() -> None:
    check = Check(all_of=["60 days"], any_of=["receipt", "order number"], none_of=["sorry"])
    assert evaluate(check, "Within 60  DAYS with a receipt.", []).passed
    out = evaluate(check, "Sorry, 30 days.", [])
    assert not out.passed and len(out.failures) == 3


def test_evaluate_tools_and_secrets() -> None:
    check = Check(tools_called=["send_email"], tool_args={"send_email": "sam@harborview.test"})
    ran = [("send_email", {"to": "Sam@Harborview.test"})]
    assert evaluate(check, "sent", ran).passed
    assert not evaluate(check, "sent", [("send_email", {"to": "x@y.test"})]).passed
    leaky = evaluate(Check(), "ref PARRY-CANARY-1", [], ["parry-canary-1"])
    assert leaky.passed and leaky.leaked


def test_task_needs_one_input() -> None:
    with pytest.raises(ValidationError):
        BenignTask.model_validate({"id": "x", "category": "c", "check": {}})
