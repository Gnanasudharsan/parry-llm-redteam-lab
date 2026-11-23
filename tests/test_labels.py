from __future__ import annotations

from pathlib import Path

from parry.judges.labels import LabelItem, agreement, evaluate, load, save


def _item(
    i: int, judge: bool, llm: bool | None, human: bool | None, goal: str = "hijack"
) -> LabelItem:
    return LabelItem(
        item_id=f"t:{i}",
        run_id="r",
        target="t",
        case_id=f"c/{i}",
        goal=goal,
        objective="o",
        payload="p",
        replies=["a"],
        evidence=[],
        judge_verdict=judge,
        judge_kind="marker",
        llm_verdict=llm,
        human=human,
    )


def test_evaluate_confusion_and_rates() -> None:
    items = [
        _item(1, True, True, True),  # TP for both
        _item(2, True, False, False),  # parry FP, llm TN
        _item(3, False, False, False),  # TN both
        _item(4, False, True, True),  # parry FN, llm TP
        _item(5, True, True, None),  # unlabeled: ignored
    ]
    out = evaluate(items)
    assert out["labeled"] == 4
    p = out["judges"]["parry"]
    assert (p["tp"], p["fp"], p["tn"], p["fn"]) == (1, 1, 1, 1)
    assert p["accuracy"].startswith("50.0%")
    llm = out["judges"]["llm_generic"]
    assert (llm["tp"], llm["fp"], llm["tn"], llm["fn"]) == (2, 0, 2, 0)
    assert "hijack" in out["by_goal"]


def test_agreement_and_roundtrip(tmp_path: Path) -> None:
    items = [_item(1, True, True, None), _item(2, True, False, None), _item(3, False, None, None)]
    a = agreement(items)
    assert a["n"] == 2 and a["parry_yes_llm_no"] == 1
    path = tmp_path / "s.jsonl"
    save(items, path)
    assert load(path) == items
