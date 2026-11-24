from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

import parry.canary as canary
from parry.judges import panel
from tests.test_analysis import S, _complete, _run


class _Resp:
    def __init__(self, content: str) -> None:
        self.content = content

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict[str, Any]:
        return {"message": {"content": self.content}}


def test_panel_is_blind_and_records_models(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "m"
    (root / "t" / "redact_output").mkdir(parents=True)
    _complete(_run(root / "t" / "redact_output", "r", {"case-77": (True, S["system_canary"])}))
    sent: list[dict[str, Any]] = []

    def fake_post(url: str, json: dict[str, Any], timeout: float) -> _Resp:
        sent.append(json)
        verdict = "t" if json["model"] == "a" else "f"
        return _Resp('{"label": "' + verdict + '", "reason": "because"}')

    real = canary.secrets_for
    monkeypatch.setattr(canary, "secrets_for", lambda target, seed=None: real("t", "seed"))
    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setattr(
        panel, "ollama_info", lambda url: {"version": "x", "models": {"a": "d1", "b": "d2"}}
    )
    item = {
        "target": "t",
        "config": "redact_output",
        "case_id": "case-77",
        "secret": "system_canary",
        "evidence_type": "residual-entropy",
        "finding": {"how": "entropy"},
    }
    res = panel.run_panel(root, [item], models=("a", "b"), seed=7)
    assert res["models"] == {"a": "d1", "b": "d2"} and res["seed"] == 7
    assert res["wording"] == "LLM-panel labels, not human-verified"
    out = res["items"][0]
    assert out["panel"]["a"]["label"] is True and out["panel"]["b"]["label"] is False
    assert out["panel_agreed"] is None  # disagreement stays unresolved
    for req in sent:
        text = json.dumps(req["messages"])
        assert S["system_canary"] in text and panel.LABELING_RULE in text
        for hidden in ("redact_output", "case-77", "entropy", "residual", "verdict", "because"):
            assert hidden not in text  # no config, case, evidence type, or other labels
        assert req["options"]["temperature"] == 0 and req["options"]["seed"] == 7
    assert panel.agreement(res["items"], ("a", "b"))["agree"] == 0


def test_unparseable_label_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx, "post", lambda url, json, timeout: _Resp("not json"))
    assert panel.label_one("a", "s", ["r"], url="http://x", seed=1)["label"] is None
