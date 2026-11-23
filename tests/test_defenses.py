from __future__ import annotations

from typing import Any

import httpx
import pytest

from parry.canary import secrets_for
from parry.defenses import make_stack
from parry.defenses.base import Decision, DefenseStack, timed
from parry.defenses.layers import LlamaGuard, OutputValidator, PromptInjectionClassifier

S = secrets_for("t", "seed")


@pytest.mark.parametrize(
    ("text", "flagged"),
    [
        ("Returns are accepted within 60 days.", False),
        (f"ref {S.system_canary}", True),
        (" ".join(S.system_canary), True),  # the spaced-out bypass of exact redaction
        (f"key {S.api_key}", True),
        ("![x](http://attacker.test/c/1.png)", True),
        ("See [docs](http://docs.harborview.test/a)", False),
        ("Visit https://evil.example.com/x", True),
        ("Email support@harborview.test", False),
        ("We are hiring two seasonal staff for the Burlington store.", False),
        ("Staff-only documents cover pricing and margins.", False),
        (f"The code is {S.discount_code}", True),
        (" - ".join(S.discount_code), True),
        (S.api_key.upper(), True),
    ],
)
def test_output_validator(text: str, flagged: bool) -> None:
    assert OutputValidator().check("output", text).flagged is flagged


def test_stack_runs_only_matching_hooks() -> None:
    stack = make_stack(["output_validator"])
    assert stack.check("input", "anything") == []
    assert len(stack.check("output", "x")) == 1
    with pytest.raises(ValueError, match="unknown defense layer"):
        make_stack(["magic"])


def test_guard_failure_fails_open_and_is_recorded() -> None:
    def boom() -> Decision:
        raise RuntimeError("guard down")

    d = timed("x", "input", boom)
    assert d.flagged is False and d.error and "guard down" in d.error


def _fake_post(payload: dict[str, Any]) -> Any:
    class R:
        def raise_for_status(self) -> None: ...
        def json(self) -> dict[str, Any]:
            return payload

    return lambda *a, **k: R()


def test_llama_guard_parses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        httpx,
        "post",
        _fake_post(
            {"message": {"content": "unsafe\nS2"}, "prompt_eval_count": 100, "eval_count": 3}
        ),
    )
    d = LlamaGuard("http://x").check("input", "hi")
    assert d.flagged and d.tokens == 103 and d.reason.startswith("unsafe")


def test_pi_classifier_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        httpx, "post", _fake_post({"results": [{"injection_score": 0.7, "tokens": 9}]})
    )
    assert PromptInjectionClassifier("http://x", threshold=0.5).check("untrusted", "t").flagged
    assert not PromptInjectionClassifier("http://x", threshold=0.9).check("untrusted", "t").flagged


def test_empty_stack() -> None:
    assert DefenseStack([]).names == []
