from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import Field

from targets.lab.profile import Profile, profile_from_env


class ScriptedModel(BaseChatModel):
    """Returns scripted replies in order and records every prompt it was given."""

    script: list[AIMessage] = Field(default_factory=list)
    seen: list[list[BaseMessage]] = Field(default_factory=list)

    def _generate(
        self, messages: list[BaseMessage], stop: Any = None, run_manager: Any = None, **kwargs: Any
    ) -> ChatResult:
        self.seen.append(list(messages))
        msg = self.script.pop(0) if self.script else AIMessage("done")
        return ChatResult(generations=[ChatGeneration(message=msg)])

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **kwargs: Any) -> ScriptedModel:
        return self

    def system_prompt(self, call: int = 0) -> str:
        return str(self.seen[call][0].content)


def call(name: str, args: dict[str, Any], id: str = "c1") -> AIMessage:
    return AIMessage("", tool_calls=[{"name": name, "args": args, "id": id}])


@pytest.fixture
def vulnerable() -> Profile:
    return profile_from_env({"PROFILE": "vulnerable"})


@pytest.fixture
def hardened() -> Profile:
    return profile_from_env({"PROFILE": "hardened"})


class FakeResponse:
    def __init__(self, text: str = "ok", status_code: int = 200) -> None:
        self.text = text
        self.status_code = status_code


@pytest.fixture
def net(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[tuple[str, str]]]:
    """Replace outbound HTTP in lab egress with a recorder; returns (method, url) pairs."""
    sent: list[tuple[str, str]] = []

    def fake_request(method: str, url: str, **kw: Any) -> FakeResponse:
        sent.append((method, url))
        return FakeResponse("<html><body><p>Express shipping costs $18.</p></body></html>")

    def fake_get(url: str, **kw: Any) -> FakeResponse:
        return fake_request("GET", url)

    monkeypatch.setattr(httpx, "request", fake_request)
    monkeypatch.setattr(httpx, "get", fake_get)
    yield sent
