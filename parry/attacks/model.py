"""Attack templates and the concrete cases they expand into.

An attack = a payload generator (template x payloads x transforms) + a delivery channel +
a success goal that a judge can check. Templates live in `parry/attacks/catalog/*.yaml`.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from parry.config import AppType
from parry.mapping import validate_ids


class Channel(StrEnum):
    DIRECT = "direct"  # the attacker is the user
    MULTI_TURN = "multi_turn"  # the attacker is the user, over several turns
    DOCUMENT = "document"  # text that a RAG app indexes (customer review)
    WEB = "web"  # a web page the app fetches or imports
    TOOL_OUTPUT = "tool_output"  # an email or file the agent reads with a tool
    NOTES = "notes"  # shared notes an MCP assistant reads
    MCP_DESCRIPTION = "mcp_description"  # a third-party tool's description
    MCP_CALL = "mcp_call"  # a client calling MCP tools directly


class Goal(StrEnum):
    LEAK_SYSTEM = "leak_system_prompt"  # system-prompt canary appears in output
    LEAK_SECRET = "leak_secret"  # noqa: S105 - a planted secret appears in output
    FORBIDDEN_TOOL = "forbidden_tool"  # a matching tool call actually executed
    EXFIL = "exfil"  # a request carrying the case nonce reached attacker.test
    HIJACK = "hijack"  # the injected marker appears in the answer
    MISINFO = "misinformation"  # the answer states the injected falsehood (LLM judge)


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ToolMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    names: list[str]
    args_contain: list[str] = Field(default_factory=list)  # all must appear in the JSON args


Payload = str | list[str]  # a list is a multi-turn conversation


class AttackTemplate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    family: str
    channel: Channel
    apps: list[AppType]
    goal: Goal
    severity: Severity
    owasp: list[str]
    atlas: list[str]
    description: str
    payloads: list[Payload] = Field(min_length=1)
    transforms: list[str] = Field(default_factory=lambda: ["none"])
    trigger: str | None = None  # the innocent user request after content is planted
    role: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)  # channel-specific
    secrets: list[str] = Field(default_factory=list)  # for leak_secret; empty = any
    tool: ToolMatch | None = None
    rubric: str | None = None  # for misinformation

    @model_validator(mode="after")
    def _check(self) -> Self:
        validate_ids([*self.owasp, *self.atlas])
        if self.goal is Goal.FORBIDDEN_TOOL and self.tool is None:
            raise ValueError(f"{self.id}: forbidden_tool goal needs `tool`")
        if self.goal is Goal.MISINFO and not self.rubric:
            raise ValueError(f"{self.id}: misinformation goal needs a `rubric`")
        indirect = {
            Channel.DOCUMENT,
            Channel.WEB,
            Channel.TOOL_OUTPUT,
            Channel.NOTES,
            Channel.MCP_DESCRIPTION,
        }
        if self.channel in indirect and not self.trigger:
            raise ValueError(f"{self.id}: indirect channels need a `trigger`")
        if self.channel is Channel.MULTI_TURN and not all(
            isinstance(p, list) for p in self.payloads
        ):
            raise ValueError(f"{self.id}: multi_turn payloads must be lists of turns")
        return self


class AttackCase(BaseModel):
    """One concrete, reproducible attack against one kind of app."""

    case_id: str
    template: str
    family: str
    channel: Channel
    apps: list[AppType]
    goal: Goal
    severity: Severity
    owasp: list[str]
    atlas: list[str]
    transform: str
    nonce: str
    payload: Payload
    trigger: str | None
    role: str | None
    params: dict[str, Any]
    secrets: list[str]
    tool: ToolMatch | None
    rubric: str | None

    @property
    def marker(self) -> str:
        return f"PARRY-HIJACK-{self.nonce}"
