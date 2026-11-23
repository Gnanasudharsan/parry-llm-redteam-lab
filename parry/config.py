"""Configuration models for `parry.yaml`.

Configs never hold secrets. Targets name the environment variable that holds a key
(`api_key_env`), and Parry reads it at run time.
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path
from typing import Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

_NAME_RE = r"^[a-z0-9][a-z0-9_-]{0,62}$"
_ENV_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


class TargetKind(StrEnum):
    """How Parry talks to a target."""

    OPENAI_COMPAT = "openai_compat"  # any /v1/chat/completions server
    LITELLM = "litellm"  # LiteLLM model string, e.g. "ollama/llama3.2"
    HTTP = "http"  # an app's own JSON endpoint
    LANGGRAPH = "langgraph"  # in-process graph, loaded from "module:attr"
    MCP_STDIO = "mcp_stdio"  # MCP server launched as a local subprocess
    MCP_HTTP = "mcp_http"  # MCP server over streamable HTTP

    @property
    def is_network(self) -> bool:
        return self not in {TargetKind.LANGGRAPH, TargetKind.MCP_STDIO}


class AppType(StrEnum):
    """What kind of application sits behind the target; decides which attacks apply."""

    CHAT = "chat"  # plain chat endpoint
    RAG = "rag"  # chat over retrieved documents
    AGENT = "agent"  # chat with tools
    MCP = "mcp"  # MCP server


class TargetConfig(BaseModel):
    """One system under test. Listing it here is not authorization by itself."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=_NAME_RE)
    kind: TargetKind
    url: HttpUrl | None = None
    model: str | None = None
    entrypoint: str | None = Field(default=None, description="module:attr for in-process targets")
    command: list[str] | None = Field(default=None, description="argv for mcp_stdio targets")
    api_key_env: str | None = None
    app: AppType = AppType.CHAT
    lab: bool = Field(
        default=False,
        description="Target exposes the Parry lab admin API (reset, planted values, events).",
    )
    canaries: list[str] = Field(
        default_factory=list,
        description="Strings planted in a non-lab target; leaking one counts as a leak.",
    )
    owner_statement: str = Field(
        min_length=10,
        description="Why you are allowed to test this target, in your own words.",
    )
    public_endpoint_acknowledged: bool = Field(
        default=False,
        description="Required (with --allow-public-endpoints) for any non-local endpoint.",
    )

    @model_validator(mode="after")
    def _check_shape(self) -> Self:
        if self.kind.is_network and self.url is None and self.kind is not TargetKind.LITELLM:
            raise ValueError(f"target '{self.name}': kind '{self.kind}' needs a url")
        if self.kind is TargetKind.LITELLM and not self.model:
            raise ValueError(f"target '{self.name}': litellm targets need a model")
        if self.kind is TargetKind.LANGGRAPH and not self.entrypoint:
            raise ValueError(f"target '{self.name}': langgraph targets need an entrypoint")
        if self.kind is TargetKind.MCP_STDIO and not self.command:
            raise ValueError(f"target '{self.name}': mcp_stdio targets need a command")
        if self.api_key_env is not None and not _ENV_RE.match(self.api_key_env):
            raise ValueError(
                f"target '{self.name}': api_key_env must be an environment variable "
                "name (e.g. OPENAI_API_KEY), never the key itself"
            )
        return self


class LabSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mockweb_url: HttpUrl = HttpUrl("http://localhost:8199")
    admin_token_env: str = "LAB_ADMIN_TOKEN"  # noqa: S105 - an env var name, not a token
    seed_env: str = "LAB_SEED"


class JudgeSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    llm_url: HttpUrl = HttpUrl("http://localhost:11434")  # Ollama native API
    llm_model: str = "qwen2.5:7b-instruct"


class ParryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(default=1, ge=1, le=1)
    seed: int = 1337
    lab: LabSettings = Field(default_factory=LabSettings)
    judge: JudgeSettings = Field(default_factory=JudgeSettings)
    targets: list[TargetConfig] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_names(self) -> Self:
        names = [t.name for t in self.targets]
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            raise ValueError(f"duplicate target names: {', '.join(dupes)}")
        return self

    def target(self, name: str) -> TargetConfig | None:
        return next((t for t in self.targets if t.name == name), None)


def load_config(path: Path) -> ParryConfig:
    with path.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    return ParryConfig.model_validate(raw)
