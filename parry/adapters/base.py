"""Adapter interfaces and the factory."""

from __future__ import annotations

import importlib
import os
from typing import Any, Protocol

import anyio
import httpx
from mcp.client.client import Client
from pydantic import BaseModel, Field

from parry.config import TargetConfig, TargetKind

DEFAULT_TIMEOUT_S = 180.0


class Reply(BaseModel):
    """What a target said, plus anything it reports about side effects."""

    text: str = ""
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)  # {name, args, status}
    rendered: list[str] = Field(default_factory=list)  # URLs a rendering client loaded
    sources: list[str] = Field(default_factory=list)
    status: int | None = None
    error: str | None = None


class ChatAdapter(Protocol):
    def chat(
        self, message: str, history: list[dict[str, str]], role: str | None = None
    ) -> Reply: ...


class HttpChatAdapter:
    """Apps exposing `POST /chat {message, history, role?}` -> `{answer, ...}` (the lab apps)."""

    def __init__(self, base_url: str, timeout: float = DEFAULT_TIMEOUT_S) -> None:
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def chat(self, message: str, history: list[dict[str, str]], role: str | None = None) -> Reply:
        body: dict[str, Any] = {"message": message, "history": history}
        if role:
            body["role"] = role
        try:
            r = httpx.post(f"{self.base}/chat", json=body, timeout=self.timeout)
        except httpx.HTTPError as exc:
            return Reply(error=exc.__class__.__name__)
        if r.status_code != 200:
            return Reply(status=r.status_code, error=r.text[:300])
        data = r.json()
        return Reply(
            text=str(data.get("answer", "")),
            tool_calls=list(data.get("tool_calls", [])),
            rendered=list(data.get("rendered", [])),
            sources=list(data.get("sources", [])),
            status=200,
        )


class OpenAICompatAdapter:
    """Any `/v1/chat/completions` server. The target's own system prompt is not touched."""

    def __init__(
        self, url: str, model: str, api_key: str | None, timeout: float = DEFAULT_TIMEOUT_S
    ):
        self.url = url.rstrip("/")
        self.model = model
        self.headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self.seed = int(os.environ.get("PARRY_SEED", "1337"))
        self.timeout = timeout

    def chat(self, message: str, history: list[dict[str, str]], role: str | None = None) -> Reply:
        messages = [*history, {"role": "user", "content": message}]
        try:
            r = httpx.post(
                f"{self.url}/chat/completions",
                json={
                    "model": self.model,
                    "messages": messages,
                    "temperature": 0,
                    "seed": self.seed,
                },
                headers=self.headers,
                timeout=self.timeout,
            )
        except httpx.HTTPError as exc:
            return Reply(error=exc.__class__.__name__)
        if r.status_code != 200:
            return Reply(status=r.status_code, error=r.text[:300])
        return Reply(text=r.json()["choices"][0]["message"]["content"] or "", status=200)


class LangGraphAdapter:
    """In-process LangGraph graph loaded from `module:attr` (a compiled graph or a factory)."""

    def __init__(self, entrypoint: str) -> None:
        module, _, attr = entrypoint.partition(":")
        obj = getattr(importlib.import_module(module), attr)
        self.graph = obj() if callable(obj) and not hasattr(obj, "invoke") else obj

    def chat(self, message: str, history: list[dict[str, str]], role: str | None = None) -> Reply:
        messages = [(m["role"], m["content"]) for m in history] + [("user", message)]
        result = self.graph.invoke({"messages": messages})
        return Reply(text=str(result["messages"][-1].content), status=200)


def _text(result: Any) -> str:
    items = getattr(result, "content", None) or getattr(result, "contents", None) or []
    return "\n".join(str(getattr(c, "text", "")) for c in items)


class McpAdapter:
    """MCP server over streamable HTTP. Each call opens a short-lived session."""

    def __init__(self, url: str, timeout: float = DEFAULT_TIMEOUT_S) -> None:
        self.url = url
        self.timeout = timeout

    def _run(self, op: str, *args: Any) -> Reply:
        async def go() -> Reply:
            with anyio.fail_after(self.timeout):
                async with Client(self.url) as c:
                    if op == "tool":
                        res = await c.call_tool(args[0], args[1])
                        failed = bool(getattr(res, "is_error", False))
                        return Reply(
                            text=_text(res), status=200, error="tool error" if failed else None
                        )
                    if op == "resource":
                        return Reply(text=_text(await c.read_resource(args[0])), status=200)
                    tools = await c.list_tools()
                    return Reply(text="\n".join(t.name for t in tools.tools), status=200)

        try:
            return anyio.run(go)
        except Exception as exc:  # transport or protocol failure is recorded, not raised
            return Reply(error=f"{exc.__class__.__name__}: {exc}"[:300])

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Reply:
        return self._run("tool", name, arguments)

    def read_resource(self, uri: str) -> Reply:
        return self._run("resource", uri)

    def list_tools(self) -> Reply:
        return self._run("list")


def make_adapter(target: TargetConfig) -> ChatAdapter | McpAdapter:
    if target.kind is TargetKind.HTTP:
        return HttpChatAdapter(str(target.url))
    if target.kind is TargetKind.OPENAI_COMPAT:
        key = os.environ.get(target.api_key_env) if target.api_key_env else None
        return OpenAICompatAdapter(str(target.url), target.model or "default", key)
    if target.kind is TargetKind.MCP_HTTP:
        return McpAdapter(str(target.url))
    if target.kind is TargetKind.LANGGRAPH:
        assert target.entrypoint is not None  # noqa: S101 - validated by config
        return LangGraphAdapter(target.entrypoint)
    raise NotImplementedError(f"adapter for kind '{target.kind}' is not implemented yet")
