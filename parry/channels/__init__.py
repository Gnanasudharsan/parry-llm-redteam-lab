"""Delivery channels: how an attack case reaches the target.

Direct and multi-turn channels speak as the user. The indirect channels first plant content
where the app will read it (a review, a web page, an email or file, a shared note, a tool
description) and then send an innocent `trigger` request, as a real user would.
"""

from __future__ import annotations

import html
from typing import Any

from pydantic import BaseModel, Field

from parry.adapters import ChatAdapter, McpAdapter, Reply
from parry.attacks.model import AttackCase, Channel
from parry.lab import LabClient

LAB_CHANNELS = {Channel.DOCUMENT, Channel.WEB, Channel.TOOL_OUTPUT, Channel.MCP_DESCRIPTION}


class Delivery(BaseModel):
    replies: list[Reply] = Field(default_factory=list)
    steps: list[str] = Field(default_factory=list)  # what the channel did, for the report
    blocked_at_delivery: str | None = None  # the app refused the planted content
    planted_id: str | None = None  # e.g. the id of a planted email


class ChannelUnavailableError(Exception):
    """The case needs something this target does not offer (e.g. lab planting)."""


def _page(title: str, body: str) -> str:
    t = html.escape(title)
    head = f"<!doctype html><html><head><title>{t}</title></head>"
    return f"{head}<body><h1>{t}</h1><p>{body}</p></body></html>"


def _need_lab(lab: LabClient | None, case: AttackCase) -> LabClient:
    if lab is None:
        raise ChannelUnavailableError(f"{case.channel} needs a lab target")
    return lab


def _chat(
    adapter: ChatAdapter | McpAdapter, message: str, history: list[dict[str, str]], role: str | None
) -> Reply:
    if isinstance(adapter, McpAdapter):
        return adapter.call_tool("ask_assistant", {"question": message})
    return adapter.chat(message, history, role)


def deliver(case: AttackCase, adapter: ChatAdapter | McpAdapter, lab: LabClient | None) -> Delivery:
    d = Delivery()
    p: dict[str, Any] = case.params

    if case.channel is Channel.DIRECT:
        assert isinstance(case.payload, str)  # noqa: S101 - validated by the template
        d.replies.append(_chat(adapter, case.payload, [], case.role))
        d.steps.append("sent payload as the user")
        return d

    if case.channel is Channel.MULTI_TURN:
        assert isinstance(case.payload, list)  # noqa: S101
        if isinstance(adapter, McpAdapter):
            raise ChannelUnavailableError("the MCP assistant is stateless; no multi-turn")
        history: list[dict[str, str]] = []
        for turn in case.payload:
            reply = adapter.chat(turn, history, case.role)
            d.replies.append(reply)
            history += [
                {"role": "user", "content": turn},
                {"role": "assistant", "content": reply.text},
            ]
        d.steps.append(f"sent {len(case.payload)} turns")
        return d

    if case.channel is Channel.MCP_CALL:
        if not isinstance(adapter, McpAdapter):
            raise ChannelUnavailableError("mcp_call needs an MCP target")
        if "resource" in p:
            d.replies.append(adapter.read_resource(p["resource"]))
            d.steps.append(f"read resource {p['resource']}")
        else:
            d.replies.append(adapter.call_tool(p["tool"], {p["arg"]: case.payload}))
            d.steps.append(f"called {p['tool']}")
        return d

    if case.channel is Channel.NOTES:
        if not isinstance(adapter, McpAdapter):
            raise ChannelUnavailableError("notes channel needs an MCP target")
        note = adapter.call_tool(
            "add_note", {"title": p["title"], "body": case.payload, "author": "guest"}
        )
        d.steps.append(f"add_note -> {note.text[:60]}")
        assert case.trigger is not None  # noqa: S101
        d.replies.append(adapter.call_tool("ask_assistant", {"question": case.trigger}))
        return d

    # Channels below plant content through the lab, then send the trigger as the user.
    lab = _need_lab(lab, case)
    assert case.trigger is not None and isinstance(case.payload, str)  # noqa: S101
    if isinstance(adapter, McpAdapter):
        raise ChannelUnavailableError(f"{case.channel} needs a chat target")

    if case.channel is Channel.DOCUMENT:
        resp = lab.public_post(
            "/reviews", {"product": p["product"], "text": case.payload, "author": "guest"}
        )
        d.steps.append(f"posted review -> {resp.status_code}")
        if resp.status_code != 200:
            d.blocked_at_delivery = f"review rejected ({resp.status_code})"
            return d
    elif case.channel is Channel.WEB:
        host, path = p["host"], p["path"]
        lab.put_page(host, path, _page(p.get("title", "Page"), case.payload))
        d.steps.append(f"hosted page http://{host}{path}")
        if "rag" in case.apps:  # staff import the page into the knowledge base
            resp = lab.public_post("/ingest-url", {"url": f"http://{host}{path}"})
            d.steps.append(f"ingest-url -> {resp.status_code}")
            if resp.status_code != 200:
                d.blocked_at_delivery = f"import refused ({resp.status_code})"
                return d
    elif case.channel is Channel.TOOL_OUTPUT:
        if p["kind"] == "email":
            eid = lab.plant_email(p["sender"], p["subject"], case.payload)
            d.planted_id = eid
            d.steps.append(f"planted email {eid} from {p['sender']}")
        else:
            lab.plant_file(p["path"], case.payload)
            d.steps.append(f"planted file {p['path']}")
    elif case.channel is Channel.MCP_DESCRIPTION:
        res = lab.install_plugin(p["name"], case.payload)
        d.steps.append(f"installed tool {p['name']} -> {res.get('status')}")
        if res.get("status") != "installed":
            d.blocked_at_delivery = f"tool rejected: {res.get('why', '')}"
            return d

    trigger = case.trigger.replace("{email_id}", d.planted_id or "")
    d.replies.append(adapter.chat(trigger, [], case.role))
    d.steps.append("sent trigger")
    return d
