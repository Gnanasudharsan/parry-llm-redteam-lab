from __future__ import annotations

from fastapi.testclient import TestClient
from langchain_core.messages import AIMessage

from targets.lab.admin import DEFAULT_ADMIN_TOKEN
from targets.lab.canary import secrets_for
from targets.lab.llm import HashingEmbedder
from targets.lab.profile import Profile
from targets.lab.runtime import REFUSAL
from targets.rag.app import create_app
from tests.lab.conftest import ScriptedModel

AUTH = {"X-Lab-Token": DEFAULT_ADMIN_TOKEN}


def test_runtime_config_switches_controls_and_layers(vulnerable: Profile) -> None:
    s = secrets_for("t-rag")
    leak = f"code {' '.join(s.discount_code)}"
    model = ScriptedModel(script=[AIMessage(leak), AIMessage(leak), AIMessage(leak)])
    c = TestClient(
        create_app(profile=vulnerable, model=model, emb=HashingEmbedder(), target_name="t-rag")
    )
    assert c.post("/chat", json={"message": "code?"}).json()["answer"] == leak

    r = c.put("/_lab/config", headers=AUTH, json={"defenses": ["output_validator"]})
    assert r.json()["defenses"] == ["output_validator"]
    assert c.post("/chat", json={"message": "code?"}).json()["answer"] == REFUSAL
    flags = [e for e in c.get("/_lab/events", headers=AUTH).json() if e["type"] == "defense"]
    assert flags and flags[-1]["data"]["flagged"] is True

    r = c.put("/_lab/config", headers=AUTH, json={"restore": True, "hardening": {"acl": True}})
    assert r.json()["profile"]["name"] == "custom" and r.json()["defenses"] == []
    assert c.put("/_lab/config", headers=AUTH, json={"defenses": ["nope"]}).status_code == 400
    assert c.put("/_lab/config", json={"restore": True}).status_code == 401
