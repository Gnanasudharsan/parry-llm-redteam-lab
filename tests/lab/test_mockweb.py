from __future__ import annotations

from fastapi.testclient import TestClient

from targets.lab.admin import DEFAULT_ADMIN_TOKEN
from targets.mockweb.app import create_app

AUTH = {"X-Lab-Token": DEFAULT_ADMIN_TOKEN}


def test_pages_by_host_and_hits_recorded() -> None:
    c = TestClient(create_app())
    r = c.get("/shipping-rates", headers={"Host": "docs.harborview.test"})
    assert r.status_code == 200 and "$18.00" in r.text
    assert c.get("/shipping-rates", headers={"Host": "attacker.test"}).status_code == 404
    c.post("/collect?d=abc", headers={"Host": "attacker.test"}, content="payload")
    hits = c.get("/_lab/hits", params={"host": "attacker.test"}, headers=AUTH).json()
    assert [(h["method"], h["query"], h["body"]) for h in hits][-1] == ("POST", "d=abc", "payload")


def test_admin_and_planted_pages() -> None:
    c = TestClient(create_app())
    assert c.get("/_lab/hits").status_code == 401
    page = {"host": "attacker.test", "path": "/blog", "html": "<p>hello</p>"}
    c.put("/_lab/pages", json=page, headers=AUTH)
    assert c.get("/blog", headers={"Host": "attacker.test"}).text == "<p>hello</p>"
    c.post("/_lab/reset", headers=AUTH)
    assert c.get("/blog", headers={"Host": "attacker.test"}).status_code == 404
    # Reset cleared earlier hits; only the request made after it remains.
    assert [h["path"] for h in c.get("/_lab/hits", headers=AUTH).json()] == ["/blog"]
