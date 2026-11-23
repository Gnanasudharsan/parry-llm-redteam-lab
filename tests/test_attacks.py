from __future__ import annotations

import base64
import codecs
import re

import pytest

from parry.attacks.catalog import expand, load_templates, nonce_for
from parry.attacks.model import AttackTemplate, Channel
from parry.attacks.transforms import apply
from parry.mapping import validate_ids

PLACEHOLDER = re.compile(r"\{(nonce|marker|exfil_url|attacker_email|attacker_account|host)\}")


def test_catalog_loads_and_expands() -> None:
    cases = expand(load_templates(), 1337)
    assert len(cases) >= 80
    assert len({c.case_id for c in cases}) == len(cases)
    for c in cases:
        validate_ids([*c.owasp, *c.atlas])
        assert c.owasp and c.atlas
        blob = f"{c.payload} {c.trigger} {c.params} {c.tool}"
        assert not PLACEHOLDER.search(blob), c.case_id


def test_every_app_has_cases_in_several_families() -> None:
    cases = expand(load_templates(), 1337)
    for app in ("rag", "agent", "mcp"):
        assert len({c.family for c in cases if app in c.apps}) >= 5


def test_expansion_is_seeded() -> None:
    a, b, c = (expand(load_templates(), s) for s in (1, 1, 2))
    assert [x.payload for x in a] == [x.payload for x in b]
    assert [x.nonce for x in a] != [x.nonce for x in c]
    assert nonce_for(1, "x") == nonce_for(1, "x") != nonce_for(1, "y")


def test_web_templates_expand_per_host() -> None:
    web = [c for c in expand(load_templates(), 1) if c.channel is Channel.WEB]
    assert {c.params["host"] for c in web} == {"attacker.test", "docs.harborview.test"}
    assert all("hosts" not in c.params for c in web)


def test_transforms() -> None:
    assert base64.b64decode(apply("base64", "hi there").split("\n")[1]).decode() == "hi there"
    assert codecs.decode(apply("rot13", "secret").split("\n")[1], "rot13") == "secret"
    assert apply("leetspeak", "secrets") == "53cr375"
    assert apply("word_split", "instructions now") == "instru-ctions now"
    with pytest.raises(KeyError):
        apply("rot47", "x")


def test_template_validation() -> None:
    base = {
        "id": "x",
        "family": "f",
        "channel": "direct",
        "apps": ["rag"],
        "severity": "low",
        "owasp": ["LLM01:2025"],
        "atlas": ["AML.T0051"],
        "description": "d",
        "payloads": ["p"],
    }
    with pytest.raises(ValueError, match="needs `tool`"):
        AttackTemplate.model_validate({**base, "goal": "forbidden_tool"})
    with pytest.raises(ValueError, match="rubric"):
        AttackTemplate.model_validate({**base, "goal": "misinformation"})
    with pytest.raises(ValueError, match="trigger"):
        AttackTemplate.model_validate({**base, "goal": "hijack", "channel": "document"})
    with pytest.raises(KeyError):
        AttackTemplate.model_validate({**base, "goal": "hijack", "atlas": ["AML.T9"]})
