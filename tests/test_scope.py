from __future__ import annotations

from typing import Any

import pytest

from parry.config import ParryConfig
from parry.scope import EndpointScope, ScopeError, authorize, classify_host


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("localhost", EndpointScope.LOOPBACK),
        ("LOCALHOST.", EndpointScope.LOOPBACK),
        ("app.localhost", EndpointScope.LOOPBACK),
        ("127.0.0.1", EndpointScope.LOOPBACK),
        ("127.8.9.10", EndpointScope.LOOPBACK),
        ("::1", EndpointScope.LOOPBACK),
        ("[::1]", EndpointScope.LOOPBACK),
        ("10.0.0.5", EndpointScope.PRIVATE),
        ("172.16.3.4", EndpointScope.PRIVATE),
        ("192.168.1.20", EndpointScope.PRIVATE),
        ("169.254.169.254", EndpointScope.PRIVATE),
        ("fd00::1", EndpointScope.PRIVATE),
        ("vuln-rag", EndpointScope.PRIVATE),
        ("lab.test", EndpointScope.PRIVATE),
        ("svc.internal", EndpointScope.PRIVATE),
        ("api.openai.com", EndpointScope.PUBLIC),
        ("example.com", EndpointScope.PUBLIC),
        ("8.8.8.8", EndpointScope.PUBLIC),
        ("localhost.example.com", EndpointScope.PUBLIC),
        ("2001:4860:4860::8888", EndpointScope.PUBLIC),
    ],
)
def test_classify_host(host: str, expected: EndpointScope) -> None:
    assert classify_host(host) is expected


def _cfg(*targets: dict[str, Any]) -> ParryConfig:
    return ParryConfig.model_validate({"targets": list(targets)})


LOCAL = {
    "name": "local",
    "kind": "http",
    "url": "http://localhost:8101/chat",
    "owner_statement": "my own local lab app",
}
PUBLIC = {
    "name": "prod",
    "kind": "http",
    "url": "https://my-app.example.com/chat",
    "owner_statement": "my own deployed app",
}
PUBLIC_ACK = {**PUBLIC, "name": "prod-ack", "public_endpoint_acknowledged": True}


def test_requires_explicit_ownership_flag() -> None:
    with pytest.raises(ScopeError, match="--i-own-this-target"):
        authorize(_cfg(LOCAL), [])


def test_local_target_authorized_when_named() -> None:
    [a] = authorize(_cfg(LOCAL), ["local"])
    assert a.target.name == "local"
    assert a.scope is EndpointScope.LOOPBACK


def test_only_named_targets_are_returned() -> None:
    other = {**LOCAL, "name": "other"}
    allowed = authorize(_cfg(LOCAL, other), ["other"])
    assert [a.target.name for a in allowed] == ["other"]


def test_unknown_name_rejected() -> None:
    with pytest.raises(ScopeError, match="not in config: typo"):
        authorize(_cfg(LOCAL), ["local", "typo"])


def test_public_refused_by_default() -> None:
    with pytest.raises(ScopeError, match="public_endpoint_acknowledged"):
        authorize(_cfg(PUBLIC), ["prod"], allow_public_endpoints=True)


def test_public_needs_cli_flag_even_when_acknowledged() -> None:
    with pytest.raises(ScopeError, match="--allow-public-endpoints"):
        authorize(_cfg(PUBLIC_ACK), ["prod-ack"])


def test_public_allowed_with_both_acknowledgements() -> None:
    [a] = authorize(_cfg(PUBLIC_ACK), ["prod-ack"], allow_public_endpoints=True)
    assert a.scope is EndpointScope.PUBLIC


def test_hosted_litellm_without_url_is_public() -> None:
    hosted = {
        "name": "groq",
        "kind": "litellm",
        "model": "groq/llama-3.1-8b-instant",
        "owner_statement": "my own Groq account",
    }
    with pytest.raises(ScopeError, match="public endpoint"):
        authorize(_cfg(hosted), ["groq"])


def test_in_process_targets() -> None:
    graph = {
        "name": "agent",
        "kind": "langgraph",
        "entrypoint": "targets.vuln_agent:graph",
        "owner_statement": "Parry's own lab agent",
    }
    [a] = authorize(_cfg(graph), ["agent"])
    assert a.scope is EndpointScope.IN_PROCESS
