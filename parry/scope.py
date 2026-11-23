"""Target authorization: the gate every scan passes through.

Two rules (see docs/adr/0001-target-authorization.md):

1. Every target that runs must be named on the command line with
   `--i-own-this-target <name>`. Listing it in a config file is not enough.
2. Public endpoints are refused unless the target sets
   `public_endpoint_acknowledged: true` *and* the run passes `--allow-public-endpoints`.

Classification is by the literal host in the URL, without DNS. A private-looking
hostname that resolves to a public address is not caught here; that limit is documented.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from parry.config import ParryConfig, TargetConfig

_LOCAL_SUFFIXES = (".localhost",)
_PRIVATE_SUFFIXES = (".test", ".internal", ".local", ".lan", ".home.arpa")


class EndpointScope(StrEnum):
    IN_PROCESS = "in_process"  # LangGraph graph or stdio subprocess on this machine
    LOOPBACK = "loopback"  # localhost, 127.0.0.0/8, ::1
    PRIVATE = "private"  # RFC 1918 / ULA / link-local, reserved test TLDs, compose service names
    PUBLIC = "public"  # anything else


class ScopeError(Exception):
    """Raised when a run would touch a target it is not authorized for."""


@dataclass(frozen=True)
class AuthorizedTarget:
    target: TargetConfig
    scope: EndpointScope


def classify_host(host: str) -> EndpointScope:
    host = host.strip().strip("[]").rstrip(".").lower()
    if not host:
        raise ValueError("empty host")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if host == "localhost" or host.endswith(_LOCAL_SUFFIXES):
            return EndpointScope.LOOPBACK
        if host.endswith(_PRIVATE_SUFFIXES) or "." not in host:
            # Single-label names are Docker Compose service names on the lab network.
            return EndpointScope.PRIVATE
        return EndpointScope.PUBLIC
    if ip.is_loopback:
        return EndpointScope.LOOPBACK
    if ip.is_private or ip.is_link_local:
        return EndpointScope.PRIVATE
    return EndpointScope.PUBLIC


def classify_target(target: TargetConfig) -> EndpointScope:
    if not target.kind.is_network:
        return EndpointScope.IN_PROCESS
    if target.url is None:
        # A LiteLLM model string with no api_base goes to the provider's hosted API.
        return EndpointScope.PUBLIC
    if target.url.host is None:
        raise ValueError(f"target '{target.name}': url has no host")
    return classify_host(target.url.host)


def authorize(
    config: ParryConfig,
    owned: Iterable[str],
    *,
    allow_public_endpoints: bool = False,
) -> list[AuthorizedTarget]:
    """Return the targets this run may touch, or raise ScopeError explaining why not."""
    owned_names = list(dict.fromkeys(owned))
    if not owned_names:
        raise ScopeError(
            "no target authorized: pass --i-own-this-target <name> for each target "
            "you own or have written permission to test"
        )

    unknown = [n for n in owned_names if config.target(n) is None]
    if unknown:
        raise ScopeError(f"--i-own-this-target names not in config: {', '.join(unknown)}")

    result: list[AuthorizedTarget] = []
    for name in owned_names:
        target = config.target(name)
        if target is None:  # unreachable: unknown names were rejected above
            raise ScopeError(f"unknown target '{name}'")
        scope = classify_target(target)
        if scope is EndpointScope.PUBLIC:
            if not target.public_endpoint_acknowledged:
                raise ScopeError(
                    f"target '{name}' is a public endpoint; Parry refuses public endpoints "
                    "unless the target sets public_endpoint_acknowledged: true"
                )
            if not allow_public_endpoints:
                raise ScopeError(
                    f"target '{name}' is a public endpoint; re-run with "
                    "--allow-public-endpoints if you own it"
                )
        result.append(AuthorizedTarget(target=target, scope=scope))
    return result


__all__ = [
    "AuthorizedTarget",
    "EndpointScope",
    "ScopeError",
    "authorize",
    "classify_host",
    "classify_target",
]
