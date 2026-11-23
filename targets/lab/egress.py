"""Outbound HTTP for lab targets, recorded in the event log.

Inside Docker the only reachable host is the mock web service (internal network). For
running targets directly on the host, LAB_RESOLVE maps lab hostnames to an address, e.g.
`docs.harborview.test=127.0.0.1:8199,attacker.test=127.0.0.1:8199`; the request then goes to
that address with the original Host header.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from urllib.parse import urlsplit, urlunsplit

import httpx

from targets.lab.events import EventLog
from targets.lab.guard import TRUSTED_HOSTS, host_of, is_trusted

MAX_BODY = 20_000


class EgressBlockedError(Exception):
    pass


def _resolve_map() -> dict[str, str]:
    raw = os.environ.get("LAB_RESOLVE", "")
    pairs = (item.split("=", 1) for item in raw.split(",") if "=" in item)
    return {host.strip().lower(): addr.strip() for host, addr in pairs}


def _route(url: str) -> tuple[str, dict[str, str]]:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    addr = _resolve_map().get(host)
    if addr is None:
        return url, {}
    return urlunsplit(parts._replace(netloc=addr)), {"Host": parts.netloc}


def request(
    log: EventLog,
    method: str,
    url: str,
    *,
    allowlist: Iterable[str] | None,
    reason: str,
    json: object | None = None,
    timeout: float = 5.0,
) -> str:
    """Send a request if policy allows; return the (truncated) body. allowlist=None means open."""
    if urlsplit(url).scheme not in ("http", "https"):
        log.record("egress_blocked", reason, url=url, why="scheme")
        raise EgressBlockedError(f"only http(s) URLs are allowed: {url}")
    if allowlist is not None and not is_trusted(url, allowlist):
        log.record("egress_blocked", reason, url=url, host=host_of(url), why="allowlist")
        raise EgressBlockedError(f"host not on the allowlist: {host_of(url)}")
    routed, headers = _route(url)
    try:
        resp = httpx.request(method, routed, headers=headers, json=json, timeout=timeout)
    except httpx.HTTPError as exc:
        log.record("egress", reason, url=url, host=host_of(url), status=None, error=str(exc))
        raise
    log.record("egress", reason, url=url, host=host_of(url), status=resp.status_code)
    return resp.text[:MAX_BODY]


def fetch(log: EventLog, url: str, *, restricted: bool, reason: str = "fetch") -> str:
    return request(log, "GET", url, allowlist=TRUSTED_HOSTS if restricted else None, reason=reason)


def render_images(log: EventLog, urls: list[str]) -> list[str]:
    """Emulate a chat UI that auto-loads images in the answer. Returns URLs fetched."""
    fetched = []
    for url in urls:
        if urlsplit(url).scheme not in ("http", "https"):
            continue
        routed, headers = _route(url)
        try:
            httpx.get(routed, headers=headers, timeout=3.0)
            status = "ok"
        except httpx.HTTPError as exc:
            status = f"error: {exc.__class__.__name__}"
        log.record("render_fetch", "markdown_image", url=url, host=host_of(url), status=status)
        fetched.append(url)
    return fetched
