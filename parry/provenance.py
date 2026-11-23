"""Record exactly which model runtime produced a result: Ollama version and model digests."""

from __future__ import annotations

from typing import Any

import httpx


def ollama_info(url: str, timeout: float = 10.0) -> dict[str, Any]:
    base = url.rstrip("/")
    try:
        version = httpx.get(f"{base}/api/version", timeout=timeout).json().get("version")
        tags = httpx.get(f"{base}/api/tags", timeout=timeout).json().get("models", [])
    except (httpx.HTTPError, ValueError) as exc:
        return {"error": f"{exc.__class__.__name__}: {exc}"}
    return {
        "version": version,
        "models": {m["name"]: m.get("digest") for m in tags},
    }
