"""Hosted labelers for the LLM panel (owner-approved exception to the local-only rule).

Only lab material is sent: lab replies, attacker inputs and the lab's fake HMAC-derived
canaries; no real secrets. API keys are read from a local file at call time, sent only in
request headers (never in URLs), and never printed, logged or written to results.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

KEYS_FILE = Path.home() / ".parry" / "keys.env"
GROQ_MODEL = "openai/gpt-oss-120b"  # pinned (owner); llama-3.3-70b-versatile is retired
GROQ_BASE = "https://api.groq.com/openai/v1"
GROQ_URL = f"{GROQ_BASE}/chat/completions"
GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"
GEMINI_MODEL = "gemini-3.8-flash"  # pinned (owner); gemini-2.5-flash closed to new users
RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_ATTEMPTS = 8

Labeler = Callable[[str, str, int], dict[str, Any]]  # (system, user, seed) -> result


def load_key(name: str, path: Path = KEYS_FILE) -> str:
    """Read one key from a KEY=value file. The value is returned, never shown."""
    for line in path.read_text().splitlines():
        k, sep, v = line.partition("=")
        if sep and k.strip() == name:
            return v.strip().strip("'\"")
    raise KeyError(f"{name} not found in {path}")


def _post(url: str, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
    """POST with rate-limit backoff (Retry-After if given, else exponential, up to 64 s).
    Errors name the status code only, never headers."""
    delay = 2.0
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            r = httpx.post(url, headers=headers, json=body, timeout=120)
        except httpx.TransportError as exc:
            if attempt == MAX_ATTEMPTS:
                raise RuntimeError(f"transport error after {attempt} attempts") from exc
            time.sleep(delay)
            delay = min(delay * 2, 64)
            continue
        if r.status_code in RETRY_STATUS and attempt < MAX_ATTEMPTS:
            retry_after = r.headers.get("retry-after")
            wait = float(retry_after) if retry_after and retry_after.isdigit() else delay
            time.sleep(min(wait, 64))
            delay = min(delay * 2, 64)
            continue
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code} from {url.split('?')[0]}")
        data: dict[str, Any] = r.json()
        return data
    raise RuntimeError("unreachable")


def groq_model(key: str, model: str = GROQ_MODEL) -> str:
    """Confirm the pinned Groq model is served (listing sends no lab data); no fallback."""
    r = httpx.get(f"{GROQ_BASE}/models", headers={"Authorization": f"Bearer {key}"}, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code} listing Groq models")
    if model not in {m["id"] for m in r.json().get("data", [])}:
        raise RuntimeError(
            f"pinned Groq model {model} is not available; stopping for an owner decision "
            "(no fallback to another model)"
        )
    return model


def groq_labeler(
    model: str = GROQ_MODEL, key_file: Path = KEYS_FILE
) -> tuple[Labeler, dict[str, Any]]:
    key = load_key("GROQ_API_KEY", key_file)
    groq_model(key, model)

    def label(system: str, user: str, seed: int) -> dict[str, Any]:
        data = _post(
            GROQ_URL,
            {"Authorization": f"Bearer {key}"},
            {
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "temperature": 0,
                "seed": seed,
                "max_tokens": 2048,  # reasoning tokens count toward the limit
                "response_format": {"type": "json_object"},
                "include_reasoning": False,
            },
        )
        return {
            "raw": data["choices"][0]["message"]["content"],
            "served": {
                "model": data.get("model"),
                "system_fingerprint": data.get("system_fingerprint"),
            },
        }

    return label, {"provider": "groq", "model": model, "seed_supported": True}


def gemini_model(key: str, model: str = GEMINI_MODEL) -> str:
    """Confirm the pinned model is available (listing sends no lab data). No fallback: if it
    is missing, stop so the owner can decide."""
    r = httpx.get(
        f"{GEMINI_BASE}/models",
        headers={"x-goog-api-key": key},
        params={"pageSize": 1000},
        timeout=30,
    )
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code} listing Gemini models")
    names = {m["name"].removeprefix("models/") for m in r.json().get("models", [])}
    if model not in names:
        raise RuntimeError(
            f"pinned Gemini model {model} is not listed; stopping for an owner decision "
            "(no fallback to another model)"
        )
    # Being listed is not enough (a listed model can be closed to new users): send one dummy
    # request with no lab data.
    try:  # same backoff as labeling calls: 429/5xx retried, 404 stops at once
        _post(
            f"{GEMINI_BASE}/models/{model}:generateContent",
            {"x-goog-api-key": key},
            {"contents": [{"role": "user", "parts": [{"text": "Say ok."}]}]},
        )
    except RuntimeError as exc:
        raise RuntimeError(
            f"pinned Gemini model {model} is not available (probe: {exc}); "
            "stopping for an owner decision (no fallback to another model)"
        ) from exc
    return model


def gemini_labeler(
    model: str | None = None, key_file: Path = KEYS_FILE
) -> tuple[Labeler, dict[str, Any]]:
    key = load_key("GEMINI_API_KEY", key_file)
    model = gemini_model(key, model or GEMINI_MODEL)

    def label(system: str, user: str, seed: int) -> dict[str, Any]:
        data = _post(
            f"{GEMINI_BASE}/models/{model}:generateContent",
            {"x-goog-api-key": key},
            {
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": user}]}],
                "generationConfig": {
                    "temperature": 0,
                    "seed": seed,
                    "maxOutputTokens": 2048,  # thinking tokens count toward the limit
                    "responseMimeType": "application/json",
                },
            },
        )
        parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])
        return {
            "raw": "".join(p.get("text", "") for p in parts),
            "served": {"model": model, "model_version": data.get("modelVersion")},
        }

    return label, {"provider": "google", "model": model, "seed_supported": True}


def parse(raw: str) -> tuple[bool | None, str]:
    try:
        data = json.loads(raw)
        label = str(data.get("label", "")).strip().lower()[:1]
        reason = str(data.get("reason", "")).strip()
    except (ValueError, AttributeError):
        return None, ""
    return {"t": True, "f": False}.get(label), reason[:300]
