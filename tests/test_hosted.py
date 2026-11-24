from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from parry.judges import hosted

FAKE_GROQ = "gsk_test_not_a_real_key_000"
FAKE_GEMINI = "AIza_test_not_a_real_key_000"


@pytest.fixture
def keyfile(tmp_path: Path) -> Path:
    p = tmp_path / "keys.env"
    p.write_text(f"GROQ_API_KEY={FAKE_GROQ}\nGEMINI_API_KEY='{FAKE_GEMINI}'\n")
    return p


class _R:
    def __init__(self, status: int, data: dict[str, Any], headers: dict[str, str] | None = None):
        self.status_code = status
        self._data = data
        self.headers = headers or {}

    def json(self) -> dict[str, Any]:
        return self._data


def test_load_key(keyfile: Path) -> None:
    assert hosted.load_key("GEMINI_API_KEY", keyfile) == FAKE_GEMINI
    with pytest.raises(KeyError):
        hosted.load_key("NOPE", keyfile)


def test_groq_request_and_backoff(keyfile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, dict[str, str], dict[str, Any]]] = []
    sleeps: list[float] = []
    replies = [
        _R(429, {}, {"retry-after": "3"}),
        _R(200, {"choices": [{"message": {"content": '{"label":"t","reason":"r"}'}}],
                 "model": "llama-3.3-70b-versatile", "system_fingerprint": "fp_1"}),
    ]  # fmt: skip

    def post(url: str, headers: dict[str, str], json: dict[str, Any], timeout: float) -> _R:
        calls.append((url, headers, json))
        return replies.pop(0)

    monkeypatch.setattr(httpx, "post", post)
    monkeypatch.setattr(time, "sleep", sleeps.append)
    listed = {"data": [{"id": "openai/gpt-oss-120b"}]}
    monkeypatch.setattr(httpx, "get", lambda url, headers, timeout: _R(200, listed))
    label, meta = hosted.groq_labeler(key_file=keyfile)
    assert meta["model"] == "openai/gpt-oss-120b"
    res = label("system", "user", 7)
    assert hosted.parse(res["raw"]) == (True, "r")
    assert sleeps == [3.0] and len(calls) == 2  # honored Retry-After, then succeeded
    url, headers, body = calls[-1]
    assert FAKE_GROQ not in url and headers["Authorization"] == f"Bearer {FAKE_GROQ}"
    assert body["temperature"] == 0 and body["seed"] == 7
    assert FAKE_GROQ not in json.dumps(res) and FAKE_GROQ not in json.dumps(meta)


def test_gemini_key_in_header_only(keyfile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, dict[str, str], dict[str, Any]]] = []

    def post(url: str, headers: dict[str, str], json: dict[str, Any], timeout: float) -> _R:
        calls.append((url, headers, json))
        return _R(200, {"candidates": [{"content": {"parts": [{"text": '{"label":"f"}'}]}}],
                        "modelVersion": "v1"})  # fmt: skip

    listed = {"models": [{"name": "models/gemini-3.8-flash"}, {"name": "models/gemini-2.5-flash"}]}
    monkeypatch.setattr(httpx, "post", post)
    monkeypatch.setattr(httpx, "get", lambda url, headers, timeout, params=None: _R(200, listed))
    label, meta = hosted.gemini_labeler(key_file=keyfile)
    assert meta["model"] == "gemini-3.8-flash"  # pinned
    assert calls[0][2]["contents"][0]["parts"][0]["text"] == "Say ok."  # probe, no lab data
    res = label("system", "user", 7)
    url, headers, body = calls[-1]
    assert FAKE_GEMINI not in url and headers["x-goog-api-key"] == FAKE_GEMINI
    assert body["generationConfig"]["temperature"] == 0 and body["generationConfig"]["seed"] == 7
    assert hosted.parse(res["raw"])[0] is False
    assert FAKE_GEMINI not in json.dumps(res) and FAKE_GEMINI not in json.dumps(meta)


def test_error_message_has_no_key(keyfile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx, "post", lambda url, headers, json, timeout: _R(401, {}))
    listed = {"data": [{"id": "openai/gpt-oss-120b"}]}
    monkeypatch.setattr(httpx, "get", lambda url, headers, timeout: _R(200, listed))
    label, _ = hosted.groq_labeler(key_file=keyfile)
    with pytest.raises(RuntimeError) as exc:
        label("s", "u", 1)
    assert FAKE_GROQ not in str(exc.value) and "401" in str(exc.value)


def test_gemini_pinned_model_missing_stops(keyfile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    listed = {"models": [{"name": "models/gemini-2.0-flash"}]}
    monkeypatch.setattr(httpx, "get", lambda url, headers, timeout, params=None: _R(200, listed))
    with pytest.raises(RuntimeError, match="no fallback"):
        hosted.gemini_labeler(key_file=keyfile)


def test_gemini_listed_but_closed_stops(keyfile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    listed = {"models": [{"name": "models/gemini-3.8-flash"}]}
    monkeypatch.setattr(httpx, "get", lambda url, headers, timeout, params=None: _R(200, listed))
    monkeypatch.setattr(httpx, "post", lambda url, headers, json, timeout: _R(404, {}))
    with pytest.raises(RuntimeError, match="probe: HTTP 404"):
        hosted.gemini_labeler(key_file=keyfile)


def test_cli_tracebacks_never_show_locals() -> None:
    from parry.cli.app import app

    assert app.pretty_exceptions_show_locals is False


def test_groq_pinned_model_missing_stops(keyfile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    listed = {"data": [{"id": "openai/gpt-oss-20b"}]}
    monkeypatch.setattr(httpx, "get", lambda url, headers, timeout: _R(200, listed))
    with pytest.raises(RuntimeError, match="no fallback"):
        hosted.groq_labeler(key_file=keyfile)


def test_reasoning_settings_only_for_gpt_oss(
    keyfile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bodies: list[dict[str, Any]] = []

    def post(url: str, headers: dict[str, str], json: dict[str, Any], timeout: float) -> _R:
        bodies.append(json)
        return _R(200, {"choices": [{"message": {"content": '{"label":"f","reason":"r"}'}}]})

    listed = {"data": [{"id": "openai/gpt-oss-120b"}, {"id": "allam-2-7b"}]}
    monkeypatch.setattr(httpx, "get", lambda url, headers, timeout: _R(200, listed))
    monkeypatch.setattr(httpx, "post", post)
    for m in hosted.GROQ_PANEL:
        hosted.groq_labeler(m, key_file=keyfile)[0]("s", "u", 3)
    gpt, allam = bodies
    assert gpt["include_reasoning"] is False and gpt["max_tokens"] == 2048
    assert "include_reasoning" not in allam and allam["max_tokens"] == 200
    assert gpt["seed"] == allam["seed"] == 3 and gpt["temperature"] == allam["temperature"] == 0
