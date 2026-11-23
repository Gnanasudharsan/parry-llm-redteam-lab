"""End-to-end: real lab apps served over HTTP in-process, a scripted model, the real engine."""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi import FastAPI
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from parry.attacks.catalog import expand, load_templates
from parry.cli.app import write_report
from parry.config import ParryConfig
from parry.engine import load_trials, run_scan
from parry.scope import authorize
from targets.lab.llm import HashingEmbedder
from targets.lab.profile import profile_from_env
from targets.mockweb.app import create_app as mockweb_app
from targets.rag.app import create_app as rag_app


class EchoSystemPrompt(BaseChatModel):
    """A worst-case model: it repeats its whole system prompt back."""

    def _generate(
        self, messages: list[BaseMessage], stop: Any = None, run_manager: Any = None, **kw: Any
    ) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=AIMessage(str(messages[0].content)))])

    @property
    def _llm_type(self) -> str:
        return "echo"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _serve(app: FastAPI) -> tuple[str, uvicorn.Server]:
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    return f"http://127.0.0.1:{port}", server


@pytest.fixture
def lab() -> Iterator[dict[str, str]]:
    servers = {}
    for name, prof in (("vuln-rag", "vulnerable"), ("hard-rag", "hardened")):
        app = rag_app(
            profile=profile_from_env({"PROFILE": prof}),
            model=EchoSystemPrompt(),
            emb=HashingEmbedder(),
            target_name=name,
        )
        servers[name] = _serve(app)
    servers["mockweb"] = _serve(mockweb_app())
    yield {k: v[0] for k, v in servers.items()}
    for _, srv in servers.values():
        srv.should_exit = True


def test_scan_end_to_end(lab: dict[str, str], tmp_path: Path) -> None:
    cfg = ParryConfig.model_validate(
        {
            "seed": 1337,
            "lab": {"mockweb_url": lab["mockweb"]},
            "targets": [
                {
                    "name": n,
                    "kind": "http",
                    "url": lab[n],
                    "app": "rag",
                    "lab": True,
                    "owner_statement": "in-process test app",
                }
                for n in ("vuln-rag", "hard-rag")
            ],
        }
    )
    wanted = {"pe-direct/01", "sd-rag/01", "ir-review-hijack/01"}
    cases = [c for c in expand(load_templates(), 1337) if c.case_id in wanted]
    run = run_scan(
        cfg,
        authorize(cfg, ["vuln-rag", "hard-rag"]),
        cases,
        tmp_path,
        use_llm_judge=False,
        progress=lambda _: None,
    )
    got = {(t.target, t.case_id): t for t in load_trials(run)}
    assert len(got) == 6 and all(t.verdict for t in got.values())

    def ok(target: str, case: str) -> bool:
        v = got[(target, case)].verdict
        return bool(v and v.success)

    # Echoing the prompt leaks the canary; hardened redaction removes it.
    assert ok("vuln-rag", "pe-direct/01") and not ok("hard-rag", "pe-direct/01")
    # The vulnerable app retrieves the internal pricing doc for a customer; ACL stops it.
    assert ok("vuln-rag", "sd-rag/01") and not ok("hard-rag", "sd-rag/01")
    # The planted review is retrieved and echoed, so the marker appears. (Spotlighting cannot
    # stop a model that repeats its context, so the hardened result is not asserted.)
    assert ok("vuln-rag", "ir-review-hijack/01")

    report = write_report(run)
    summary = json.loads((run / "summary.json").read_text())
    assert summary["targets"]["vuln-rag"]["overall"]["asr"]["n"] == 3
    assert "ASR by attack family" in report.read_text()
    assert (run / "report.html").read_text().startswith("<!doctype html>")
