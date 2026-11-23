"""Run benign task sets through Parry's adapters: utility, false positives, latency, cost.

Latency is measured around the target call only (not lab resets), so it reflects what a
user would wait. Guard flags and blocked actions come from the lab event log.
"""

from __future__ import annotations

import time
from typing import Any

from pydantic import BaseModel, Field

from parry.adapters import ChatAdapter, McpAdapter
from parry.lab import LabClient
from parry.tasks import BenignTask, Outcome, TaskSet, evaluate


class BenignResult(BaseModel):
    id: str
    category: str
    approval_gated: bool
    passed: bool
    leaked: bool
    failures: list[str]
    latency_s: float
    tools: list[str]
    answer: str
    defense_flags: list[str] = Field(default_factory=list)  # layer@hook that fired
    blocked: list[str] = Field(default_factory=list)  # tool / egress blocks
    guard_tokens: int = 0
    guard_ms: float = 0.0
    attempt: int = 1

    @property
    def errored(self) -> bool:
        return any(f.startswith("error:") for f in self.failures)


def _run_one(
    adapter: ChatAdapter | McpAdapter, task: BenignTask
) -> tuple[str, list[tuple[str, Any]], str | None]:
    if isinstance(adapter, McpAdapter):
        last, executed, err = "", [], None
        for call in task.calls:
            reply = (
                adapter.read_resource(call.resource)
                if call.resource
                else adapter.call_tool(call.tool or "", call.arguments)
            )
            last, err = reply.text, reply.error or err
            if call.tool:
                executed.append((call.tool, call.arguments))
        return last, executed, err
    reply = adapter.chat(task.message or "", [t.model_dump() for t in task.history], task.role)
    executed = [(c["name"], c["args"]) for c in reply.tool_calls if c.get("status") == "executed"]
    return reply.text, executed, reply.error


def run_benign(
    adapter: ChatAdapter | McpAdapter, lab: LabClient | None, tasks: TaskSet
) -> list[BenignResult]:
    forbidden = []
    if lab is not None:
        s = lab.secrets()
        forbidden = [s.system_canary, s.api_key]
    out = []

    def one(task: BenignTask, attempt: int) -> BenignResult:
        if lab is not None:
            lab.reset()
        t0 = time.perf_counter()
        answer, executed, err = _run_one(adapter, task)
        latency = time.perf_counter() - t0
        outcome = (
            evaluate(task.check, answer, executed, forbidden)
            if err is None
            else Outcome(passed=False, failures=[f"error: {err[:120]}"])
        )
        events = lab.events() if lab is not None else []
        defense = [e for e in events if e["type"] == "defense"]
        return BenignResult(
            id=task.id,
            category=task.category,
            approval_gated=task.approval_gated,
            passed=outcome.passed,
            leaked=outcome.leaked,
            failures=outcome.failures,
            latency_s=round(latency, 3),
            tools=[n for n, _ in executed],
            answer=answer[:500],
            defense_flags=[
                f"{e['name']}@{e['data'].get('hook')}" for e in defense if e["data"].get("flagged")
            ],
            blocked=[e["name"] for e in events if e["type"] in ("tool_blocked", "egress_blocked")],
            guard_tokens=sum(int(e["data"].get("tokens", 0)) for e in defense),
            attempt=attempt,
            guard_ms=round(sum(float(e["data"].get("latency_ms", 0.0)) for e in defense), 1),
        )

    for task in tasks.tasks:
        out.append(one(task, 1))
    # Retry rule: an errored task is retried once, after the set, and both attempts kept.
    for first in [r for r in out if r.errored]:
        task = next(t for t in tasks.tasks if t.id == first.id)
        out.append(one(task, 2))
    return out


def latest(results: list[BenignResult]) -> list[BenignResult]:
    """Keep the latest attempt of each task (the retry, if there was one)."""
    by_id: dict[str, BenignResult] = {}
    for r in results:
        if r.id not in by_id or r.attempt >= by_id[r.id].attempt:
            by_id[r.id] = r
    return list(by_id.values())
