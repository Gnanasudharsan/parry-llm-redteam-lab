"""Run benign task sets against running lab targets and report pass rates with Wilson CIs.

    uv run python -m targets.benign.run -c targets/parry.lab.yaml \
        --i-own-this-target vuln-rag --i-own-this-target hard-rag --out reports/benign.json

Authorization goes through `parry.scope.authorize`, like every other Parry entry point.
The target's state is reset through the lab admin API before every task.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import anyio
import httpx
from mcp.client.client import Client

from parry.config import TargetConfig, load_config
from parry.metrics import wilson_interval
from parry.scope import ScopeError, authorize
from parry.tasks import BenignTask, Outcome, evaluate, load_taskset
from targets.lab.admin import admin_token

TASKS_DIR = Path(__file__).parent
TASK_TIMEOUT_S = 180


def target_type(name: str) -> str:
    kind = name.rsplit("-", 1)[-1]
    if kind not in ("rag", "agent", "mcp"):
        raise ValueError(f"cannot tell the task set for target {name!r}")
    return kind


def admin_base(target: TargetConfig) -> str:
    assert target.url is not None  # noqa: S101 - lab targets are all URL-based
    parts = urlsplit(str(target.url))
    return urlunsplit((parts.scheme, parts.netloc, "", "", "")).rstrip("/")


def _text(result: Any) -> str:
    contents = getattr(result, "content", None) or getattr(result, "contents", [])
    return "\n".join(str(getattr(c, "text", "")) for c in contents)


async def run_mcp_task(client: Client, task: BenignTask) -> tuple[str, list[tuple[str, Any]]]:
    last, executed = "", []
    for call in task.calls:
        if call.resource is not None:
            last = _text(await client.read_resource(call.resource))
        else:
            assert call.tool is not None  # noqa: S101 - validated by the model
            last = _text(await client.call_tool(call.tool, call.arguments))
            executed.append((call.tool, call.arguments))
    return last, executed


def run_chat_task(http: httpx.Client, base: str, task: BenignTask) -> tuple[str, list[Any]]:
    body: dict[str, Any] = {
        "message": task.message,
        "history": [t.model_dump() for t in task.history],
    }
    if task.role:
        body["role"] = task.role
    resp = http.post(f"{base}/chat", json=body)
    resp.raise_for_status()
    data = resp.json()
    executed = [
        (c["name"], c["args"]) for c in data.get("tool_calls", []) if c["status"] == "executed"
    ]
    return data["answer"], executed


async def run_target(target: TargetConfig, limit: int | None) -> dict[str, Any]:
    kind = target_type(target.name)
    tasks = load_taskset(TASKS_DIR / f"{kind}.yaml").tasks[:limit]
    base = admin_base(target)
    headers = {"X-Lab-Token": admin_token()}
    results: list[dict[str, Any]] = []
    with httpx.Client(timeout=TASK_TIMEOUT_S, headers=headers) as http:
        state = http.get(f"{base}/_lab/state").raise_for_status().json()
        forbidden = [state["secrets"]["system_canary"], state["secrets"]["api_key"]]

        async def one(task: BenignTask, client: Client | None) -> None:
            http.post(f"{base}/_lab/reset").raise_for_status()
            t0 = time.perf_counter()
            try:
                if client is not None:
                    answer, executed = await run_mcp_task(client, task)
                else:
                    answer, executed = run_chat_task(http, base, task)
                outcome = evaluate(task.check, answer, executed, forbidden)
            except (httpx.HTTPError, TimeoutError) as exc:  # counted as a failure, not skipped
                answer, executed = "", []
                outcome = Outcome(passed=False, failures=[f"error: {exc.__class__.__name__}"])
            results.append(
                {
                    "id": task.id,
                    "category": task.category,
                    "approval_gated": task.approval_gated,
                    "passed": outcome.passed,
                    "leaked": outcome.leaked,
                    "failures": outcome.failures,
                    "latency_s": round(time.perf_counter() - t0, 3),
                    "answer": answer[:500],
                    "tools": [n for n, _ in executed],
                }
            )
            mark = ("PASS" if outcome.passed else "FAIL") + (" LEAK" if outcome.leaked else "")
            print(f"  {mark} {target.name}/{task.id} {'; '.join(outcome.failures)}", flush=True)

        if kind == "mcp":
            async with Client(str(target.url)) as client:
                for task in tasks:
                    await one(task, client)
        else:
            for task in tasks:
                await one(task, None)

    def summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
        rate = wilson_interval(sum(r["passed"] for r in rows), len(rows))
        return {"passed": rate.successes, "n": rate.trials, "rate": rate.point,
                "ci95": [rate.low, rate.high], "text": str(rate)}  # fmt: skip

    return {
        "target": target.name,
        "profile": state["profile"]["name"],
        "model": state.get("model"),
        "core": summary([r for r in results if not r["approval_gated"]]),
        "approval_gated": summary([r for r in results if r["approval_gated"]]),
        "leaks": sum(r["leaked"] for r in results),
        "median_latency_s": sorted(r["latency_s"] for r in results)[len(results) // 2],
        "tasks": results,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("-c", "--config", type=Path, default=Path("targets/parry.lab.yaml"))
    ap.add_argument("--i-own-this-target", action="append", default=[], dest="owned")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--limit", type=int, default=None, help="first N tasks per target")
    args = ap.parse_args(argv)

    try:
        allowed = authorize(load_config(args.config), args.owned)
    except ScopeError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 3

    reports = []
    for a in allowed:
        print(f"== {a.target.name} ({a.scope})", flush=True)
        reports.append(anyio.run(run_target, a.target, args.limit))

    print("\ntarget        core pass rate [95% CI]           approval-gated                 leaks")
    for r in reports:
        gated = r["approval_gated"]["text"] if r["approval_gated"]["n"] else "-"
        print(f"{r['target']:<13} {r['core']['text']:<33} {gated:<30} {r['leaks']}")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({"seed_note": "LAB_SEED/LAB_MODEL_SEED from compose",
                                        "reports": reports}, indent=2))  # fmt: skip
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
