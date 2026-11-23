"""Lab-only admin API used by Parry's judges and test harness.

Exposes planted secrets, the event log and reset. Guarded by a shared token so an attack
payload cannot use it; the lab's ports are bound to 127.0.0.1 only.
"""

from __future__ import annotations

import hmac
import os
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from targets.lab.canary import LabSecrets
from targets.lab.events import Event, EventLog
from targets.lab.llm import DEFAULT_CHAT_MODEL
from targets.lab.runtime import Runtime

DEFAULT_ADMIN_TOKEN = "parry-lab-admin"  # noqa: S105 - lab-only, documented, not a real secret


class ConfigBody(BaseModel):
    """PUT /_lab/config: change hardening flags and defense layers on a running app."""

    hardening: dict[str, bool] | None = None
    defenses: list[str] | None = None
    restore: bool = False


def admin_token() -> str:
    return os.environ.get("LAB_ADMIN_TOKEN", DEFAULT_ADMIN_TOKEN)


def require_token(x_lab_token: str = Header(default="")) -> None:
    if not hmac.compare_digest(x_lab_token, admin_token()):
        raise HTTPException(status_code=401, detail="lab admin token required")


def admin_router(
    *,
    target: str,
    runtime: Runtime,
    secrets: LabSecrets,
    log: EventLog,
    reset: Callable[[], None],
    extra_state: Callable[[], dict[str, Any]] | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/_lab", dependencies=[Depends(require_token)])

    @router.get("/state")
    def state() -> dict[str, Any]:
        out: dict[str, Any] = {
            "target": target,
            **runtime.describe(),
            "secrets": secrets.as_dict(),
            "model": os.environ.get("LAB_CHAT_MODEL", DEFAULT_CHAT_MODEL),
        }
        if extra_state:
            out.update(extra_state())
        return out

    @router.get("/events")
    def events(since: int = 0) -> list[Event]:
        return log.list(since)

    @router.put("/config")
    def configure(body: ConfigBody) -> dict[str, Any]:
        if body.restore:
            runtime.restore()
        try:
            runtime.configure(body.hardening, body.defenses)
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return runtime.describe()

    @router.post("/reset")
    def do_reset() -> dict[str, str]:
        log.clear()
        reset()
        return {"status": "reset"}

    return router
