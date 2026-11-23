"""In-memory event log: tool calls, blocked actions, outbound fetches.

Judges read it through the lab admin API, so "the forbidden tool was called" is a lookup,
not an interpretation of the model's prose. Targets run a single worker, so one process-wide
log is enough.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Literal

from pydantic import BaseModel, Field

EventType = Literal[
    "tool_call", "tool_blocked", "egress", "egress_blocked", "render_fetch", "defense"
]


class Event(BaseModel):
    seq: int
    ts: float
    type: EventType
    name: str
    data: dict[str, Any] = Field(default_factory=dict)


class EventLog:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: list[Event] = []
        self._seq = 0

    def record(self, type: EventType, name: str, **data: Any) -> Event:
        with self._lock:
            self._seq += 1
            event = Event(seq=self._seq, ts=time.time(), type=type, name=name, data=data)
            self._events.append(event)
            return event

    def list(self, since: int = 0) -> list[Event]:
        with self._lock:
            return [e for e in self._events if e.seq > since]

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
