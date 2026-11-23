"""Defense layer interface.

A layer inspects text at one or more hooks and returns a `Decision`:
- `input`: the user's message, before the model sees it
- `untrusted`: content from outside the trust boundary (retrieved docs, tool outputs, notes)
- `output`: the model's answer, before the user (or a renderer) sees it

The app decides what "flagged" means at each hook (refuse, drop the document, replace the
tool output). Layers only classify.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Literal, Protocol

from pydantic import BaseModel

Hook = Literal["input", "untrusted", "output"]


class Decision(BaseModel):
    layer: str
    hook: Hook
    flagged: bool
    score: float | None = None
    reason: str = ""
    latency_ms: float = 0.0
    tokens: int = 0  # model tokens the check consumed (cost overhead)
    error: str | None = None  # the guard failed; the app fails open and records it


class Layer(Protocol):
    name: str
    hooks: frozenset[Hook]

    def check(self, hook: Hook, text: str) -> Decision: ...


def timed(layer: str, hook: Hook, fn: Callable[[], Decision]) -> Decision:
    """Run a check, stamp its latency, and turn guard failures into an unflagged decision."""
    t0 = time.perf_counter()
    try:
        d = fn()
    except Exception as exc:  # a broken guard must not crash the app; it is recorded
        d = Decision(
            layer=layer, hook=hook, flagged=False, error=f"{exc.__class__.__name__}: {exc}"[:200]
        )
    return d.model_copy(update={"latency_ms": round((time.perf_counter() - t0) * 1000, 1)})


class DefenseStack:
    """An ordered set of layers. `check` runs every layer that applies to the hook."""

    def __init__(self, layers: list[Layer]) -> None:
        self.layers = layers

    @property
    def names(self) -> list[str]:
        return [layer.name for layer in self.layers]

    def check(self, hook: Hook, text: str) -> list[Decision]:
        return [layer.check(hook, text) for layer in self.layers if hook in layer.hooks]
