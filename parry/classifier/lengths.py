"""Token-length distribution of every split, in the classifier's own tokens (no specials)."""

from __future__ import annotations

from typing import Any

from parry.classifier.data import load_split
from parry.classifier.evaluate import SETS

LIMIT = 256


def _q(xs: list[int], q: float) -> int:
    return xs[min(len(xs) - 1, int(q * (len(xs) - 1) + 0.5))]


def distribution(tok: Any, sets: tuple[str, ...] = ("train", *SETS)) -> dict[str, Any]:
    out: dict[str, Any] = {"limit": LIMIT, "sets": {}}
    for name in sets:
        items = load_split(name)
        n = [len(tok(it["text"], add_special_tokens=False)["input_ids"]) for it in items]
        order = sorted(n)
        over = [it for it, k in zip(items, n, strict=True) if k > LIMIT - 2]
        out["sets"][name] = {
            "n": len(n),
            "median": _q(order, 0.5),
            "p95": _q(order, 0.95),
            "max": order[-1],
            "over_limit": len(over),
            "over_limit_share": round(len(over) / len(n), 4),
            "over_limit_injections": sum(it["label"] for it in over),
        }
    return out
