"""Paired tests for comparing defense configurations on the same attack cases."""

from __future__ import annotations

from math import comb


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value from the two discordant counts.

    b = cases the baseline lost and the defense won (attack stopped by the defense),
    c = cases the defense lost and the baseline won. Under H0 the discordant pairs split
    50/50, so the p-value is a two-sided binomial test on min(b, c) out of b + c.
    """
    if b < 0 or c < 0:
        raise ValueError("counts must be non-negative")
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail: float = sum(comb(n, i) for i in range(k + 1)) / 2**n
    return min(1.0, 2 * tail)
