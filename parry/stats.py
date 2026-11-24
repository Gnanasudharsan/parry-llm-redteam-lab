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


def holm(pvalues: dict[str, float]) -> dict[str, float]:
    """Holm-Bonferroni adjusted p-values (step-down, monotone, capped at 1)."""
    order = sorted(pvalues, key=lambda k: pvalues[k])
    m = len(order)
    adjusted: dict[str, float] = {}
    running = 0.0
    for i, key in enumerate(order):
        running = max(running, min(1.0, (m - i) * pvalues[key]))
        adjusted[key] = running
    return adjusted


def cohen_kappa(a: list[bool], b: list[bool]) -> float | None:
    """Cohen's kappa for two raters' binary labels on the same items.

    kappa = (p_o - p_e) / (1 - p_e); None when undefined (no items, or p_e == 1, i.e. both
    raters gave one identical label to everything).
    """
    if len(a) != len(b):
        raise ValueError("raters must label the same items")
    n = len(a)
    if n == 0:
        return None
    p_o = sum(x == y for x, y in zip(a, b, strict=True)) / n
    pa, pb = sum(a) / n, sum(b) / n
    p_e = pa * pb + (1 - pa) * (1 - pb)
    if p_e == 1:
        return None
    return (p_o - p_e) / (1 - p_e)


def mcnemar_power(n: int, p_stop: float, p_open: float, alpha: float = 0.05) -> float:
    """Exact power of the two-sided exact McNemar test on n paired cases.

    Each case is independently "stopped" (attack succeeds without the defense, fails with it)
    with probability p_stop, "opened" with p_open, concordant otherwise. Power = probability
    that mcnemar_exact(b, c) < alpha, summed over every (b, c)."""
    if p_stop < 0 or p_open < 0 or p_stop + p_open > 1:
        raise ValueError("invalid probabilities")
    rest = 1 - p_stop - p_open
    power = 0.0
    for b in range(n + 1):
        for c in range(n + 1 - b):
            if mcnemar_exact(b, c) < alpha:
                power += comb(n, b) * comb(n - b, c) * p_stop**b * p_open**c * rest ** (n - b - c)
    return power


def minimum_detectable_effect(
    n: int, p_open: float = 0.0, alpha: float = 0.05, power: float = 0.8
) -> float | None:
    """Smallest ASR reduction (p_stop - p_open) detectable with the given power, by bisection
    on p_stop (power is increasing in p_stop for fixed p_open). None if not reachable."""
    lo, hi = p_open, 1.0 - p_open
    if mcnemar_power(n, hi, p_open, alpha) < power:
        return None
    for _ in range(40):
        mid = (lo + hi) / 2
        if mcnemar_power(n, mid, p_open, alpha) >= power:
            hi = mid
        else:
            lo = mid
    return hi - p_open
