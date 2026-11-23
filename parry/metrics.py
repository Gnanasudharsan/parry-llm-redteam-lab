"""Statistics used for every reported rate (see docs/metrics.md)."""

from __future__ import annotations

import math
from dataclasses import dataclass

Z_95 = 1.959963984540054  # two-sided 95% normal quantile


@dataclass(frozen=True)
class Rate:
    successes: int
    trials: int
    low: float
    high: float

    @property
    def point(self) -> float:
        return self.successes / self.trials if self.trials else 0.0

    def __str__(self) -> str:
        return f"{self.point:.1%} [{self.low:.1%}, {self.high:.1%}] (n={self.trials})"


def wilson_interval(successes: int, trials: int, z: float = Z_95) -> Rate:
    """Wilson score interval for a binomial proportion.

    Chosen over the normal (Wald) interval because attack success rates are often
    near 0 or 1 with small n, where Wald collapses to zero width or leaves [0, 1].
    """
    if trials < 0 or successes < 0 or successes > trials:
        raise ValueError(f"invalid counts: {successes}/{trials}")
    if trials == 0:
        return Rate(0, 0, 0.0, 1.0)
    p = successes / trials
    z2 = z * z
    denom = 1 + z2 / trials
    centre = (p + z2 / (2 * trials)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / trials + z2 / (4 * trials * trials))
    low = 0.0 if successes == 0 else max(0.0, centre - half)
    high = 1.0 if successes == trials else min(1.0, centre + half)
    return Rate(successes, trials, low, high)
