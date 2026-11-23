from __future__ import annotations

import pytest

from parry.metrics import wilson_interval


@pytest.mark.parametrize(
    ("k", "n", "low", "high"),
    [
        # Reference values computed independently (Wilson score, z = 1.959964).
        (5, 10, 0.2366, 0.7634),
        (0, 10, 0.0, 0.2775),
        (10, 10, 0.7225, 1.0),
        (1, 50, 0.0035, 0.1050),
        (81, 263, 0.2553, 0.3662),
    ],
)
def test_wilson_reference_values(k: int, n: int, low: float, high: float) -> None:
    r = wilson_interval(k, n)
    assert r.low == pytest.approx(low, abs=5e-4)
    assert r.high == pytest.approx(high, abs=5e-4)
    assert r.low <= r.point <= r.high


def test_zero_trials_is_uninformative() -> None:
    r = wilson_interval(0, 0)
    assert (r.low, r.high) == (0.0, 1.0)


@pytest.mark.parametrize(("k", "n"), [(-1, 5), (6, 5), (0, -1)])
def test_invalid_counts(k: int, n: int) -> None:
    with pytest.raises(ValueError, match="invalid counts"):
        wilson_interval(k, n)


def test_str_format() -> None:
    assert str(wilson_interval(5, 10)) == "50.0% [23.7%, 76.3%] (n=10)"
